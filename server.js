import makeWASocket, {
  useMultiFileAuthState,
  DisconnectReason,
  fetchLatestBaileysVersion,
} from '@whiskeysockets/baileys'
import express from 'express'
import cookieParser from 'cookie-parser'
import Database from 'better-sqlite3'
import qrcode from 'qrcode-terminal'
import pino from 'pino'
import crypto from 'node:crypto'

const PORT = process.env.PORT || 3000
const INVITE_CODE = process.env.INVITE_CODE        // friends need this to sign up
const DAILY_LIMIT = Number(process.env.DAILY_LIMIT || 100) // messages per key per day
const MIN_GAP_MS = Number(process.env.MIN_GAP_MS || 2000)  // global gap between sends

if (!INVITE_CODE) throw new Error('Set INVITE_CODE env var')

// ---------- DB ----------
const db = new Database('data.db')
db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY, username TEXT UNIQUE, pass_hash TEXT, created_at INTEGER);
CREATE TABLE IF NOT EXISTS sessions (
  token TEXT PRIMARY KEY, user_id INTEGER, expires_at INTEGER);
CREATE TABLE IF NOT EXISTS keys (
  id INTEGER PRIMARY KEY, user_id INTEGER, name TEXT, prefix TEXT,
  key_hash TEXT UNIQUE, created_at INTEGER, revoked INTEGER DEFAULT 0, last_used INTEGER);
CREATE TABLE IF NOT EXISTS usage (
  key_id INTEGER, day TEXT, count INTEGER, PRIMARY KEY (key_id, day));
CREATE TABLE IF NOT EXISTS pairings (
  code TEXT PRIMARY KEY, user_id INTEGER, expires_at INTEGER);
CREATE TABLE IF NOT EXISTS rooms (
  id TEXT PRIMARY KEY, user_id INTEGER, jid TEXT, label TEXT, created_at INTEGER,
  UNIQUE (user_id, jid));
`)

const sha256 = s => crypto.createHash('sha256').update(s).digest('hex')
const hashPass = (p, salt = crypto.randomBytes(16).toString('hex')) =>
  `${salt}:${crypto.scryptSync(p, salt, 64).toString('hex')}`
const checkPass = (p, stored) => {
  const [salt, h] = stored.split(':')
  const a = Buffer.from(h, 'hex'), b = crypto.scryptSync(p, salt, 64)
  return a.length === b.length && crypto.timingSafeEqual(a, b)
}

// ---------- WhatsApp ----------
let sock, waStatus = 'connecting'
async function startWA() {
  const { state, saveCreds } = await useMultiFileAuthState('./auth')
  const { version } = await fetchLatestBaileysVersion()
  sock = makeWASocket({ version, auth: state, logger: pino({ level: 'warn' }) })
  sock.ev.on('creds.update', saveCreds)
  sock.ev.on('connection.update', ({ connection, lastDisconnect, qr }) => {
    if (qr) qrcode.generate(qr, { small: true })
    if (connection) waStatus = connection
    if (connection === 'close') {
      const code = lastDisconnect?.error?.output?.statusCode
      if (code !== DisconnectReason.loggedOut) startWA()
      else console.log('Logged out. Delete ./auth and restart to re-pair.')
    }
  })

  // "/setup CODE" in a DM or group links that chat to the dashboard user who made CODE
  sock.ev.on('messages.upsert', async ({ messages, type }) => {
    if (type !== 'notify') return
    for (const m of messages) {
      const text = (m.message?.conversation || m.message?.extendedTextMessage?.text || '').trim()
      const jid = m.key.remoteJid
      if (!text.startsWith('/setup') || !jid || jid === 'status@broadcast') continue

      const code = (text.split(/\s+/)[1] || '').toUpperCase()
      const say = t => enqueueSend(jid, { text: t }).catch(() => {})
      if (!code) { await say('Usage: /setup <code>\nGet a code from the dashboard ("Link a chat").'); continue }

      const p = db.prepare('SELECT * FROM pairings WHERE code = ? AND expires_at > ?').get(code, Date.now())
      if (!p) { await say('Invalid or expired code.'); continue }
      db.prepare('DELETE FROM pairings WHERE code = ?').run(code) // single use

      let room = db.prepare('SELECT id FROM rooms WHERE user_id = ? AND jid = ?').get(p.user_id, jid)
      if (!room) {
        let label = m.pushName || 'Direct chat'
        if (jid.endsWith('@g.us')) label = (await sock.groupMetadata(jid).catch(() => null))?.subject || 'Group'
        room = { id: 'rm_' + crypto.randomBytes(9).toString('base64url') }
        db.prepare('INSERT INTO rooms VALUES (?,?,?,?,?)').run(room.id, p.user_id, jid, label, Date.now())
      }
      await say(`Linked.\nRoom ID: ${room.id}\nUse it as "room" in the API. Remove it any time from the dashboard.`)
    }
  })
}

// simple serial send queue so friends can't burst-spam your number
let chain = Promise.resolve()
const enqueueSend = (jid, content) => {
  const job = chain.then(async () => {
    const r = await sock.sendMessage(jid, content)
    await new Promise(r => setTimeout(r, MIN_GAP_MS))
    return r
  })
  chain = job.catch(() => {})
  return job
}

// ---------- HTTP ----------
const app = express()
app.use(express.json({ limit: '100kb' }))
app.use(cookieParser())
app.use(express.static('public'))

const cookieOpts = { httpOnly: true, sameSite: 'lax', maxAge: 7 * 864e5 }

function auth(req, res, next) {
  const t = req.cookies.sid
  const row = t && db.prepare(
    'SELECT u.id, u.username FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.token = ? AND s.expires_at > ?'
  ).get(t, Date.now())
  if (!row) return res.status(401).json({ error: 'not logged in' })
  req.user = row
  next()
}

function login(res, userId) {
  const token = crypto.randomBytes(32).toString('hex')
  db.prepare('INSERT INTO sessions VALUES (?,?,?)').run(token, userId, Date.now() + 7 * 864e5)
  res.cookie('sid', token, cookieOpts)
}

app.post('/auth/signup', (req, res) => {
  const { username, password, invite } = req.body || {}
  if (invite !== INVITE_CODE) return res.status(403).json({ error: 'bad invite code' })
  if (!/^[a-z0-9_]{3,20}$/i.test(username || '') || (password || '').length < 8)
    return res.status(400).json({ error: 'username 3-20 chars, password min 8' })
  try {
    const r = db.prepare('INSERT INTO users (username, pass_hash, created_at) VALUES (?,?,?)')
      .run(username.toLowerCase(), hashPass(password), Date.now())
    login(res, r.lastInsertRowid)
    res.json({ ok: true })
  } catch { res.status(409).json({ error: 'username taken' }) }
})

app.post('/auth/login', (req, res) => {
  const { username, password } = req.body || {}
  const u = db.prepare('SELECT * FROM users WHERE username = ?').get((username || '').toLowerCase())
  if (!u || !checkPass(password || '', u.pass_hash)) return res.status(401).json({ error: 'invalid credentials' })
  login(res, u.id)
  res.json({ ok: true })
})

app.post('/auth/logout', (req, res) => {
  db.prepare('DELETE FROM sessions WHERE token = ?').run(req.cookies.sid)
  res.clearCookie('sid'); res.json({ ok: true })
})

app.get('/me', auth, (req, res) => res.json({ username: req.user.username, wa: waStatus, dailyLimit: DAILY_LIMIT }))

// ----- key management (dashboard) -----
app.get('/keys', auth, (req, res) => {
  const day = new Date().toISOString().slice(0, 10)
  const rows = db.prepare(`
    SELECT k.id, k.name, k.prefix, k.created_at, k.last_used, k.revoked,
           COALESCE(u.count, 0) AS today
    FROM keys k LEFT JOIN usage u ON u.key_id = k.id AND u.day = ?
    WHERE k.user_id = ? ORDER BY k.id DESC`).all(day, req.user.id)
  res.json(rows)
})

app.post('/keys', auth, (req, res) => {
  const n = db.prepare('SELECT COUNT(*) c FROM keys WHERE user_id = ? AND revoked = 0').get(req.user.id).c
  if (n >= 5) return res.status(400).json({ error: 'max 5 active keys' })
  const raw = 'wak_' + crypto.randomBytes(24).toString('base64url')
  db.prepare('INSERT INTO keys (user_id, name, prefix, key_hash, created_at) VALUES (?,?,?,?,?)')
    .run(req.user.id, String(req.body?.name || 'key').slice(0, 40), raw.slice(0, 8), sha256(raw), Date.now())
  res.json({ key: raw }) // shown once, only the hash is stored
})

app.delete('/keys/:id', auth, (req, res) => {
  db.prepare('UPDATE keys SET revoked = 1 WHERE id = ? AND user_id = ?').run(req.params.id, req.user.id)
  res.json({ ok: true })
})

// ----- chat linking (dashboard) -----
app.post('/pair', auth, (req, res) => {
  db.prepare('DELETE FROM pairings WHERE expires_at < ? OR user_id = ?').run(Date.now(), req.user.id)
  const code = crypto.randomBytes(4).toString('hex').toUpperCase()
  db.prepare('INSERT INTO pairings VALUES (?,?,?)').run(code, req.user.id, Date.now() + 10 * 60e3)
  res.json({ code, expiresInSec: 600 })
})

app.get('/rooms', auth, (req, res) =>
  res.json(db.prepare('SELECT id, label, created_at FROM rooms WHERE user_id = ? ORDER BY created_at DESC').all(req.user.id)))

app.delete('/rooms/:id', auth, (req, res) => {
  db.prepare('DELETE FROM rooms WHERE id = ? AND user_id = ?').run(req.params.id, req.user.id)
  res.json({ ok: true })
})

// ----- the actual webhook -----
app.post('/api/send', async (req, res) => {
  const m = /^Bearer (.+)$/.exec(req.get('authorization') || '')
  const key = m && db.prepare('SELECT * FROM keys WHERE key_hash = ? AND revoked = 0').get(sha256(m[1]))
  if (!key) return res.status(401).json({ error: 'invalid api key' })

  const { room, text } = req.body || {}
  // rooms are scoped to the key's owner, so one friend can't use another's room ID
  const target = db.prepare('SELECT jid FROM rooms WHERE id = ? AND user_id = ?').get(String(room || ''), key.user_id)
  if (!target) return res.status(404).json({ error: 'unknown room' })
  const jid = target.jid
  if (typeof text !== 'string' || !text || text.length > 4000)
    return res.status(400).json({ error: '`text` required, max 4000 chars' })
  if (waStatus !== 'open') return res.status(503).json({ error: 'whatsapp not connected' })

  const day = new Date().toISOString().slice(0, 10)
  const used = db.prepare('SELECT count FROM usage WHERE key_id = ? AND day = ?').get(key.id, day)?.count || 0
  if (used >= DAILY_LIMIT) return res.status(429).json({ error: 'daily limit reached' })

  try {
    const r = await enqueueSend(jid, { text })
    db.prepare(`INSERT INTO usage VALUES (?,?,1)
                ON CONFLICT(key_id, day) DO UPDATE SET count = count + 1`).run(key.id, day)
    db.prepare('UPDATE keys SET last_used = ? WHERE id = ?').run(Date.now(), key.id)
    res.json({ ok: true, id: r?.key?.id })
  } catch (e) {
    res.status(500).json({ error: e.message })
  }
})

app.listen(PORT, () => console.log(`gateway on :${PORT}`))
startWA()
