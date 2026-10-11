FROM node:22-slim AS deps
RUN apt-get update && apt-get install -y --no-install-recommends git ca-certificates && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY package.json ./
RUN npm install --omit=dev

FROM node:22-slim
WORKDIR /app
COPY --from=deps /app/node_modules ./node_modules
COPY package.json ./
COPY src ./src
# server uses cwd-relative paths (data.db, ./auth, ./public); run from the /data volume
ENV PORT=3000
EXPOSE 3000
VOLUME /data
CMD ["sh", "-c", "mkdir -p /data && cd /data && ln -sfn /app/src/public public && exec node /app/src/server.js"]
