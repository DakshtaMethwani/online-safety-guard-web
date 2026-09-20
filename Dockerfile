# syntax=docker/dockerfile:1

# ---------------------------------------------------------------------------
# Online Safety Guard — persistent-host deployment
# Builds the client + server bundle in stage 1, then runs the compiled
# server in stage 2 as a non-root user. The SQLite database lives at
# /data/gateway.db so a persistent volume can be mounted at /data.
# ---------------------------------------------------------------------------

# ---------- build stage ----------
FROM node:24-alpine AS build
WORKDIR /app

# Install ALL deps (devDeps are needed to build), leveraging layer caching.
COPY package.json package-lock.json ./
RUN npm ci

# Copy sources and compile (vite build + esbuild server bundle).
COPY . .
RUN npm run build

# ---------- run stage ----------
FROM node:24-alpine

ENV NODE_ENV=production
ENV PORT=3000
ENV DB_PATH=/data/gateway.db

WORKDIR /app

# Runtime needs only the production dependencies (the bundle requires
# express, tldts, dotenv and @google/genai externally) plus the dist bundle.
COPY package.json package-lock.json ./
RUN npm ci --omit=dev && npm cache clean --force

COPY --from=build /app/dist ./dist

# su-exec lets the entrypoint drop root -> node after fixing disk permissions.
RUN apk add --no-cache su-exec

# Writable data directory for the (possibly mounted) persistent volume. The
# entrypoint re-applies ownership at runtime because a mounted disk can shadow
# this directory with root-owned files.
RUN mkdir -p /data && chown -R node:node /data

COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

EXPOSE 3000
VOLUME /data

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
  CMD node -e "const p=process.env.PORT||3000;fetch('http://127.0.0.1:'+p+'/healthz').then(r=>{if(r.status!==200)process.exit(1)}).catch(()=>process.exit(1))"

ENTRYPOINT ["docker-entrypoint.sh"]
CMD ["node", "dist/server.cjs"]