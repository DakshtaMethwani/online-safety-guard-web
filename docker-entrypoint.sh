#!/bin/sh
# Container entrypoint.
#
# Starts as root (the default), makes sure the persistent data directory is
# writable by the non-root "node" user, then drops privileges. This matters on
# platforms like Render where a freshly mounted disk (or volume) can be
# root-owned, which would otherwise make the SQLite database unwritable for a
# non-root process.
set -e

if [ "$(id -u)" = "0" ]; then
  datadir="$(dirname "${DB_PATH:-/data/gateway.db}")"
  mkdir -p "$datadir"
  chown -R node:node "$datadir" 2>/dev/null || true
  exec su-exec node "$@"
fi

exec "$@"
