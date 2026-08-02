# Docker deployment

Requires Docker Engine 24+ and Docker Compose v2.

## Compose

```bash
cp .env.example .env
# Set DEWHIRLPOOLER_FULCRUM_HOST in .env
docker compose up --detach --build
docker compose ps
```

Default endpoint: `http://127.0.0.1:8000`.

Runtime constraints:

- UID/GID `10001:10001`
- read-only root filesystem
- all Linux capabilities dropped
- `no-new-privileges`
- PID limit `128`
- writable `/data` volume
- `noexec,nosuid,nodev` `/tmp` tmpfs

Health and logs:

```bash
docker inspect --format '{{json .State.Health}}' \
  "$(docker compose ps --quiet dewhirlpooler)"
docker compose logs --tail 100 dewhirlpooler
```

## Bitcoin Core RPC

The historical index requires Bitcoin Core 28+, an unpruned scan range, and a
dedicated RPC identity limited to:

```text
getblockcount
getblockhash
getblock
```

Minimal `bitcoin.conf` shape:

```ini
rpcauth=<user>:<salt-and-hash>
rpcwhitelistdefault=0
rpcwhitelist=<user>:getblockcount,getblockhash,getblock
rpcbind=<node-address>
rpcallowip=<application-address>/32
```

Application environment:

```text
DEWHIRLPOOLER_CORE_HOST=<host>
DEWHIRLPOOLER_CORE_PORT=8332
DEWHIRLPOOLER_CORE_USER=<user>
DEWHIRLPOOLER_CORE_PASSWORD=<password>
DEWHIRLPOOLER_CORE_TLS=false
DEWHIRLPOOLER_CORE_TIMEOUT=30
```

## Historical index

```text
DEWHIRLPOOLER_CHAIN_DB=/data/chain.sqlite3
DEWHIRLPOOLER_CHAIN_START_HEIGHT=571000
DEWHIRLPOOLER_CHAIN_BUSY_TIMEOUT_MS=5000
DEWHIRLPOOLER_CHAIN_PREFETCH_WORKERS=8
```

```bash
dewhirlpooler chain-index
dewhirlpooler chain-status
```

The scanner commits each validated block atomically and resumes from the
indexed tip. `DEWHIRLPOOLER_CHAIN_PREFETCH_WORKERS` accepts `1`–`16`; `8` is
the default.

The checked-in Compose service contains the web tracer and report cache. A
separate index service should mount the same `/data` volume. Only the index
process needs `DEWHIRLPOOLER_CORE_*`; the web process needs
`DEWHIRLPOOLER_CHAIN_DB=/data/chain.sqlite3`.

SQLite WAL mode supports concurrent index writes and read-only web queries.
Pool-history responses include the indexed range and cap results at 2,000
rows.

### Install the historical index bundle

The v0.1.0 historical index bundle is a point-in-time snapshot of public-chain
data classified with DeWhirlpooler's heuristics. It covers mainnet blocks
571,000 through 960,650 and must be caught up to your Bitcoin Core tip after
installation. Download and verify all release files before decompressing:

```bash
mkdir dewhirlpooler-index-v0.1.0
cd dewhirlpooler-index-v0.1.0

curl -fLO https://github.com/clenchwallet/dewhirlpooler/releases/download/v0.1.0/dewhirlpooler-v0.1.0-mainnet-index-schema1-571000-960650.sqlite3.zst
curl -fLO https://github.com/clenchwallet/dewhirlpooler/releases/download/v0.1.0/dewhirlpooler-v0.1.0-mainnet-index-manifest.json
curl -fLO https://github.com/clenchwallet/dewhirlpooler/releases/download/v0.1.0/SHA256SUMS
sha256sum --check SHA256SUMS

mkdir -p "$HOME/.local/share/dewhirlpooler"
zstd -d dewhirlpooler-v0.1.0-mainnet-index-schema1-571000-960650.sqlite3.zst \
  -o "$HOME/.local/share/dewhirlpooler/chain.sqlite3"
export DEWHIRLPOOLER_CHAIN_DB="$HOME/.local/share/dewhirlpooler/chain.sqlite3"
dewhirlpooler chain-status
dewhirlpooler chain-index
```

Decompress into a new `chain.sqlite3` path. Do not overwrite a newer local
index, and do not copy or use SQLite `-wal` or `-shm` files. The manifest binds
the snapshot to its exact height, block hash, schema, counts, and checksums.
The final command resumes from height 960,650 and catches up to your Bitcoin
Core tip.

### Continuous refresh with systemd

The checked-in user units in `deploy/systemd/` run `chain-index` on a
five-minute schedule and restart a failed indexing process after 30 seconds. A
successful refresh exits, so an inactive service between timer runs is
expected. The timer is the persistent component.

Install the CLI at `%h/.local/bin/dewhirlpooler`, then create the two
environment files referenced by the service:

```text
# ~/.config/dewhirlpooler/core.env (permissions 0600)
DEWHIRLPOOLER_CORE_HOST=<host>
DEWHIRLPOOLER_CORE_PORT=8332
DEWHIRLPOOLER_CORE_USER=<user>
DEWHIRLPOOLER_CORE_PASSWORD=<password>
DEWHIRLPOOLER_CORE_TLS=false
DEWHIRLPOOLER_CORE_TIMEOUT=30

# ~/.config/dewhirlpooler/index.env
DEWHIRLPOOLER_CHAIN_DB=%h/.local/share/dewhirlpooler/chain.sqlite3
DEWHIRLPOOLER_CHAIN_START_HEIGHT=571000
DEWHIRLPOOLER_CHAIN_BUSY_TIMEOUT_MS=5000
DEWHIRLPOOLER_CHAIN_PREFETCH_WORKERS=8
```

Use an absolute path rather than `%h` in the value of
`DEWHIRLPOOLER_CHAIN_DB`; systemd does not expand specifiers inside environment
file values. Install and enable the units:

```bash
mkdir -p "$HOME/.config/systemd/user" "$HOME/.config/dewhirlpooler"
cp deploy/systemd/dewhirlpooler-index.service "$HOME/.config/systemd/user/"
cp deploy/systemd/dewhirlpooler-index.timer "$HOME/.config/systemd/user/"
chmod 600 "$HOME/.config/dewhirlpooler/core.env"

systemctl --user daemon-reload
systemctl --user enable --now dewhirlpooler-index.timer
systemctl --user list-timers dewhirlpooler-index.timer
systemctl --user status dewhirlpooler-index.timer
journalctl --user -u dewhirlpooler-index.service --since today
systemctl --user start dewhirlpooler-index.service
DEWHIRLPOOLER_CHAIN_DB="$HOME/.local/share/dewhirlpooler/chain.sqlite3" \
  dewhirlpooler chain-status
```

`Persistent=true` causes a missed refresh to run after the user manager starts.
Enable lingering with `loginctl enable-linger "$USER"` if the user manager must
start at boot without an interactive login. Starting the service manually is a
safe way to request an immediate catch up; systemd will not launch a second
instance if a refresh is already active.

## Lifecycle

```bash
# Stop, retain data
docker compose down

# Rebuild
git pull
docker compose up --detach --build

# Stop and delete the named data volume
docker compose down --volumes
```

The application has no authentication. `DEWHIRLPOOLER_BIND_ADDRESS` defaults
to `127.0.0.1`; wider bindings require an external access-control layer.

Plain Fulcrum uses TCP. Set `DEWHIRLPOOLER_FULCRUM_TLS=true` for TLS and use the
matching TLS port.

## Troubleshooting

- `BYPASS`: cache disabled or a cache operation failed.
- Unhealthy container: inspect `docker compose ps` and service logs.
- `/data` permission failure: volume must be writable by UID/GID
  `10001:10001`.
- Fulcrum failure: verify host, port, TLS mode, routing, and firewall.
- Core failure: verify the RPC whitelist, unpruned range, and verbosity-3
  prevout availability.
