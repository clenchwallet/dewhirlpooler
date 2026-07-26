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
