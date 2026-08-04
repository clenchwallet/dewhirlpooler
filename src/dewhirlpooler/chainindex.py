"""Resumable SQLite index for chain-wide Whirlpool aggregates."""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import time
from collections.abc import Callable, Mapping, Sequence
from concurrent.futures import Future, ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path

from .bitcoin import OutPoint, ScriptType, Transaction, TxOutput
from .blocksource import CoreBlock, CoreBlockError, CoreBlockSource
from .core import CoreRpcError
from .pathutils import expand_user_path
from .whirlpool import (
    DEFAULT_POOLS,
    Confidence,
    OutputRole,
    PoolDefinition,
    TransactionKind,
    WhirlpoolDetection,
    detect_whirlpool,
)

_SCHEMA_VERSION = "1"
_DEFAULT_START_HEIGHT = 550_000
_DEFAULT_BUSY_TIMEOUT_MS = 5_000
_DEFAULT_PREFETCH_WORKERS = 8
_MAX_PREFETCH_WORKERS = 16
_HASH_LENGTH = 64


class ChainIndexError(RuntimeError):
    """Safe public failure for chain-index configuration or state."""


@dataclass(frozen=True, slots=True)
class ChainIndexSettings:
    """Filesystem and coverage settings for one derived chain index."""

    path: Path
    start_height: int = _DEFAULT_START_HEIGHT
    busy_timeout_ms: int = _DEFAULT_BUSY_TIMEOUT_MS
    prefetch_workers: int = _DEFAULT_PREFETCH_WORKERS

    def __post_init__(self) -> None:
        if not isinstance(self.path, Path) or "\x00" in str(self.path):
            raise ValueError("Chain index path must be a valid Path.")
        if type(self.start_height) is not int or self.start_height < 0:
            raise ValueError(
                "Chain index start height must be a nonnegative integer."
            )
        if type(self.busy_timeout_ms) is not int or self.busy_timeout_ms <= 0:
            raise ValueError(
                "Chain index busy timeout must be a positive integer."
            )
        if (
            type(self.prefetch_workers) is not int
            or not 1 <= self.prefetch_workers <= _MAX_PREFETCH_WORKERS
        ):
            raise ValueError(
                "Chain index prefetch workers must be an integer "
                "from 1 through 16."
            )

    @classmethod
    def from_env(
        cls,
        env: Mapping[str, str] | None = None,
    ) -> ChainIndexSettings:
        values = os.environ if env is None else env
        path_text = values.get(
            "DEWHIRLPOOLER_CHAIN_DB",
            "/data/chain.sqlite3",
        )
        if (
            not isinstance(path_text, str)
            or not path_text.strip()
            or "\x00" in path_text
        ):
            raise ValueError(
                "DEWHIRLPOOLER_CHAIN_DB must be a database file path"
            )

        start_height = _parse_nonnegative_integer(
            values.get(
                "DEWHIRLPOOLER_CHAIN_START_HEIGHT",
                str(_DEFAULT_START_HEIGHT),
            ),
            "DEWHIRLPOOLER_CHAIN_START_HEIGHT",
        )
        busy_timeout_ms = _parse_positive_integer(
            values.get(
                "DEWHIRLPOOLER_CHAIN_BUSY_TIMEOUT_MS",
                str(_DEFAULT_BUSY_TIMEOUT_MS),
            ),
            "DEWHIRLPOOLER_CHAIN_BUSY_TIMEOUT_MS",
        )
        prefetch_workers = _parse_prefetch_workers(
            values.get(
                "DEWHIRLPOOLER_CHAIN_PREFETCH_WORKERS",
                str(_DEFAULT_PREFETCH_WORKERS),
            )
        )
        return cls(
            path=expand_user_path(path_text),
            start_height=start_height,
            busy_timeout_ms=busy_timeout_ms,
            prefetch_workers=prefetch_workers,
        )


@dataclass(frozen=True, slots=True)
class PoolSnapshot:
    height: int
    pool_id: str
    liquidity_sats: int
    utxo_count: int
    entry_sats: int
    exit_sats: int
    tx0_count: int
    round_count: int


@dataclass(frozen=True, slots=True)
class CoordinatorSummary:
    gross_revenue_sats: int
    known_mining_cost_sats: int
    net_known_profit_sats: int
    fee_output_count: int
    ambiguous_spend_count: int
    ambiguous_input_sats: int


@dataclass(frozen=True, slots=True)
class ChainIndexStatus:
    start_height: int
    last_height: int | None
    last_block_hash: str | None
    blocks_indexed: int
    tip_height: int | None
    complete_to_tip: bool


@dataclass(frozen=True, slots=True)
class ScanResult:
    start_height: int
    stop_height: int
    blocks_scanned: int
    reorg_blocks_rolled_back: int


@dataclass(frozen=True, slots=True)
class _PoolUtxo:
    pool_id: str
    liquidity_sats: int
    source_kind: str


@dataclass(frozen=True, slots=True)
class _CoordinatorUtxo:
    pool_id: str
    value_sats: int
    script_id: str


_SCHEMA = """
CREATE TABLE IF NOT EXISTS chain_meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS chain_blocks (
    height INTEGER PRIMARY KEY CHECK (height >= 0),
    block_hash TEXT NOT NULL UNIQUE,
    previous_block_hash TEXT,
    block_time INTEGER NOT NULL CHECK (block_time >= 0)
);

CREATE TABLE IF NOT EXISTS pool_utxos (
    txid TEXT NOT NULL,
    vout INTEGER NOT NULL CHECK (vout >= 0),
    pool_id TEXT NOT NULL,
    liquidity_sats INTEGER NOT NULL CHECK (liquidity_sats > 0),
    source_kind TEXT NOT NULL CHECK (source_kind IN ('tx0', 'round')),
    created_height INTEGER NOT NULL REFERENCES chain_blocks(height),
    spent_height INTEGER REFERENCES chain_blocks(height),
    spent_txid TEXT,
    spend_kind TEXT CHECK (
        spend_kind IS NULL OR spend_kind IN ('round', 'exit')
    ),
    PRIMARY KEY (txid, vout)
);

CREATE TABLE IF NOT EXISTS pool_snapshots (
    height INTEGER NOT NULL REFERENCES chain_blocks(height),
    pool_id TEXT NOT NULL,
    liquidity_sats INTEGER NOT NULL CHECK (liquidity_sats >= 0),
    utxo_count INTEGER NOT NULL CHECK (utxo_count >= 0),
    entry_sats INTEGER NOT NULL CHECK (entry_sats >= 0),
    exit_sats INTEGER NOT NULL CHECK (exit_sats >= 0),
    tx0_count INTEGER NOT NULL CHECK (tx0_count >= 0),
    round_count INTEGER NOT NULL CHECK (round_count >= 0),
    PRIMARY KEY (height, pool_id)
);

CREATE TABLE IF NOT EXISTS indexed_tx0s (
    txid TEXT PRIMARY KEY,
    height INTEGER NOT NULL REFERENCES chain_blocks(height),
    pool_id TEXT NOT NULL,
    confidence TEXT NOT NULL,
    input_count INTEGER NOT NULL,
    input_value_sats INTEGER NOT NULL,
    miner_fee_sats INTEGER NOT NULL,
    coordinator_fee_sats INTEGER NOT NULL,
    coordinator_fee_vout INTEGER,
    coordinator_fee_method TEXT,
    premix_output_count INTEGER NOT NULL,
    entered_pool_sats INTEGER NOT NULL,
    total_fee_cost_sats INTEGER NOT NULL,
    fee_cost_percent TEXT NOT NULL,
    doxxic_change_vout INTEGER
);

CREATE TABLE IF NOT EXISTS indexed_rounds (
    txid TEXT PRIMARY KEY,
    height INTEGER NOT NULL REFERENCES chain_blocks(height),
    pool_id TEXT NOT NULL,
    round_size INTEGER NOT NULL,
    entrant_count INTEGER NOT NULL,
    remixer_count INTEGER NOT NULL,
    miner_fee_sats INTEGER NOT NULL,
    liquidity_rollover INTEGER NOT NULL
        CHECK (liquidity_rollover IN (0, 1))
);

CREATE TABLE IF NOT EXISTS coordinator_fee_utxos (
    txid TEXT NOT NULL,
    vout INTEGER NOT NULL CHECK (vout >= 0),
    pool_id TEXT NOT NULL,
    value_sats INTEGER NOT NULL CHECK (value_sats >= 0),
    script_id TEXT NOT NULL,
    confidence TEXT NOT NULL,
    method TEXT NOT NULL,
    created_height INTEGER NOT NULL REFERENCES chain_blocks(height),
    spent_height INTEGER REFERENCES chain_blocks(height),
    spent_txid TEXT,
    PRIMARY KEY (txid, vout)
);

CREATE TABLE IF NOT EXISTS coordinator_spends (
    txid TEXT PRIMARY KEY,
    height INTEGER NOT NULL REFERENCES chain_blocks(height),
    tracked_input_sats INTEGER NOT NULL,
    total_input_sats INTEGER NOT NULL,
    miner_fee_sats INTEGER NOT NULL,
    attributed_mining_cost_sats INTEGER NOT NULL,
    all_inputs_tracked INTEGER NOT NULL
        CHECK (all_inputs_tracked IN (0, 1))
);

CREATE INDEX IF NOT EXISTS pool_utxos_active
ON pool_utxos(pool_id, created_height)
WHERE spent_height IS NULL;

CREATE INDEX IF NOT EXISTS pool_snapshots_pool_height
ON pool_snapshots(pool_id, height);

CREATE INDEX IF NOT EXISTS indexed_tx0s_height_pool
ON indexed_tx0s(height, pool_id);

CREATE INDEX IF NOT EXISTS indexed_rounds_height_pool
ON indexed_rounds(height, pool_id);

CREATE INDEX IF NOT EXISTS coordinator_fee_utxos_active
ON coordinator_fee_utxos(created_height)
WHERE spent_height IS NULL;

CREATE INDEX IF NOT EXISTS coordinator_spends_height
ON coordinator_spends(height);
"""


class ChainIndex:
    """One reorg-aware derived index backed by SQLite."""

    def __init__(
        self,
        settings: ChainIndexSettings,
        pools: Sequence[PoolDefinition] = DEFAULT_POOLS,
    ) -> None:
        self.settings = settings
        self.pools = tuple(pools)
        if not self.pools:
            raise ValueError("At least one Whirlpool pool is required.")
        identifiers = [pool.identifier for pool in self.pools]
        if len(set(identifiers)) != len(identifiers):
            raise ValueError("Whirlpool pool identifiers must be unique.")
        self._pool_by_id = {
            pool.identifier: pool for pool in self.pools
        }
        self._validate_path()
        settings.path.parent.mkdir(parents=True, exist_ok=True)
        try:
            self._connection = sqlite3.connect(
                settings.path,
                timeout=settings.busy_timeout_ms / 1000,
                isolation_level=None,
            )
        except sqlite3.Error:
            raise ChainIndexError(
                "The chain index database could not be opened."
            ) from None
        self._connection.row_factory = sqlite3.Row
        try:
            self._configure()
            self._initialize_schema()
            self._validate_metadata()
            self._reload_active_state()
        except Exception:
            self._connection.close()
            raise

    def __enter__(self) -> ChainIndex:
        return self

    def __exit__(
        self,
        exc_type: object,
        exc_value: object,
        traceback: object,
    ) -> None:
        self.close()

    def close(self) -> None:
        self._connection.close()

    def status(
        self,
        *,
        tip_height: int | None = None,
    ) -> ChainIndexStatus:
        if tip_height is not None and (
            type(tip_height) is not int or tip_height < 0
        ):
            raise ValueError("Tip height must be a nonnegative integer.")
        row = self._connection.execute(
            """
            SELECT height, block_hash
            FROM chain_blocks
            ORDER BY height DESC
            LIMIT 1
            """
        ).fetchone()
        count = int(
            self._connection.execute(
                "SELECT COUNT(*) FROM chain_blocks"
            ).fetchone()[0]
        )
        last_height = int(row["height"]) if row is not None else None
        last_hash = str(row["block_hash"]) if row is not None else None
        return ChainIndexStatus(
            start_height=self.settings.start_height,
            last_height=last_height,
            last_block_hash=last_hash,
            blocks_indexed=count,
            tip_height=tip_height,
            complete_to_tip=(
                tip_height is not None and last_height == tip_height
            ),
        )

    def block_hash(self, height: int) -> str | None:
        if type(height) is not int or height < 0:
            raise ValueError("Block height must be a nonnegative integer.")
        row = self._connection.execute(
            "SELECT block_hash FROM chain_blocks WHERE height = ?",
            (height,),
        ).fetchone()
        return str(row[0]) if row is not None else None

    def apply_block(self, block: CoreBlock) -> None:
        status = self.status()
        expected_height = (
            self.settings.start_height
            if status.last_height is None
            else status.last_height + 1
        )
        if block.height != expected_height:
            raise ChainIndexError(
                "The block height did not follow the chain index."
            )
        if (
            status.last_height is not None
            and block.previous_block_hash != status.last_block_hash
        ):
            raise ChainIndexError(
                "The block did not connect to the chain index."
            )

        pool_spent: dict[OutPoint, tuple[str, str]] = {}
        pool_added: dict[OutPoint, _PoolUtxo] = {}
        coordinator_spent: dict[OutPoint, str] = {}
        coordinator_added: dict[OutPoint, _CoordinatorUtxo] = {}
        coordinator_scripts = set(self._coordinator_scripts)
        entries = {pool.identifier: 0 for pool in self.pools}
        exits = {pool.identifier: 0 for pool in self.pools}
        tx0_counts = {pool.identifier: 0 for pool in self.pools}
        round_counts = {pool.identifier: 0 for pool in self.pools}
        tx0_rows: list[tuple[object, ...]] = []
        round_rows: list[tuple[object, ...]] = []
        coordinator_spend_rows: list[tuple[object, ...]] = []
        coordinator_fee_rows: list[tuple[object, ...]] = []

        for block_transaction in block.transactions:
            transaction = block_transaction.transaction
            prevouts = block_transaction.prevouts
            detection = detect_whirlpool(transaction, prevouts)
            transaction_pool_inputs = self._tracked_pool_inputs(
                transaction,
                pool_spent,
                pool_added,
            )
            rollover = self._is_liquidity_rollover(
                transaction,
                detection,
                transaction_pool_inputs,
            )

            for outpoint, tracked in transaction_pool_inputs.items():
                spend_kind = "round" if rollover else "exit"
                pool_spent[outpoint] = (transaction.txid, spend_kind)
                if not rollover:
                    exits[tracked.pool_id] += tracked.liquidity_sats

            coordinator_inputs = self._tracked_coordinator_inputs(
                transaction,
                coordinator_spent,
                coordinator_added,
            )
            if coordinator_inputs:
                total_input_sats, miner_fee_sats = _transaction_accounting(
                    transaction,
                    prevouts,
                )
                tracked_input_sats = sum(
                    item.value_sats for item in coordinator_inputs.values()
                )
                all_inputs_tracked = (
                    len(coordinator_inputs) == len(transaction.inputs)
                )
                attributed_cost = (
                    miner_fee_sats if all_inputs_tracked else 0
                )
                coordinator_spend_rows.append(
                    (
                        transaction.txid,
                        block.height,
                        tracked_input_sats,
                        total_input_sats,
                        miner_fee_sats,
                        attributed_cost,
                        int(all_inputs_tracked),
                    )
                )
                for outpoint in coordinator_inputs:
                    coordinator_spent[outpoint] = transaction.txid

            if detection.kind is TransactionKind.TX0:
                self._stage_tx0(
                    block=block,
                    transaction=transaction,
                    detection=detection,
                    coordinator_scripts=coordinator_scripts,
                    entries=entries,
                    tx0_counts=tx0_counts,
                    pool_added=pool_added,
                    coordinator_added=coordinator_added,
                    tx0_rows=tx0_rows,
                    coordinator_fee_rows=coordinator_fee_rows,
                )
            elif (
                detection.kind is TransactionKind.WHIRLPOOL_ROUND
                and detection.pool is not None
                and detection.input_count is not None
                and detection.miner_fee_sats is not None
                and detection.round_size is not None
            ):
                pool_id = detection.pool.identifier
                round_counts[pool_id] += 1
                if rollover:
                    for output in transaction.outputs:
                        outpoint = OutPoint(transaction.txid, output.index)
                        pool_added[outpoint] = _PoolUtxo(
                            pool_id=pool_id,
                            liquidity_sats=detection.pool.denomination_sats,
                            source_kind="round",
                        )
                round_rows.append(
                    (
                        transaction.txid,
                        block.height,
                        pool_id,
                        detection.round_size,
                        detection.premix_input_count,
                        detection.remix_input_count,
                        detection.miner_fee_sats,
                        int(rollover),
                    )
                )

        snapshots = self._snapshots_after_changes(
            block.height,
            entries=entries,
            exits=exits,
            tx0_counts=tx0_counts,
            round_counts=round_counts,
            pool_spent=pool_spent,
            pool_added=pool_added,
        )
        self._write_block(
            block=block,
            pool_spent=pool_spent,
            pool_added=pool_added,
            coordinator_spent=coordinator_spent,
            coordinator_added=coordinator_added,
            tx0_rows=tx0_rows,
            round_rows=round_rows,
            coordinator_spend_rows=coordinator_spend_rows,
            coordinator_fee_rows=coordinator_fee_rows,
            snapshots=snapshots,
        )
        for outpoint in pool_spent:
            self._pool_active.pop(outpoint, None)
        self._pool_active.update(
            {
                outpoint: item
                for outpoint, item in pool_added.items()
                if outpoint not in pool_spent
            }
        )
        for outpoint in coordinator_spent:
            self._coordinator_active.pop(outpoint, None)
        self._coordinator_active.update(
            {
                outpoint: item
                for outpoint, item in coordinator_added.items()
                if outpoint not in coordinator_spent
            }
        )
        self._coordinator_scripts.update(
            item.script_id for item in coordinator_added.values()
        )
        self._liquidity = {
            snapshot.pool_id: snapshot.liquidity_sats
            for snapshot in snapshots
        }
        self._utxo_counts = {
            snapshot.pool_id: snapshot.utxo_count
            for snapshot in snapshots
        }

    def rollback_after(self, height: int) -> int:
        if type(height) is not int or height < self.settings.start_height - 1:
            raise ChainIndexError(
                "The chain index cannot roll back below its start height."
            )
        row = self._connection.execute(
            "SELECT COUNT(*) FROM chain_blocks WHERE height > ?",
            (height,),
        ).fetchone()
        rollback_count = int(row[0])
        if rollback_count == 0:
            return 0
        try:
            self._connection.execute("BEGIN IMMEDIATE")
            self._connection.execute(
                """
                UPDATE pool_utxos
                SET spent_height = NULL, spent_txid = NULL, spend_kind = NULL
                WHERE spent_height > ?
                """,
                (height,),
            )
            self._connection.execute(
                """
                UPDATE coordinator_fee_utxos
                SET spent_height = NULL, spent_txid = NULL
                WHERE spent_height > ?
                """,
                (height,),
            )
            for table in (
                "coordinator_spends",
                "coordinator_fee_utxos",
                "indexed_rounds",
                "indexed_tx0s",
                "pool_snapshots",
                "pool_utxos",
            ):
                column = (
                    "created_height"
                    if table in {"coordinator_fee_utxos", "pool_utxos"}
                    else "height"
                )
                self._connection.execute(
                    f"DELETE FROM {table} WHERE {column} > ?",
                    (height,),
                )
            self._connection.execute(
                "DELETE FROM chain_blocks WHERE height > ?",
                (height,),
            )
            self._connection.execute("COMMIT")
        except sqlite3.Error:
            self._rollback_quietly()
            raise ChainIndexError(
                "The chain index rollback failed."
            ) from None
        self._reload_active_state()
        return rollback_count

    def pool_snapshot(
        self,
        pool_id: str,
        height: int,
    ) -> PoolSnapshot | None:
        self._require_pool(pool_id)
        if type(height) is not int or height < 0:
            raise ValueError("Block height must be a nonnegative integer.")
        row = self._connection.execute(
            """
            SELECT height, pool_id, liquidity_sats, utxo_count, entry_sats,
                   exit_sats, tx0_count, round_count
            FROM pool_snapshots
            WHERE pool_id = ? AND height = ?
            """,
            (pool_id, height),
        ).fetchone()
        return _snapshot_from_row(row) if row is not None else None

    def latest_pool_snapshots(self) -> tuple[PoolSnapshot, ...]:
        rows = self._connection.execute(
            """
            SELECT snapshots.height, snapshots.pool_id,
                   snapshots.liquidity_sats, snapshots.utxo_count,
                   snapshots.entry_sats, snapshots.exit_sats,
                   snapshots.tx0_count, snapshots.round_count
            FROM pool_snapshots AS snapshots
            JOIN (
                SELECT pool_id, MAX(height) AS height
                FROM pool_snapshots
                GROUP BY pool_id
            ) AS latest
              ON latest.pool_id = snapshots.pool_id
             AND latest.height = snapshots.height
            ORDER BY snapshots.pool_id
            """
        ).fetchall()
        return tuple(_snapshot_from_row(row) for row in rows)

    def coordinator_summary(self) -> CoordinatorSummary:
        fee_row = self._connection.execute(
            """
            SELECT COALESCE(SUM(value_sats), 0), COUNT(*)
            FROM coordinator_fee_utxos
            """
        ).fetchone()
        spend_row = self._connection.execute(
            """
            SELECT COALESCE(SUM(attributed_mining_cost_sats), 0),
                   COALESCE(SUM(
                       CASE WHEN all_inputs_tracked = 0 THEN 1 ELSE 0 END
                   ), 0),
                   COALESCE(SUM(
                       CASE
                           WHEN all_inputs_tracked = 0
                           THEN tracked_input_sats
                           ELSE 0
                       END
                   ), 0)
            FROM coordinator_spends
            """
        ).fetchone()
        gross = int(fee_row[0])
        mining_cost = int(spend_row[0])
        return CoordinatorSummary(
            gross_revenue_sats=gross,
            known_mining_cost_sats=mining_cost,
            net_known_profit_sats=gross - mining_cost,
            fee_output_count=int(fee_row[1]),
            ambiguous_spend_count=int(spend_row[1]),
            ambiguous_input_sats=int(spend_row[2]),
        )

    def _validate_path(self) -> None:
        if self.settings.path.exists() and self.settings.path.is_dir():
            raise ChainIndexError(
                "The chain index path must be a database file."
            )

    def _configure(self) -> None:
        try:
            self._connection.execute(
                f"PRAGMA busy_timeout = {self.settings.busy_timeout_ms}"
            )
            self._connection.execute("PRAGMA foreign_keys = ON")
            self._connection.execute("PRAGMA journal_mode = WAL")
            self._connection.execute("PRAGMA synchronous = NORMAL")
        except sqlite3.Error:
            raise ChainIndexError(
                "The chain index database could not be configured."
            ) from None

    def _initialize_schema(self) -> None:
        try:
            self._connection.executescript(_SCHEMA)
            self._connection.execute(
                """
                INSERT OR IGNORE INTO chain_meta(key, value)
                VALUES ('schema_version', ?)
                """,
                (_SCHEMA_VERSION,),
            )
            self._connection.execute(
                """
                INSERT OR IGNORE INTO chain_meta(key, value)
                VALUES ('start_height', ?)
                """,
                (str(self.settings.start_height),),
            )
            self._connection.execute(
                """
                INSERT OR IGNORE INTO chain_meta(key, value)
                VALUES ('pool_config', ?)
                """,
                (_pool_config(self.pools),),
            )
        except sqlite3.Error:
            raise ChainIndexError(
                "The chain index schema could not be initialized."
            ) from None

    def _validate_metadata(self) -> None:
        rows = self._connection.execute(
            "SELECT key, value FROM chain_meta"
        ).fetchall()
        metadata = {str(row["key"]): str(row["value"]) for row in rows}
        if metadata.get("schema_version") != _SCHEMA_VERSION:
            raise ChainIndexError(
                "The chain index schema version is unsupported."
            )
        if metadata.get("start_height") != str(self.settings.start_height):
            raise ChainIndexError(
                "The chain index start height does not match its database."
            )
        if metadata.get("pool_config") != _pool_config(self.pools):
            raise ChainIndexError(
                "The Whirlpool pool configuration does not match its database."
            )

    def _reload_active_state(self) -> None:
        self._pool_active: dict[OutPoint, _PoolUtxo] = {}
        for row in self._connection.execute(
            """
            SELECT txid, vout, pool_id, liquidity_sats, source_kind
            FROM pool_utxos
            WHERE spent_height IS NULL
            """
        ):
            self._pool_active[
                OutPoint(str(row["txid"]), int(row["vout"]))
            ] = _PoolUtxo(
                pool_id=str(row["pool_id"]),
                liquidity_sats=int(row["liquidity_sats"]),
                source_kind=str(row["source_kind"]),
            )

        self._coordinator_active: dict[OutPoint, _CoordinatorUtxo] = {}
        for row in self._connection.execute(
            """
            SELECT txid, vout, pool_id, value_sats, script_id
            FROM coordinator_fee_utxos
            WHERE spent_height IS NULL
            """
        ):
            self._coordinator_active[
                OutPoint(str(row["txid"]), int(row["vout"]))
            ] = _CoordinatorUtxo(
                pool_id=str(row["pool_id"]),
                value_sats=int(row["value_sats"]),
                script_id=str(row["script_id"]),
            )
        self._coordinator_scripts = {
            str(row[0])
            for row in self._connection.execute(
                "SELECT DISTINCT script_id FROM coordinator_fee_utxos"
            )
        }
        self._liquidity = {
            pool.identifier: 0 for pool in self.pools
        }
        self._utxo_counts = {
            pool.identifier: 0 for pool in self.pools
        }
        for item in self._pool_active.values():
            self._liquidity[item.pool_id] += item.liquidity_sats
            self._utxo_counts[item.pool_id] += 1

    def _tracked_pool_inputs(
        self,
        transaction: Transaction,
        spent: Mapping[OutPoint, tuple[str, str]],
        added: Mapping[OutPoint, _PoolUtxo],
    ) -> dict[OutPoint, _PoolUtxo]:
        tracked: dict[OutPoint, _PoolUtxo] = {}
        for transaction_input in transaction.inputs:
            outpoint = transaction_input.previous_output
            if outpoint in spent:
                raise ChainIndexError(
                    "A block spent one tracked pool output twice."
                )
            item = added.get(outpoint, self._pool_active.get(outpoint))
            if item is not None:
                tracked[outpoint] = item
        return tracked

    def _tracked_coordinator_inputs(
        self,
        transaction: Transaction,
        spent: Mapping[OutPoint, str],
        added: Mapping[OutPoint, _CoordinatorUtxo],
    ) -> dict[OutPoint, _CoordinatorUtxo]:
        tracked: dict[OutPoint, _CoordinatorUtxo] = {}
        for transaction_input in transaction.inputs:
            outpoint = transaction_input.previous_output
            if outpoint in spent:
                raise ChainIndexError(
                    "A block spent one coordinator fee output twice."
                )
            item = added.get(
                outpoint,
                self._coordinator_active.get(outpoint),
            )
            if item is not None:
                tracked[outpoint] = item
        return tracked

    def _is_liquidity_rollover(
        self,
        transaction: Transaction,
        detection: WhirlpoolDetection,
        tracked: Mapping[OutPoint, _PoolUtxo],
    ) -> bool:
        if (
            detection.kind is not TransactionKind.WHIRLPOOL_ROUND
            or detection.confidence is not Confidence.HIGH
            or detection.pool is None
            or len(tracked) != len(transaction.inputs)
        ):
            return False
        pool_id = detection.pool.identifier
        return (
            all(item.pool_id == pool_id for item in tracked.values())
            and sum(item.liquidity_sats for item in tracked.values())
            == len(transaction.outputs) * detection.pool.denomination_sats
        )

    def _stage_tx0(
        self,
        *,
        block: CoreBlock,
        transaction: Transaction,
        detection: WhirlpoolDetection,
        coordinator_scripts: set[str],
        entries: dict[str, int],
        tx0_counts: dict[str, int],
        pool_added: dict[OutPoint, _PoolUtxo],
        coordinator_added: dict[OutPoint, _CoordinatorUtxo],
        tx0_rows: list[tuple[object, ...]],
        coordinator_fee_rows: list[tuple[object, ...]],
    ) -> None:
        pool = detection.pool
        if (
            pool is None
            or detection.input_count is None
            or detection.input_value_sats is None
            or detection.miner_fee_sats is None
            or detection.premix_output_count is None
            or detection.entered_pool_sats is None
            or detection.total_fee_cost_sats is None
            or detection.fee_cost_percent is None
        ):
            return

        roles = {item.index: item.role for item in detection.outputs}
        premix_outputs = tuple(
            output
            for output in transaction.outputs
            if roles.get(output.index) is OutputRole.PREMIX
        )
        if len(premix_outputs) != detection.premix_output_count:
            raise ChainIndexError("Tx0 premix accounting was inconsistent.")

        fee_output, fee_method, fee_confidence = _coordinator_fee_output(
            transaction,
            detection,
            coordinator_scripts,
        )
        coordinator_fee_sats = (
            fee_output.value_sats if fee_output is not None else 0
        )
        total_fee_cost_sats = (
            detection.miner_fee_sats + coordinator_fee_sats
        )
        fee_percent = _percentage_text(
            total_fee_cost_sats,
            detection.entered_pool_sats,
        )
        doxxic = next(
            (
                output.index
                for output in transaction.outputs
                if roles.get(output.index) is OutputRole.DOXXIC_CHANGE
            ),
            None,
        )
        tx0_rows.append(
            (
                transaction.txid,
                block.height,
                pool.identifier,
                detection.confidence.value,
                detection.input_count,
                detection.input_value_sats,
                detection.miner_fee_sats,
                coordinator_fee_sats,
                fee_output.index if fee_output is not None else None,
                fee_method,
                detection.premix_output_count,
                detection.entered_pool_sats,
                total_fee_cost_sats,
                fee_percent,
                doxxic,
            )
        )
        tx0_counts[pool.identifier] += 1
        for output in premix_outputs:
            outpoint = OutPoint(transaction.txid, output.index)
            pool_added[outpoint] = _PoolUtxo(
                pool_id=pool.identifier,
                liquidity_sats=pool.denomination_sats,
                source_kind="tx0",
            )
            entries[pool.identifier] += pool.denomination_sats

        if fee_output is not None and fee_method is not None:
            outpoint = OutPoint(transaction.txid, fee_output.index)
            script_id = _script_id(fee_output)
            item = _CoordinatorUtxo(
                pool_id=pool.identifier,
                value_sats=fee_output.value_sats,
                script_id=script_id,
            )
            coordinator_added[outpoint] = item
            coordinator_scripts.add(script_id)
            coordinator_fee_rows.append(
                (
                    transaction.txid,
                    fee_output.index,
                    pool.identifier,
                    fee_output.value_sats,
                    script_id,
                    fee_confidence.value,
                    fee_method,
                    block.height,
                )
            )

    def _snapshots_after_changes(
        self,
        height: int,
        *,
        entries: Mapping[str, int],
        exits: Mapping[str, int],
        tx0_counts: Mapping[str, int],
        round_counts: Mapping[str, int],
        pool_spent: Mapping[OutPoint, tuple[str, str]],
        pool_added: Mapping[OutPoint, _PoolUtxo],
    ) -> tuple[PoolSnapshot, ...]:
        liquidity = dict(self._liquidity)
        counts = dict(self._utxo_counts)
        for outpoint in pool_spent:
            if outpoint in pool_added:
                continue
            item = pool_added.get(
                outpoint,
                self._pool_active.get(outpoint),
            )
            if item is None:
                raise ChainIndexError(
                    "A tracked pool spend was unavailable."
                )
            liquidity[item.pool_id] -= item.liquidity_sats
            counts[item.pool_id] -= 1
        for outpoint, item in pool_added.items():
            if outpoint in pool_spent:
                continue
            liquidity[item.pool_id] += item.liquidity_sats
            counts[item.pool_id] += 1

        snapshots: list[PoolSnapshot] = []
        for pool in self.pools:
            pool_id = pool.identifier
            expected = (
                self._liquidity[pool_id]
                + entries[pool_id]
                - exits[pool_id]
            )
            if (
                liquidity[pool_id] != expected
                or liquidity[pool_id] < 0
                or counts[pool_id] < 0
            ):
                raise ChainIndexError(
                    "Pool liquidity changes did not reconcile."
                )
            snapshots.append(
                PoolSnapshot(
                    height=height,
                    pool_id=pool_id,
                    liquidity_sats=liquidity[pool_id],
                    utxo_count=counts[pool_id],
                    entry_sats=entries[pool_id],
                    exit_sats=exits[pool_id],
                    tx0_count=tx0_counts[pool_id],
                    round_count=round_counts[pool_id],
                )
            )
        return tuple(snapshots)

    def _write_block(
        self,
        *,
        block: CoreBlock,
        pool_spent: Mapping[OutPoint, tuple[str, str]],
        pool_added: Mapping[OutPoint, _PoolUtxo],
        coordinator_spent: Mapping[OutPoint, str],
        coordinator_added: Mapping[OutPoint, _CoordinatorUtxo],
        tx0_rows: Sequence[tuple[object, ...]],
        round_rows: Sequence[tuple[object, ...]],
        coordinator_spend_rows: Sequence[tuple[object, ...]],
        coordinator_fee_rows: Sequence[tuple[object, ...]],
        snapshots: Sequence[PoolSnapshot],
    ) -> None:
        try:
            self._connection.execute("BEGIN IMMEDIATE")
            self._connection.execute(
                """
                INSERT INTO chain_blocks(
                    height, block_hash, previous_block_hash, block_time
                ) VALUES (?, ?, ?, ?)
                """,
                (
                    block.height,
                    block.block_hash,
                    block.previous_block_hash,
                    block.block_time,
                ),
            )
            self._connection.executemany(
                """
                UPDATE pool_utxos
                SET spent_height = ?, spent_txid = ?, spend_kind = ?
                WHERE txid = ? AND vout = ? AND spent_height IS NULL
                """,
                (
                    (
                        block.height,
                        spending_txid,
                        spend_kind,
                        outpoint.txid,
                        outpoint.index,
                    )
                    for outpoint, (
                        spending_txid,
                        spend_kind,
                    ) in pool_spent.items()
                    if outpoint not in pool_added
                ),
            )
            self._connection.executemany(
                """
                INSERT INTO pool_utxos(
                    txid, vout, pool_id, liquidity_sats, source_kind,
                    created_height, spent_height, spent_txid, spend_kind
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    (
                        outpoint.txid,
                        outpoint.index,
                        item.pool_id,
                        item.liquidity_sats,
                        item.source_kind,
                        block.height,
                        (
                            block.height
                            if outpoint in pool_spent
                            else None
                        ),
                        (
                            pool_spent[outpoint][0]
                            if outpoint in pool_spent
                            else None
                        ),
                        (
                            pool_spent[outpoint][1]
                            if outpoint in pool_spent
                            else None
                        ),
                    )
                    for outpoint, item in pool_added.items()
                ),
            )
            self._connection.executemany(
                """
                UPDATE coordinator_fee_utxos
                SET spent_height = ?, spent_txid = ?
                WHERE txid = ? AND vout = ? AND spent_height IS NULL
                """,
                (
                    (
                        block.height,
                        spending_txid,
                        outpoint.txid,
                        outpoint.index,
                    )
                    for outpoint, spending_txid in coordinator_spent.items()
                    if outpoint not in coordinator_added
                ),
            )
            self._connection.executemany(
                """
                INSERT INTO indexed_tx0s VALUES (
                    ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
                )
                """,
                tx0_rows,
            )
            self._connection.executemany(
                """
                INSERT INTO indexed_rounds VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                round_rows,
            )
            self._connection.executemany(
                """
                INSERT INTO coordinator_spends VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                coordinator_spend_rows,
            )
            self._connection.executemany(
                """
                INSERT INTO coordinator_fee_utxos(
                    txid, vout, pool_id, value_sats, script_id,
                    confidence, method, created_height
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                coordinator_fee_rows,
            )
            self._connection.executemany(
                """
                UPDATE coordinator_fee_utxos
                SET spent_height = ?, spent_txid = ?
                WHERE txid = ? AND vout = ? AND spent_height IS NULL
                """,
                (
                    (
                        block.height,
                        spending_txid,
                        outpoint.txid,
                        outpoint.index,
                    )
                    for outpoint, spending_txid in coordinator_spent.items()
                    if outpoint in coordinator_added
                ),
            )
            self._connection.executemany(
                """
                INSERT INTO pool_snapshots VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    (
                        snapshot.height,
                        snapshot.pool_id,
                        snapshot.liquidity_sats,
                        snapshot.utxo_count,
                        snapshot.entry_sats,
                        snapshot.exit_sats,
                        snapshot.tx0_count,
                        snapshot.round_count,
                    )
                    for snapshot in snapshots
                ),
            )
            self._connection.execute("COMMIT")
        except (sqlite3.Error, ChainIndexError):
            self._rollback_quietly()
            raise ChainIndexError(
                "The chain index could not apply the block."
            ) from None

    def _rollback_quietly(self) -> None:
        try:
            self._connection.execute("ROLLBACK")
        except sqlite3.Error:
            pass

    def _require_pool(self, pool_id: str) -> None:
        if pool_id not in self._pool_by_id:
            raise ValueError("The Whirlpool pool identifier is unsupported.")


class ChainIndexReader:
    """Read-only view of one existing derived chain index."""

    def __init__(
        self,
        path: Path,
        *,
        busy_timeout_ms: int = _DEFAULT_BUSY_TIMEOUT_MS,
        pools: Sequence[PoolDefinition] = DEFAULT_POOLS,
    ) -> None:
        if not isinstance(path, Path) or "\x00" in str(path):
            raise ValueError("Chain index path must be a valid Path.")
        if type(busy_timeout_ms) is not int or busy_timeout_ms <= 0:
            raise ValueError(
                "Chain index busy timeout must be a positive integer."
            )
        self.path = path
        self.busy_timeout_ms = busy_timeout_ms
        self.pools = tuple(pools)
        if not self.pools:
            raise ValueError("At least one Whirlpool pool is required.")
        identifiers = [pool.identifier for pool in self.pools]
        if len(set(identifiers)) != len(identifiers):
            raise ValueError("Whirlpool pool identifiers must be unique.")
        self._pool_ids = frozenset(identifiers)
        if not path.is_file():
            raise ChainIndexError(
                "The chain index database is not available."
            )
        try:
            uri = f"{path.resolve().as_uri()}?mode=ro"
            self._connection = sqlite3.connect(
                uri,
                uri=True,
                timeout=busy_timeout_ms / 1000,
                isolation_level=None,
            )
            self._connection.row_factory = sqlite3.Row
            self._connection.execute(
                f"PRAGMA busy_timeout = {busy_timeout_ms}"
            )
            self._connection.execute("PRAGMA query_only = ON")
            self._validate_metadata()
        except ChainIndexError:
            connection = getattr(self, "_connection", None)
            if connection is not None:
                connection.close()
            raise
        except (OSError, sqlite3.Error, ValueError):
            connection = getattr(self, "_connection", None)
            if connection is not None:
                connection.close()
            raise ChainIndexError(
                "The chain index database could not be read."
            ) from None

    def __enter__(self) -> ChainIndexReader:
        return self

    def __exit__(
        self,
        exc_type: object,
        exc_value: object,
        traceback: object,
    ) -> None:
        self.close()

    def close(self) -> None:
        self._connection.close()

    def status(self) -> ChainIndexStatus:
        try:
            row = self._connection.execute(
                """
                SELECT height, block_hash
                FROM chain_blocks
                ORDER BY height DESC
                LIMIT 1
                """
            ).fetchone()
            count = int(
                self._connection.execute(
                    "SELECT COUNT(*) FROM chain_blocks"
                ).fetchone()[0]
            )
        except sqlite3.Error:
            raise ChainIndexError(
                "The chain index status could not be read."
            ) from None
        last_height = int(row["height"]) if row is not None else None
        last_hash = str(row["block_hash"]) if row is not None else None
        return ChainIndexStatus(
            start_height=self._start_height,
            last_height=last_height,
            last_block_hash=last_hash,
            blocks_indexed=count,
            tip_height=None,
            complete_to_tip=False,
        )

    def latest_pool_snapshots(self) -> tuple[PoolSnapshot, ...]:
        try:
            rows = self._connection.execute(
                """
                SELECT snapshots.height, snapshots.pool_id,
                       snapshots.liquidity_sats, snapshots.utxo_count,
                       snapshots.entry_sats, snapshots.exit_sats,
                       snapshots.tx0_count, snapshots.round_count
                FROM pool_snapshots AS snapshots
                JOIN (
                    SELECT pool_id, MAX(height) AS height
                    FROM pool_snapshots
                    GROUP BY pool_id
                ) AS latest
                  ON latest.pool_id = snapshots.pool_id
                 AND latest.height = snapshots.height
                ORDER BY snapshots.pool_id
                """
            ).fetchall()
        except sqlite3.Error:
            raise ChainIndexError(
                "The pool snapshots could not be read."
            ) from None
        return tuple(_snapshot_from_row(row) for row in rows)

    def coordinator_summary(self) -> CoordinatorSummary:
        try:
            fee_row = self._connection.execute(
                """
                SELECT COALESCE(SUM(value_sats), 0), COUNT(*)
                FROM coordinator_fee_utxos
                """
            ).fetchone()
            spend_row = self._connection.execute(
                """
                SELECT COALESCE(SUM(attributed_mining_cost_sats), 0),
                       COALESCE(SUM(
                           CASE WHEN all_inputs_tracked = 0 THEN 1 ELSE 0 END
                       ), 0),
                       COALESCE(SUM(
                           CASE
                               WHEN all_inputs_tracked = 0
                               THEN tracked_input_sats
                               ELSE 0
                           END
                       ), 0)
                FROM coordinator_spends
                """
            ).fetchone()
        except sqlite3.Error:
            raise ChainIndexError(
                "The coordinator summary could not be read."
            ) from None
        gross = int(fee_row[0])
        mining_cost = int(spend_row[0])
        return CoordinatorSummary(
            gross_revenue_sats=gross,
            known_mining_cost_sats=mining_cost,
            net_known_profit_sats=gross - mining_cost,
            fee_output_count=int(fee_row[1]),
            ambiguous_spend_count=int(spend_row[1]),
            ambiguous_input_sats=int(spend_row[2]),
        )

    def pool_history(
        self,
        pool_id: str,
        *,
        start_height: int | None = None,
        end_height: int | None = None,
        limit: int = 500,
    ) -> tuple[PoolSnapshot, ...]:
        self._require_pool(pool_id)
        for name, height in (
            ("Start", start_height),
            ("End", end_height),
        ):
            if height is not None and (
                type(height) is not int or height < 0
            ):
                raise ValueError(
                    f"{name} height must be a nonnegative integer."
                )
        if (
            start_height is not None
            and end_height is not None
            and start_height > end_height
        ):
            raise ValueError("Start height may not exceed end height.")
        if type(limit) is not int or not 1 <= limit <= 2_000:
            raise ValueError("History limit must be from 1 through 2000.")

        clauses = ["pool_id = ?"]
        parameters: list[object] = [pool_id]
        if start_height is not None:
            clauses.append("height >= ?")
            parameters.append(start_height)
        if end_height is not None:
            clauses.append("height <= ?")
            parameters.append(end_height)
        parameters.append(limit)
        where = " AND ".join(clauses)
        try:
            rows = self._connection.execute(
                f"""
                SELECT *
                FROM (
                    SELECT height, pool_id, liquidity_sats, utxo_count,
                           entry_sats, exit_sats, tx0_count, round_count
                    FROM pool_snapshots
                    WHERE {where}
                    ORDER BY height DESC
                    LIMIT ?
                )
                ORDER BY height
                """,
                parameters,
            ).fetchall()
        except sqlite3.Error:
            raise ChainIndexError(
                "The pool history could not be read."
            ) from None
        return tuple(_snapshot_from_row(row) for row in rows)

    def _validate_metadata(self) -> None:
        rows = self._connection.execute(
            "SELECT key, value FROM chain_meta"
        ).fetchall()
        metadata = {str(row["key"]): str(row["value"]) for row in rows}
        if metadata.get("schema_version") != _SCHEMA_VERSION:
            raise ChainIndexError(
                "The chain index schema version is unsupported."
            )
        start_height = metadata.get("start_height")
        if (
            start_height is None
            or not start_height.isdigit()
            or int(start_height) < 0
        ):
            raise ChainIndexError(
                "The chain index start height is invalid."
            )
        if metadata.get("pool_config") != _pool_config(self.pools):
            raise ChainIndexError(
                "The Whirlpool pool configuration does not match its database."
            )
        self._start_height = int(start_height)

    def _require_pool(self, pool_id: str) -> None:
        if pool_id not in self._pool_ids:
            raise ValueError("The Whirlpool pool identifier is unsupported.")


class ChainScanner:
    """Drive a chain index forward with bounded RPC retries."""

    def __init__(
        self,
        source: CoreBlockSource,
        index: ChainIndex,
        *,
        retry_attempts: int = 4,
        retry_delay: Callable[[int], None] = time.sleep,
        prefetch_workers: int = 8,
    ) -> None:
        if type(retry_attempts) is not int or retry_attempts <= 0:
            raise ValueError("Retry attempts must be a positive integer.")
        if (
            type(prefetch_workers) is not int
            or not 1 <= prefetch_workers <= 16
        ):
            raise ValueError(
                "Prefetch workers must be an integer from 1 through 16."
            )
        self.source = source
        self.index = index
        self.retry_attempts = retry_attempts
        self.retry_delay = retry_delay
        self.prefetch_workers = prefetch_workers

    def scan(
        self,
        *,
        stop_height: int | None = None,
        max_blocks: int | None = None,
        progress: Callable[[int, int], None] | None = None,
    ) -> ScanResult:
        if stop_height is not None and (
            type(stop_height) is not int or stop_height < 0
        ):
            raise ValueError("Stop height must be a nonnegative integer.")
        if max_blocks is not None and (
            type(max_blocks) is not int or max_blocks <= 0
        ):
            raise ValueError("Maximum blocks must be a positive integer.")

        tip = self._retry_rpc(self.source.chain_height)
        effective_stop = tip if stop_height is None else min(stop_height, tip)
        rollback_count = self._reconcile_reorg(tip)
        status = self.index.status(tip_height=tip)
        next_height = (
            self.index.settings.start_height
            if status.last_height is None
            else status.last_height + 1
        )
        if effective_stop < next_height:
            return ScanResult(
                start_height=next_height,
                stop_height=effective_stop,
                blocks_scanned=0,
                reorg_blocks_rolled_back=rollback_count,
            )

        scan_start = next_height
        final_height = effective_stop
        if max_blocks is not None:
            final_height = min(
                final_height,
                next_height + max_blocks - 1,
            )
        heights = range(next_height, final_height + 1)
        blocks_scanned = self._scan_heights(
            heights,
            effective_stop=effective_stop,
            progress=progress,
        )
        actual_stop = (
            scan_start + blocks_scanned - 1
            if blocks_scanned
            else effective_stop
        )
        return ScanResult(
            start_height=scan_start,
            stop_height=actual_stop,
            blocks_scanned=blocks_scanned,
            reorg_blocks_rolled_back=rollback_count,
        )

    def _scan_heights(
        self,
        heights: range,
        *,
        effective_stop: int,
        progress: Callable[[int, int], None] | None,
    ) -> int:
        pending: dict[int, Future[CoreBlock]] = {}
        height_iterator = iter(heights)
        blocks_scanned = 0

        executor = ThreadPoolExecutor(
            max_workers=self.prefetch_workers,
            thread_name_prefix="dewhirlpooler-block",
        )
        try:
            for _ in range(self.prefetch_workers):
                try:
                    height = next(height_iterator)
                except StopIteration:
                    break
                pending[height] = executor.submit(
                    self._fetch_block,
                    height,
                )

            for height in heights:
                future = pending.pop(height)
                block = future.result()
                self.index.apply_block(block)
                blocks_scanned += 1
                if progress is not None:
                    progress(height, effective_stop)
                try:
                    next_height = next(height_iterator)
                except StopIteration:
                    continue
                pending[next_height] = executor.submit(
                    self._fetch_block,
                    next_height,
                )
        finally:
            for future in pending.values():
                future.cancel()
            executor.shutdown(wait=True, cancel_futures=True)
        return blocks_scanned

    def _fetch_block(self, height: int) -> CoreBlock:
        return self._retry_rpc(
            lambda: self.source.block_at_height(height)
        )

    def _reconcile_reorg(self, tip: int) -> int:
        status = self.index.status(tip_height=tip)
        last_height = status.last_height
        if last_height is None:
            return 0
        candidate = min(last_height, tip)
        while candidate >= self.index.settings.start_height:
            stored_hash = self.index.block_hash(candidate)
            current_hash = self._retry_rpc(
                lambda candidate=candidate: (
                    self.source.block_hash_at_height(candidate)
                )
            )
            if stored_hash == current_hash:
                return self.index.rollback_after(candidate)
            candidate -= 1
        raise ChainIndexError(
            "The chain reorganization crossed the index start height."
        )

    def _retry_rpc(self, operation: Callable[[], object]):
        for attempt in range(self.retry_attempts):
            try:
                return operation()
            except CoreBlockError:
                raise
            except CoreRpcError:
                if attempt + 1 == self.retry_attempts:
                    raise
                self.retry_delay(2**attempt)
        raise AssertionError("unreachable")


def _parse_nonnegative_integer(value: object, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, str):
        raise ValueError(f"{name} must be a nonnegative integer")
    try:
        parsed = int(value)
    except ValueError:
        raise ValueError(f"{name} must be a nonnegative integer") from None
    if parsed < 0 or str(parsed) != value.strip():
        raise ValueError(f"{name} must be a nonnegative integer")
    return parsed


def _parse_positive_integer(value: object, name: str) -> int:
    parsed = _parse_nonnegative_integer(value, name)
    if parsed <= 0:
        raise ValueError(f"{name} must be a positive integer")
    return parsed


def _parse_prefetch_workers(value: object) -> int:
    name = "DEWHIRLPOOLER_CHAIN_PREFETCH_WORKERS"
    if isinstance(value, bool) or not isinstance(value, str):
        raise ValueError(f"{name} must be an integer from 1 through 16")
    try:
        parsed = int(value)
    except ValueError:
        raise ValueError(
            f"{name} must be an integer from 1 through 16"
        ) from None
    if (
        str(parsed) != value
        or not 1 <= parsed <= _MAX_PREFETCH_WORKERS
    ):
        raise ValueError(f"{name} must be an integer from 1 through 16")
    return parsed


def _pool_config(pools: Sequence[PoolDefinition]) -> str:
    return json.dumps(
        [
            {
                "identifier": pool.identifier,
                "protocol": pool.protocol,
                "denomination_sats": pool.denomination_sats,
                "coordinator_fee_sats": pool.coordinator_fee_sats,
                "alternate_coordinator_fee_sats": (
                    pool.alternate_coordinator_fee_sats
                ),
                "max_premix_outputs": pool.max_premix_outputs,
                "max_premix_reserve_sats": pool.max_premix_reserve_sats,
            }
            for pool in pools
        ],
        sort_keys=True,
        separators=(",", ":"),
    )


def _snapshot_from_row(row: sqlite3.Row) -> PoolSnapshot:
    return PoolSnapshot(
        height=int(row["height"]),
        pool_id=str(row["pool_id"]),
        liquidity_sats=int(row["liquidity_sats"]),
        utxo_count=int(row["utxo_count"]),
        entry_sats=int(row["entry_sats"]),
        exit_sats=int(row["exit_sats"]),
        tx0_count=int(row["tx0_count"]),
        round_count=int(row["round_count"]),
    )


def _transaction_accounting(
    transaction: Transaction,
    prevouts: Mapping[OutPoint, TxOutput],
) -> tuple[int, int]:
    if len(prevouts) != len(transaction.inputs):
        raise ChainIndexError(
            "A coordinator spend did not have complete previous outputs."
        )
    try:
        input_total = sum(
            prevouts[item.previous_output].value_sats
            for item in transaction.inputs
        )
    except KeyError:
        raise ChainIndexError(
            "A coordinator spend did not have complete previous outputs."
        ) from None
    output_total = sum(output.value_sats for output in transaction.outputs)
    miner_fee = input_total - output_total
    if input_total < 0 or miner_fee < 0:
        raise ChainIndexError(
            "A coordinator spend had invalid transaction totals."
        )
    return input_total, miner_fee


def _coordinator_fee_output(
    transaction: Transaction,
    detection: WhirlpoolDetection,
    coordinator_scripts: set[str],
) -> tuple[TxOutput | None, str | None, Confidence]:
    roles = {item.index: item.role for item in detection.outputs}
    exact = [
        output
        for output in transaction.outputs
        if roles.get(output.index) is OutputRole.COORDINATOR_FEE
    ]
    if len(exact) == 1:
        return exact[0], "exact_documented_fee", detection.confidence
    if len(exact) > 1 or detection.pool is None:
        return None, None, Confidence.LOW
    if detection.pool.protocol != "Samourai legacy":
        return None, None, Confidence.LOW

    residual = [
        output
        for output in transaction.outputs
        if (
            roles.get(output.index) is OutputRole.UNCLASSIFIED
            and output.value_sats > 0
            and output.script_type is ScriptType.P2WPKH
        )
    ]
    script_matches = [
        output
        for output in residual
        if _script_id(output) in coordinator_scripts
    ]
    if len(script_matches) == 1:
        return (
            script_matches[0],
            "discounted_fee_script_reuse",
            Confidence.MEDIUM,
        )
    standard = detection.pool.coordinator_fee_sats
    amount_matches = [
        output for output in residual if output.value_sats < standard
    ]
    if (
        len(amount_matches) == 1
        and all(
            output is amount_matches[0] or output.value_sats > standard
            for output in residual
        )
    ):
        return (
            amount_matches[0],
            "discounted_fee_amount",
            Confidence.MEDIUM,
        )
    return None, None, Confidence.LOW


def _script_id(output: TxOutput) -> str:
    return hashlib.sha256(output.script_pubkey).hexdigest()


def _percentage_text(numerator: int, denominator: int) -> str:
    from decimal import ROUND_HALF_UP, Decimal

    if numerator < 0 or denominator <= 0:
        raise ChainIndexError("Tx0 fee percentage values were invalid.")
    value = (
        Decimal(numerator) * Decimal(100) / Decimal(denominator)
    ).quantize(Decimal("0.0001"), rounding=ROUND_HALF_UP)
    return format(value, ".4f")
