"""Optional bounded SQLite cache for completed exposure reports."""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import time
from collections.abc import Callable, Mapping
from contextlib import closing
from dataclasses import dataclass
from pathlib import Path

from .trace import TraceLimits

TRACE_CACHE_VERSION = 6

_DEFAULT_TTL_SECONDS = 900
_DEFAULT_MAX_ENTRIES = 256
_MIN_TTL_SECONDS = 1
_MAX_TTL_SECONDS = 86_400
_MIN_MAX_ENTRIES = 1
_MAX_MAX_ENTRIES = 10_000

_SCHEMA = """
CREATE TABLE IF NOT EXISTS trace_reports (
    cache_key TEXT PRIMARY KEY,
    created_at INTEGER NOT NULL,
    report_json TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS trace_reports_created_at
ON trace_reports(created_at);
"""


@dataclass(frozen=True, slots=True)
class CacheSettings:
    """Validated report-cache configuration."""

    path: Path | None
    ttl_seconds: int
    max_entries: int

    @classmethod
    def from_env(
        cls,
        env: Mapping[str, str] | None = None,
    ) -> CacheSettings:
        """Load cache settings without reading node connection settings."""

        values = os.environ if env is None else env
        raw_path = values.get("DEWHIRLPOOLER_CACHE_PATH", "")
        if not isinstance(raw_path, str):
            raise ValueError(
                "DEWHIRLPOOLER_CACHE_PATH must be a valid file path."
            )

        try:
            path = (
                None
                if not raw_path.strip()
                else Path(raw_path.strip()).expanduser()
            )
        except (OSError, RuntimeError, TypeError):
            raise ValueError(
                "DEWHIRLPOOLER_CACHE_PATH must be a valid file path."
            ) from None

        ttl_seconds = _read_bounded_integer(
            values,
            "DEWHIRLPOOLER_CACHE_TTL_SECONDS",
            default=_DEFAULT_TTL_SECONDS,
            minimum=_MIN_TTL_SECONDS,
            maximum=_MAX_TTL_SECONDS,
        )
        max_entries = _read_bounded_integer(
            values,
            "DEWHIRLPOOLER_CACHE_MAX_ENTRIES",
            default=_DEFAULT_MAX_ENTRIES,
            minimum=_MIN_MAX_ENTRIES,
            maximum=_MAX_MAX_ENTRIES,
        )
        return cls(
            path=path,
            ttl_seconds=ttl_seconds,
            max_entries=max_entries,
        )


class CacheError(RuntimeError):
    """A safe cache failure that callers may bypass."""


class TraceCache:
    """Persistent cache of successful, JSON-ready trace reports."""

    def __init__(
        self,
        settings: CacheSettings,
        *,
        clock: Callable[[], float] = time.time,
    ) -> None:
        if settings.path is None:
            raise ValueError("Trace cache requires an enabled cache path.")

        self._settings = settings
        self._path = settings.path
        self._clock = clock

        try:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            with closing(self._connect()) as connection:
                connection.executescript(_SCHEMA)
                connection.commit()
        except (OSError, sqlite3.Error):
            raise CacheError(
                "Could not initialize the report cache."
            ) from None

    def get(
        self,
        txid: str,
        limits: TraceLimits,
    ) -> dict[str, object] | None:
        """Return a detached, unexpired report or ``None`` on a miss."""

        cache_key = _make_cache_key(txid, limits)
        now = int(self._clock())

        try:
            with closing(self._connect()) as connection:
                row = connection.execute(
                    """
                    SELECT created_at, report_json
                    FROM trace_reports
                    WHERE cache_key = ?
                    """,
                    (cache_key,),
                ).fetchone()
                if row is None:
                    return None

                try:
                    created_at = int(row[0])
                    report = json.loads(
                        row[1],
                        parse_constant=_reject_json_constant,
                    )
                except (TypeError, ValueError):
                    self._delete(connection, cache_key)
                    return None

                if now - created_at >= self._settings.ttl_seconds:
                    self._delete(connection, cache_key)
                    return None
                if not isinstance(report, dict):
                    self._delete(connection, cache_key)
                    return None
                return report
        except (OSError, sqlite3.Error):
            raise CacheError("Could not read the report cache.") from None

    def put(
        self,
        txid: str,
        limits: TraceLimits,
        report: Mapping[str, object],
    ) -> None:
        """Store a successful report and prune expired or oldest rows."""

        cache_key = _make_cache_key(txid, limits)
        created_at = int(self._clock())
        try:
            report_json = json.dumps(
                dict(report),
                allow_nan=False,
                ensure_ascii=False,
                separators=(",", ":"),
            )
        except (TypeError, ValueError):
            raise CacheError("Could not update the report cache.") from None

        try:
            with closing(self._connect()) as connection:
                with connection:
                    connection.execute(
                        """
                        INSERT OR REPLACE INTO trace_reports (
                            cache_key,
                            created_at,
                            report_json
                        )
                        VALUES (?, ?, ?)
                        """,
                        (cache_key, created_at, report_json),
                    )
                    connection.execute(
                        """
                        DELETE FROM trace_reports
                        WHERE created_at <= ?
                        """,
                        (
                            created_at - self._settings.ttl_seconds,
                        ),
                    )
                    row_count = connection.execute(
                        "SELECT COUNT(*) FROM trace_reports"
                    ).fetchone()[0]
                    excess = row_count - self._settings.max_entries
                    if excess > 0:
                        connection.execute(
                            """
                            DELETE FROM trace_reports
                            WHERE cache_key IN (
                                SELECT cache_key
                                FROM trace_reports
                                ORDER BY created_at ASC, cache_key ASC
                                LIMIT ?
                            )
                            """,
                            (excess,),
                        )
        except (OSError, sqlite3.Error):
            raise CacheError("Could not update the report cache.") from None

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(
            self._path,
            timeout=5.0,
        )
        try:
            connection.execute("PRAGMA busy_timeout = 5000")
            connection.execute("PRAGMA journal_mode = WAL")
        except sqlite3.Error:
            connection.close()
            raise
        return connection

    @staticmethod
    def _delete(
        connection: sqlite3.Connection,
        cache_key: str,
    ) -> None:
        with connection:
            connection.execute(
                "DELETE FROM trace_reports WHERE cache_key = ?",
                (cache_key,),
            )


def _read_bounded_integer(
    env: Mapping[str, str],
    name: str,
    *,
    default: int,
    minimum: int,
    maximum: int,
) -> int:
    raw_value = env.get(name)
    if raw_value is None:
        return default
    if not isinstance(raw_value, str):
        raise ValueError(f"{name} must be an integer.")
    try:
        value = int(raw_value)
    except ValueError:
        raise ValueError(f"{name} must be an integer.") from None
    if not minimum <= value <= maximum:
        raise ValueError(f"{name} is outside the allowed range.")
    return value


def _make_cache_key(txid: str, limits: TraceLimits) -> str:
    key_payload = {
        "max_depth": limits.max_depth,
        "max_history_lookups": limits.max_history_lookups,
        "max_outputs": limits.max_outputs,
        "max_transactions": limits.max_transactions,
        "trace_cache_version": TRACE_CACHE_VERSION,
        "txid": txid.lower(),
    }
    canonical_json = json.dumps(
        key_payload,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    )
    return hashlib.sha256(canonical_json.encode("utf-8")).hexdigest()


def _reject_json_constant(_: str) -> None:
    raise ValueError("Non-finite JSON values are not cacheable.")
