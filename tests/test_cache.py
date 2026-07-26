from __future__ import annotations

import hashlib
import json
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

from dewhirlpooler.cache import (
    TRACE_CACHE_VERSION,
    CacheError,
    CacheSettings,
    TraceCache,
)
from dewhirlpooler.trace import TraceLimits

TXID = "a" * 64
OTHER_TXID = "b" * 64


class MutableClock:
    def __init__(self, now: float) -> None:
        self.now = now

    def __call__(self) -> float:
        return self.now


def _settings(
    path: Path,
    *,
    ttl_seconds: int = 900,
    max_entries: int = 256,
) -> CacheSettings:
    return CacheSettings(
        path=path,
        ttl_seconds=ttl_seconds,
        max_entries=max_entries,
    )


def _report(txid: str = TXID) -> dict[str, object]:
    return {
        "root_txid": txid,
        "nodes": [],
        "warnings": [],
        "truncated": False,
    }


def _row_count(path: Path) -> int:
    with sqlite3.connect(path) as connection:
        return connection.execute(
            "SELECT COUNT(*) FROM trace_reports"
        ).fetchone()[0]


def test_settings_defaults_disable_cache() -> None:
    settings = CacheSettings.from_env({})

    assert settings == CacheSettings(
        path=None,
        ttl_seconds=900,
        max_entries=256,
    )


def test_settings_load_explicit_values_and_expand_home(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))

    settings = CacheSettings.from_env(
        {
            "DEWHIRLPOOLER_CACHE_PATH": "~/data/reports.sqlite3",
            "DEWHIRLPOOLER_CACHE_TTL_SECONDS": "60",
            "DEWHIRLPOOLER_CACHE_MAX_ENTRIES": "12",
        }
    )

    assert settings == CacheSettings(
        path=tmp_path / "data" / "reports.sqlite3",
        ttl_seconds=60,
        max_entries=12,
    )


@pytest.mark.parametrize(
    ("name", "value"),
    [
        ("DEWHIRLPOOLER_CACHE_TTL_SECONDS", "not-an-integer"),
        ("DEWHIRLPOOLER_CACHE_TTL_SECONDS", "0"),
        ("DEWHIRLPOOLER_CACHE_TTL_SECONDS", "86401"),
        ("DEWHIRLPOOLER_CACHE_MAX_ENTRIES", "not-an-integer"),
        ("DEWHIRLPOOLER_CACHE_MAX_ENTRIES", "0"),
        ("DEWHIRLPOOLER_CACHE_MAX_ENTRIES", "10001"),
    ],
)
def test_invalid_numeric_settings_name_variable_without_echoing_value(
    name: str,
    value: str,
) -> None:
    with pytest.raises(ValueError) as raised:
        CacheSettings.from_env({name: value})

    message = str(raised.value)
    assert name in message
    assert value not in message


def test_disabled_settings_are_rejected() -> None:
    with pytest.raises(ValueError, match="enabled cache path"):
        TraceCache(CacheSettings(None, 900, 256))


def test_initialization_error_does_not_echo_path(
    tmp_path: Path,
) -> None:
    parent_file = tmp_path / "private-cache-location"
    parent_file.write_text("not a directory", encoding="utf-8")
    cache_path = parent_file / "reports.sqlite3"

    with pytest.raises(CacheError) as raised:
        TraceCache(_settings(cache_path))

    assert str(cache_path) not in str(raised.value)
    assert "Not a directory" not in str(raised.value)


def test_same_txid_and_limits_hit_but_different_limits_miss(
    tmp_path: Path,
) -> None:
    cache = TraceCache(_settings(tmp_path / "reports.sqlite3"))
    limits = TraceLimits()
    report = _report()

    cache.put(TXID.upper(), limits, report)

    assert cache.get(TXID, limits) == report
    assert cache.get(TXID, TraceLimits(max_depth=5)) is None
    assert cache.get(OTHER_TXID, limits) is None


def test_get_returns_detached_dictionary(tmp_path: Path) -> None:
    cache = TraceCache(_settings(tmp_path / "reports.sqlite3"))
    report = _report()
    cache.put(TXID, TraceLimits(), report)

    first = cache.get(TXID, TraceLimits())
    assert first is not None
    first["truncated"] = True

    assert cache.get(TXID, TraceLimits()) == report


def test_expired_row_is_deleted(tmp_path: Path) -> None:
    clock = MutableClock(1_000)
    path = tmp_path / "reports.sqlite3"
    cache = TraceCache(
        _settings(path, ttl_seconds=10),
        clock=clock,
    )
    cache.put(TXID, TraceLimits(), _report())

    clock.now = 1_010

    assert cache.get(TXID, TraceLimits()) is None
    assert _row_count(path) == 0


def test_cache_persists_across_instances(tmp_path: Path) -> None:
    path = tmp_path / "reports.sqlite3"
    first = TraceCache(_settings(path))
    first.put(TXID, TraceLimits(), _report())

    second = TraceCache(_settings(path))

    assert second.get(TXID, TraceLimits()) == _report()


def test_cache_version_six_does_not_return_version_five_report(
    tmp_path: Path,
) -> None:
    path = tmp_path / "reports.sqlite3"
    cache = TraceCache(_settings(path))
    limits = TraceLimits()
    old_payload = {
        "max_depth": limits.max_depth,
        "max_history_lookups": limits.max_history_lookups,
        "max_outputs": limits.max_outputs,
        "max_transactions": limits.max_transactions,
        "trace_cache_version": 5,
        "txid": TXID,
    }
    old_key = hashlib.sha256(
        json.dumps(
            old_payload,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    ).hexdigest()
    with sqlite3.connect(path) as connection:
        connection.execute(
            """
            INSERT INTO trace_reports (cache_key, created_at, report_json)
            VALUES (?, ?, ?)
            """,
            (old_key, 1, json.dumps(_report())),
        )

    assert TRACE_CACHE_VERSION == 6
    assert cache.get(TXID, limits) is None
    assert _row_count(path) == 1


@pytest.mark.parametrize(
    "bad_json",
    [
        "not json",
        "[]",
        "null",
        '"text"',
        '{"value": NaN}',
        b"\xff",
    ],
)
def test_malformed_or_non_object_json_self_heals(
    tmp_path: Path,
    bad_json: str | bytes,
) -> None:
    path = tmp_path / "reports.sqlite3"
    cache = TraceCache(_settings(path))
    cache.put(TXID, TraceLimits(), _report())
    with sqlite3.connect(path) as connection:
        connection.execute(
            "UPDATE trace_reports SET report_json = ?",
            (bad_json,),
        )

    assert cache.get(TXID, TraceLimits()) is None
    assert _row_count(path) == 0


def test_put_removes_expired_rows(tmp_path: Path) -> None:
    clock = MutableClock(100)
    path = tmp_path / "reports.sqlite3"
    cache = TraceCache(
        _settings(path, ttl_seconds=10),
        clock=clock,
    )
    cache.put(TXID, TraceLimits(), _report())
    clock.now = 111

    cache.put(OTHER_TXID, TraceLimits(), _report(OTHER_TXID))

    assert cache.get(TXID, TraceLimits()) is None
    assert cache.get(OTHER_TXID, TraceLimits()) == _report(OTHER_TXID)
    assert _row_count(path) == 1


def test_oldest_row_eviction_enforces_max_entries(
    tmp_path: Path,
) -> None:
    clock = MutableClock(100)
    path = tmp_path / "reports.sqlite3"
    cache = TraceCache(
        _settings(path, max_entries=2),
        clock=clock,
    )
    txids = ("a" * 64, "b" * 64, "c" * 64)
    for offset, txid in enumerate(txids):
        clock.now = 100 + offset
        cache.put(txid, TraceLimits(), _report(txid))

    assert cache.get(txids[0], TraceLimits()) is None
    assert cache.get(txids[1], TraceLimits()) == _report(txids[1])
    assert cache.get(txids[2], TraceLimits()) == _report(txids[2])
    assert _row_count(path) == 2


def test_concurrent_operations_use_thread_local_connections(
    tmp_path: Path,
) -> None:
    cache = TraceCache(
        _settings(
            tmp_path / "reports.sqlite3",
            max_entries=64,
        )
    )
    txids = [f"{index:064x}" for index in range(32)]

    def put_and_get(txid: str) -> dict[str, object] | None:
        report = _report(txid)
        cache.put(txid, TraceLimits(), report)
        return cache.get(txid, TraceLimits())

    with ThreadPoolExecutor(max_workers=8) as executor:
        results = list(executor.map(put_and_get, txids))

    assert results == [_report(txid) for txid in txids]


def test_schema_contains_only_report_fields_and_no_infrastructure(
    tmp_path: Path,
) -> None:
    path = tmp_path / "reports.sqlite3"
    TraceCache(_settings(path))

    with sqlite3.connect(path) as connection:
        columns = [
            row[1]
            for row in connection.execute(
                "PRAGMA table_info(trace_reports)"
            )
        ]
        schema = "\n".join(
            row[0]
            for row in connection.execute(
                """
                SELECT sql
                FROM sqlite_master
                WHERE tbl_name = 'trace_reports' AND sql IS NOT NULL
                """
            )
        ).lower()

    assert columns == ["cache_key", "created_at", "report_json"]
    for forbidden in (
        "fulcrum",
        "hostname",
        "node_port",
        "credential",
        "environment_value",
    ):
        assert forbidden not in schema
