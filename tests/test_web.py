from __future__ import annotations

import inspect
import re
import sqlite3
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from dewhirlpooler.blocksource import CoreBlock
from dewhirlpooler.cache import CacheError, CacheSettings, TraceCache
from dewhirlpooler.chainindex import ChainIndex, ChainIndexSettings
from dewhirlpooler.trace import (
    TraceLimits,
    TraceReport,
    TraceSummary,
    TraceTransaction,
)
from dewhirlpooler.web import create_app
from dewhirlpooler.whirlpool import Confidence, TransactionKind

TXID = "A" * 64
NORMALIZED_TXID = TXID.lower()
SAFE_DETAIL = (
    "Could not complete the trace from your node. "
    "Check the node connection and try again."
)
STATIC_DIRECTORY = (
    Path(__file__).parents[1] / "src" / "dewhirlpooler" / "static"
)
CACHE_ENVIRONMENT_VARIABLES = (
    "DEWHIRLPOOLER_CACHE_PATH",
    "DEWHIRLPOOLER_CACHE_TTL_SECONDS",
    "DEWHIRLPOOLER_CACHE_MAX_ENTRIES",
)
CHAIN_ENVIRONMENT_VARIABLES = (
    "DEWHIRLPOOLER_CHAIN_DB",
    "DEWHIRLPOOLER_CHAIN_START_HEIGHT",
    "DEWHIRLPOOLER_CHAIN_BUSY_TIMEOUT_MS",
)
NETWORK_UNAVAILABLE_DETAIL = (
    "Pool history is not available yet. "
    "The transaction tracer is still ready."
)


@pytest.fixture(autouse=True)
def disable_environment_cache(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    for name in CACHE_ENVIRONMENT_VARIABLES + CHAIN_ENVIRONMENT_VARIABLES:
        monkeypatch.delenv(name, raising=False)


class FakeTraceService:
    def __init__(
        self,
        report: TraceReport | None = None,
        error: Exception | None = None,
    ) -> None:
        self.report = report or _report()
        self.error = error
        self.calls: list[tuple[str, TraceLimits]] = []

    def __call__(self, txid: str, limits: TraceLimits) -> TraceReport:
        self.calls.append((txid, limits))
        if self.error is not None:
            raise self.error
        return self.report


class FakeNetworkService:
    def __init__(
        self,
        *,
        error: Exception | None = None,
    ) -> None:
        self.error = error
        self.overview_calls = 0
        self.history_calls: list[
            tuple[str, int | None, int | None, int]
        ] = []

    def overview(self) -> dict[str, object]:
        self.overview_calls += 1
        if self.error is not None:
            raise self.error
        return _network_overview()

    def history(
        self,
        pool_id: str,
        *,
        start_height: int | None,
        end_height: int | None,
        limit: int,
    ) -> dict[str, object]:
        self.history_calls.append(
            (pool_id, start_height, end_height, limit)
        )
        if self.error is not None:
            raise self.error
        if pool_id != "ashigaru-0.025":
            raise ValueError("private unsupported pool detail")
        return {
            "pool_id": pool_id,
            "snapshots": _network_overview()["pools"],
        }


def _network_overview() -> dict[str, object]:
    return {
        "coverage": {
            "start_height": 571_000,
            "last_height": 571_621,
            "blocks_indexed": 622,
        },
        "coordinator": {
            "gross_revenue_sats": 125_000,
            "known_mining_cost_sats": 539,
            "net_known_profit_sats": 124_461,
            "minimum_coordinator_mining_cost_sats": 539,
            "maximum_coordinator_mining_cost_sats": 739,
            "net_profit_lower_bound_sats": 124_261,
            "net_profit_upper_bound_sats": 124_461,
            "fee_output_count": 1,
            "ambiguous_spend_count": 1,
            "ambiguous_input_sats": 25_000,
        },
        "pools": [
            {
                "height": 571_621,
                "pool_id": "ashigaru-0.025",
                "liquidity_sats": 22_500_000,
                "utxo_count": 9,
                "entry_sats": 22_500_000,
                "exit_sats": 0,
                "tx0_count": 1,
                "round_count": 0,
            }
        ],
    }


def _report() -> TraceReport:
    return TraceReport(
        root_txid=NORMALIZED_TXID,
        nodes=(),
        edges=(),
        findings=(),
        summary=TraceSummary(
            transactions_examined=1,
            outputs_examined=0,
            whirlpool_rounds=0,
            later_tx0s=0,
            postmix_consolidations=0,
            possible_payments=0,
            unspent_output_count=0,
            unspent_sats=0,
        ),
        warnings=(),
        truncated=False,
        transactions=(
            TraceTransaction(
                txid=NORMALIZED_TXID,
                kind=TransactionKind.TX0,
                confidence=Confidence.HIGH,
                pool="ashigaru-0.025",
                input_count=2,
                input_value_sats=25_121_000,
                miner_fee_sats=15_000,
                coordinator_fee_sats=125_000,
                premix_output_count=9,
                entered_pool_sats=22_500_000,
                total_fee_cost_sats=140_000,
                fee_cost_percent="0.6222",
                round_size=None,
                premix_input_count=0,
                remix_input_count=0,
                new_entrant_ratio=None,
                remixer_ratio=None,
                doxxic_change_enters_later_tx0=True,
            ),
        ),
    )


def _request(**overrides: object) -> dict[str, object]:
    request: dict[str, object] = {
        "txid": TXID,
        "max_depth": 8,
        "max_transactions": 100,
        "max_outputs": 250,
        "max_history_lookups": 250,
    }
    request.update(overrides)
    return request


def _cache(path: Path) -> TraceCache:
    return TraceCache(
        CacheSettings(
            path=path,
            ttl_seconds=900,
            max_entries=256,
        )
    )


class LookupFailureCache:
    def get(
        self,
        txid: str,
        limits: TraceLimits,
    ) -> dict[str, object] | None:
        raise CacheError("private cache lookup failure")

    def put(
        self,
        txid: str,
        limits: TraceLimits,
        report: dict[str, object],
    ) -> None:
        raise AssertionError("storage must be bypassed after lookup failure")


class StorageFailureCache:
    def get(
        self,
        txid: str,
        limits: TraceLimits,
    ) -> dict[str, object] | None:
        return None

    def put(
        self,
        txid: str,
        limits: TraceLimits,
        report: dict[str, object],
    ) -> None:
        raise CacheError("private cache storage failure")


def test_create_app_does_not_evaluate_default_node_configuration(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fail_if_called() -> None:
        raise AssertionError("node configuration was evaluated")

    monkeypatch.setattr(
        "dewhirlpooler.web.FulcrumSettings.from_env",
        fail_if_called,
    )

    app = create_app()

    assert app.title == "DeWhirlpooler"


def test_trace_route_uses_fastapi_sync_worker_path() -> None:
    app = create_app(FakeTraceService())
    trace_route = next(
        route
        for route in app.routes
        if getattr(route, "path", None) == "/api/trace"
    )

    assert not inspect.iscoroutinefunction(trace_route.endpoint)


def test_index_returns_packaged_html_with_only_local_assets() -> None:
    service = FakeTraceService()
    client = TestClient(create_app(service))

    response = client.get("/")

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/html")
    references = re.findall(
        r"""(?:src|href)=["']([^"']+)["']""",
        response.text,
    )
    assert references
    assert all(reference.startswith("/static/") for reference in references)
    assert service.calls == []


def test_health_is_process_only_and_does_not_invoke_trace() -> None:
    service = FakeTraceService(error=AssertionError("trace invoked"))
    client = TestClient(create_app(service))

    response = client.get("/health")

    assert response.status_code == 200
    assert response.json() == {"status": "ok"}
    assert service.calls == []


def test_create_app_does_not_open_chain_index(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fail_if_called(*args: object, **kwargs: object) -> None:
        raise AssertionError("chain index opened")

    monkeypatch.setattr(
        "dewhirlpooler.web.ChainIndexReader",
        fail_if_called,
    )

    create_app(FakeTraceService())


def test_network_overview_returns_exact_injected_result() -> None:
    network = FakeNetworkService()
    client = TestClient(
        create_app(FakeTraceService(), network_service=network)
    )

    response = client.get("/api/network")

    assert response.status_code == 200
    assert response.json() == _network_overview()
    assert network.overview_calls == 1


def test_network_history_passes_validated_bounds() -> None:
    network = FakeNetworkService()
    client = TestClient(
        create_app(FakeTraceService(), network_service=network)
    )

    response = client.get(
        "/api/network/pools/ashigaru-0.025/history"
        "?start_height=571000&end_height=571621&limit=12"
    )

    assert response.status_code == 200
    assert response.json() == {
        "pool_id": "ashigaru-0.025",
        "snapshots": _network_overview()["pools"],
    }
    assert network.history_calls == [
        ("ashigaru-0.025", 571_000, 571_621, 12)
    ]


@pytest.mark.parametrize(
    "query",
    [
        "?start_height=-1",
        "?end_height=-1",
        "?limit=0",
        "?limit=2001",
        "?limit=1.5",
        "?start_height=true",
        "?start_height=10&end_height=9",
    ],
)
def test_network_history_rejects_invalid_query_without_service_call(
    query: str,
) -> None:
    network = FakeNetworkService()
    client = TestClient(
        create_app(FakeTraceService(), network_service=network)
    )

    response = client.get(
        f"/api/network/pools/ashigaru-0.025/history{query}"
    )

    assert response.status_code == 422
    assert network.history_calls == []


def test_network_history_unknown_pool_is_safe_404() -> None:
    network = FakeNetworkService()
    client = TestClient(
        create_app(FakeTraceService(), network_service=network)
    )

    response = client.get("/api/network/pools/private-pool/history")

    assert response.status_code == 404
    assert response.json() == {
        "detail": "That Whirlpool pool is not available in this index."
    }
    assert "private unsupported" not in response.text


def test_network_failure_is_safe_and_trace_stays_ready() -> None:
    private_error = RuntimeError(
        "database /private/index.sqlite3 at 192.168.0.134 failed"
    )
    network = FakeNetworkService(error=private_error)
    service = FakeTraceService()
    client = TestClient(
        create_app(service, network_service=network)
    )

    overview = client.get("/api/network")
    history = client.get(
        "/api/network/pools/ashigaru-0.025/history"
    )
    trace = client.post("/api/trace", json=_request())

    assert overview.status_code == 503
    assert history.status_code == 503
    assert overview.json() == {"detail": NETWORK_UNAVAILABLE_DETAIL}
    assert history.json() == {"detail": NETWORK_UNAVAILABLE_DETAIL}
    assert "/private/" not in overview.text
    assert "192.168." not in history.text
    assert trace.status_code == 200
    assert len(service.calls) == 1


def test_default_network_service_reads_existing_index(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    path = tmp_path / "chain.sqlite3"
    with ChainIndex(
        ChainIndexSettings(path=path, start_height=550_000)
    ) as index:
        index.apply_block(
            CoreBlock(
                height=550_000,
                block_hash="1" * 64,
                previous_block_hash=None,
                block_time=1_700_000_000,
                transactions=(),
            )
        )
    monkeypatch.setenv("DEWHIRLPOOLER_CHAIN_DB", str(path))
    client = TestClient(create_app(FakeTraceService()))

    response = client.get("/api/network")

    assert response.status_code == 200
    body = response.json()
    assert body["coverage"] == {
        "start_height": 550_000,
        "last_height": 550_000,
        "blocks_indexed": 1,
    }
    assert body["coordinator"]["gross_revenue_sats"] == 0
    assert len(body["pools"]) == 6


def test_default_network_service_reports_mixed_input_profit_bounds(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    path = tmp_path / "chain.sqlite3"
    with ChainIndex(
        ChainIndexSettings(path=path, start_height=550_000)
    ) as index:
        index.apply_block(
            CoreBlock(
                height=550_000,
                block_hash="1" * 64,
                previous_block_hash=None,
                block_time=1_700_000_000,
                transactions=(),
            )
        )
    connection = sqlite3.connect(path)
    connection.execute("PRAGMA foreign_keys = ON")
    connection.execute(
        """
        INSERT INTO coordinator_fee_utxos VALUES (
            ?, 0, 'ashigaru-0.025', 125000, 'script', 'high',
            'current_fixed_fee', 550000, 550000, ?
        )
        """,
        ("a" * 64, "b" * 64),
    )
    connection.execute(
        """
        INSERT INTO coordinator_spends VALUES (
            ?, 550000, 125000, 225000, 130000, 0, 0
        )
        """,
        ("b" * 64,),
    )
    connection.commit()
    connection.close()
    monkeypatch.setenv("DEWHIRLPOOLER_CHAIN_DB", str(path))

    response = TestClient(create_app(FakeTraceService())).get("/api/network")

    assert response.status_code == 200
    assert response.json()["coordinator"] == {
        "gross_revenue_sats": 125_000,
        "known_mining_cost_sats": 0,
        "net_known_profit_sats": 125_000,
        "minimum_coordinator_mining_cost_sats": 30_000,
        "maximum_coordinator_mining_cost_sats": 130_000,
        "net_profit_lower_bound_sats": -5_000,
        "net_profit_upper_bound_sats": 95_000,
        "fee_output_count": 1,
        "ambiguous_spend_count": 1,
        "ambiguous_input_sats": 125_000,
    }


def test_default_network_service_missing_or_corrupt_database_is_safe(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    private_path = tmp_path / "private-node-index.sqlite3"
    monkeypatch.setenv(
        "DEWHIRLPOOLER_CHAIN_DB",
        str(private_path),
    )
    client = TestClient(create_app(FakeTraceService()))

    missing = client.get("/api/network")
    private_path.write_bytes(b"not a sqlite database")
    corrupt = client.get("/api/network")

    assert missing.status_code == 503
    assert corrupt.status_code == 503
    assert missing.json() == {"detail": NETWORK_UNAVAILABLE_DETAIL}
    assert corrupt.json() == {"detail": NETWORK_UNAVAILABLE_DETAIL}
    assert str(private_path) not in missing.text
    assert str(private_path) not in corrupt.text


def test_valid_trace_passes_exact_limits_and_returns_report() -> None:
    report = _report()
    service = FakeTraceService(report)
    client = TestClient(create_app(service))

    response = client.post(
        "/api/trace",
        json=_request(
            max_depth=12,
            max_transactions=500,
            max_outputs=2_000,
            max_history_lookups=2_000,
        ),
    )

    assert response.status_code == 200
    assert response.json() == report.to_dict()
    assert response.headers["X-DeWhirlpooler-Cache"] == "BYPASS"
    assert service.calls == [
        (
            NORMALIZED_TXID,
            TraceLimits(
                max_depth=12,
                max_transactions=500,
                max_outputs=2_000,
                max_history_lookups=2_000,
            ),
        )
    ]


def test_trace_normalizes_txid_to_lowercase() -> None:
    service = FakeTraceService()
    client = TestClient(create_app(service))

    response = client.post("/api/trace", json=_request())

    assert response.status_code == 200
    assert service.calls[0][0] == NORMALIZED_TXID


@pytest.mark.parametrize(
    "txid",
    [
        "",
        "a" * 63,
        "a" * 65,
        "g" * 64,
        " " + "a" * 63,
        123,
        None,
    ],
)
def test_malformed_txid_returns_422_without_invoking_service(
    txid: object,
) -> None:
    service = FakeTraceService()
    client = TestClient(create_app(service))

    response = client.post("/api/trace", json=_request(txid=txid))

    assert response.status_code == 422
    assert service.calls == []


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("max_depth", 0),
        ("max_depth", 13),
        ("max_transactions", 0),
        ("max_transactions", 501),
        ("max_outputs", 0),
        ("max_outputs", 2_001),
        ("max_history_lookups", 0),
        ("max_history_lookups", 2_001),
        ("max_depth", 1.5),
        ("max_transactions", "100"),
        ("max_outputs", True),
    ],
)
def test_out_of_range_limit_returns_422_without_invoking_service(
    field: str,
    value: object,
) -> None:
    service = FakeTraceService()
    client = TestClient(create_app(service))

    response = client.post("/api/trace", json=_request(**{field: value}))

    assert response.status_code == 422
    assert service.calls == []


def test_service_exception_returns_fixed_safe_502_without_leak() -> None:
    private_message = (
        "secret failure from host 10.23.45.67:50001 "
        "with deadbeef raw transaction data"
    )
    service = FakeTraceService(error=RuntimeError(private_message))
    client = TestClient(create_app(service))

    response = client.post("/api/trace", json=_request())

    assert response.status_code == 502
    assert response.json() == {"detail": SAFE_DETAIL}
    assert private_message not in response.text
    assert "10.23.45.67" not in response.text
    assert "deadbeef" not in response.text


def test_first_success_is_miss_then_hit_and_service_runs_once(
    tmp_path: Path,
) -> None:
    report = _report()
    service = FakeTraceService(report)
    client = TestClient(
        create_app(
            service,
            trace_cache=_cache(tmp_path / "reports.sqlite3"),
        )
    )

    first = client.post("/api/trace", json=_request())
    second = client.post("/api/trace", json=_request())

    assert first.status_code == 200
    assert first.headers["X-DeWhirlpooler-Cache"] == "MISS"
    assert second.status_code == 200
    assert second.headers["X-DeWhirlpooler-Cache"] == "HIT"
    assert first.json() == report.to_dict()
    assert second.json() == report.to_dict()
    assert first.content == second.content
    assert len(service.calls) == 1


def test_different_limits_produce_independent_misses(
    tmp_path: Path,
) -> None:
    service = FakeTraceService()
    client = TestClient(
        create_app(
            service,
            trace_cache=_cache(tmp_path / "reports.sqlite3"),
        )
    )

    first = client.post(
        "/api/trace",
        json=_request(max_depth=2),
    )
    second = client.post(
        "/api/trace",
        json=_request(max_depth=3),
    )

    assert first.headers["X-DeWhirlpooler-Cache"] == "MISS"
    assert second.headers["X-DeWhirlpooler-Cache"] == "MISS"
    assert len(service.calls) == 2


def test_trace_failures_are_not_cached(tmp_path: Path) -> None:
    service = FakeTraceService(error=RuntimeError("private node failure"))
    client = TestClient(
        create_app(
            service,
            trace_cache=_cache(tmp_path / "reports.sqlite3"),
        )
    )

    first = client.post("/api/trace", json=_request())
    second = client.post("/api/trace", json=_request())

    assert first.status_code == 502
    assert second.status_code == 502
    assert len(service.calls) == 2


def test_cache_lookup_failure_returns_live_result_with_bypass() -> None:
    service = FakeTraceService()
    client = TestClient(
        create_app(
            service,
            trace_cache=LookupFailureCache(),  # type: ignore[arg-type]
        )
    )

    response = client.post("/api/trace", json=_request())

    assert response.status_code == 200
    assert response.json() == service.report.to_dict()
    assert response.headers["X-DeWhirlpooler-Cache"] == "BYPASS"
    assert len(service.calls) == 1


def test_cache_storage_failure_returns_live_result_with_bypass() -> None:
    service = FakeTraceService()
    client = TestClient(
        create_app(
            service,
            trace_cache=StorageFailureCache(),  # type: ignore[arg-type]
        )
    )

    response = client.post("/api/trace", json=_request())

    assert response.status_code == 200
    assert response.json() == service.report.to_dict()
    assert response.headers["X-DeWhirlpooler-Cache"] == "BYPASS"
    assert len(service.calls) == 1


def test_environment_cache_initialization_failure_is_bypassed(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    service = FakeTraceService()
    monkeypatch.setenv(
        "DEWHIRLPOOLER_CACHE_PATH",
        str(tmp_path / "reports.sqlite3"),
    )

    def fail_initialization(settings: CacheSettings) -> TraceCache:
        raise CacheError("private cache initialization failure")

    monkeypatch.setattr(
        "dewhirlpooler.web.TraceCache",
        fail_initialization,
    )

    client = TestClient(create_app(service))
    response = client.post("/api/trace", json=_request())

    assert response.status_code == 200
    assert response.json() == service.report.to_dict()
    assert response.headers["X-DeWhirlpooler-Cache"] == "BYPASS"
    assert len(service.calls) == 1


@pytest.mark.parametrize(
    "path",
    [
        "/static/app.css",
        "/static/app.js",
        "/static/vendor/cytoscape.min.js",
        "/static/vendor/CYTOSCAPE-LICENSE",
    ],
)
def test_static_assets_are_served(path: str) -> None:
    client = TestClient(create_app(FakeTraceService()))

    response = client.get(path)

    assert response.status_code == 200
    assert response.content


def test_html_contains_required_regions_and_accessible_live_status() -> None:
    client = TestClient(create_app(FakeTraceService()))

    html = client.get("/").text

    for required_text in (
        "Pool history",
        "Totals cover indexed blocks only.",
        "Latest pool liquidity",
        "Recent blocks",
        "Transaction ID",
        "Analyze transaction",
        "Exposure summary",
        "What stands out",
        "Transaction trail",
        "Details",
        "Solid lines are observed spends.",
    ):
        assert required_text in html
    for required_id in (
        'id="network-status"',
        'id="network-summary"',
        'id="pool-list"',
        'id="pool-history-table"',
        'id="txid"',
        'id="analyze-button"',
        'id="summary-grid"',
        'id="findings-list"',
        'id="transaction-graph"',
        'id="detail-panel"',
        'id="interpretation"',
    ):
        assert required_id in html
    assert html.count('aria-live="') >= 1
    assert (
        "18c999772ed82bf7753bdce9021cfa68b505de36344ce81f77d0c436b7135892"
        in html
    )


def test_authored_static_source_has_no_private_or_remote_asset_reference() -> None:
    content = "\n".join(
        (STATIC_DIRECTORY / name).read_text(encoding="utf-8")
        for name in ("index.html", "app.css", "app.js")
    ).lower()

    assert "192.168." not in content
    assert "10.23.45." not in content
    assert "cdn." not in content
    assert "analytics" not in content
    assert "telemetry" not in content
    assert "http://" not in content
    assert "https://" not in content
    assert "//" not in "\n".join(
        line
        for line in content.splitlines()
        if "font-family" not in line
    )


def test_browser_source_presents_phase_six_metrics_and_heuristic_warning() -> None:
    script = (STATIC_DIRECTORY / "app.js").read_text(encoding="utf-8")

    for required_text in (
        "Tx0 miner fee",
        "Total Tx0 fee cost",
        "Inputs grouped by this transaction",
        "common-input-ownership",
        "evidence, not proof",
        "Round size",
        "New entrants",
        "Remixers",
        "Change entered another Tx0",
        "Stonewall candidates",
        "Ricochet candidates",
        "Possible Stonewall / StonewallX2",
        "Possible Ricochet",
        "Possible Payjoin / Cahoots fingerprint leak",
        "Unnecessary-input clue:",
        "Input fingerprint differences:",
        "Observable input groups:",
        "Previous-output script type",
        "Input sequence",
        "ECDSA signature R length",
        "ECDSA sighash",
        "Taproot sighash form",
        "Consistent with Payjoin/Cahoots, not proof",
        "observable groups are not proven owners",
        "Repeated output amount",
        "Ricochet service fee",
        "Ricochet fee address",
        "Four observed hops",
        "Cross-role address reuse",
        "Address reused across Whirlpool roles",
        "Whirlpool CPFP candidates",
        "Possible Whirlpool CPFP",
        "Parent round:",
        "Same confirmation block:",
        "Fee rates (parent / child / package):",
        "Address:",
        "Roles:",
        "Coordinator fee",
        "Tx0 premix",
        "Whirlpool output",
        "Stonewall equal output",
        "within these limits",
        "Gross coordinator fees",
        "Known consolidation costs",
        "Coordinator mining cost range",
        "Net profit range",
        "possible mixed-input cost",
        "Ambiguous fee spends",
        "Indexed blocks",
        "Recent blocks for this pool are not available yet.",
        "/api/network",
        "limit=12",
    ):
        assert required_text in script
    assert "innerHTML" not in script


def test_pool_history_table_is_contained_on_narrow_viewports() -> None:
    styles = (STATIC_DIRECTORY / "app.css").read_text(encoding="utf-8")

    assert ".pool-history-layout > section {\n  min-width: 0;\n}" in styles
    assert ".pool-table-wrap {" in styles
    assert "overflow-x: auto;" in styles
    assert "#pool-history-table {" in styles
    assert "min-width: 680px;" in styles


def test_cytoscape_distribution_and_mit_license_are_bundled() -> None:
    script = (
        STATIC_DIRECTORY / "vendor" / "cytoscape.min.js"
    ).read_text(encoding="utf-8")
    license_text = (
        STATIC_DIRECTORY / "vendor" / "CYTOSCAPE-LICENSE"
    ).read_text(encoding="utf-8")

    assert "The Cytoscape Consortium" in script
    assert "THE SOFTWARE IS PROVIDED “AS IS”" in license_text
