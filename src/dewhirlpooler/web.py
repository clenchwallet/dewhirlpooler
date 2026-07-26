"""Local FastAPI application for the DeWhirlpooler exposure explorer."""

from __future__ import annotations

import os
import re
from collections.abc import Callable
from pathlib import Path
from typing import Annotated, Protocol

from fastapi import FastAPI, HTTPException, Query, Response
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, ConfigDict, Field, field_validator

from .cache import CacheError, CacheSettings, TraceCache
from .chainindex import (
    ChainIndexError,
    ChainIndexReader,
    ChainIndexSettings,
    CoordinatorSummary,
    PoolSnapshot,
)
from .config import FulcrumSettings
from .electrum import ElectrumClient
from .resolver import TransactionResolver
from .trace import ExposureTracer, TraceLimits, TraceReport

TraceService = Callable[[str, TraceLimits], TraceReport]

_STATIC_DIRECTORY = Path(__file__).resolve().parent / "static"
_SAFE_FAILURE_DETAIL = (
    "Could not complete the trace from your node. "
    "Check the node connection and try again."
)
_NETWORK_UNAVAILABLE_DETAIL = (
    "Pool history is not available yet. "
    "The transaction tracer is still ready."
)
_UNKNOWN_POOL_DETAIL = "That Whirlpool pool is not available in this index."
_TXID_PATTERN = re.compile(r"[0-9a-fA-F]{64}\Z")


class NetworkService(Protocol):
    """Synchronous read-only chain-history service."""

    def overview(self) -> dict[str, object]: ...

    def history(
        self,
        pool_id: str,
        *,
        start_height: int | None,
        end_height: int | None,
        limit: int,
    ) -> dict[str, object]: ...


class _TraceRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    txid: str
    max_depth: Annotated[int, Field(strict=True, ge=1, le=12)] = 8
    max_transactions: Annotated[
        int,
        Field(strict=True, ge=1, le=500),
    ] = 100
    max_outputs: Annotated[
        int,
        Field(strict=True, ge=1, le=2_000),
    ] = 250
    max_history_lookups: Annotated[
        int,
        Field(strict=True, ge=1, le=2_000),
    ] = 250

    @field_validator("txid")
    @classmethod
    def _normalize_txid(cls, value: str) -> str:
        if _TXID_PATTERN.fullmatch(value) is None:
            raise ValueError(
                "Transaction ID must be exactly 64 hexadecimal characters."
            )
        return value.lower()

    def trace_limits(self) -> TraceLimits:
        return TraceLimits(
            max_depth=self.max_depth,
            max_transactions=self.max_transactions,
            max_outputs=self.max_outputs,
            max_history_lookups=self.max_history_lookups,
        )


def _trace_with_configured_node(
    txid: str,
    limits: TraceLimits,
) -> TraceReport:
    settings = FulcrumSettings.from_env()
    resolver = TransactionResolver(ElectrumClient(settings))
    return ExposureTracer(resolver, limits).trace(txid)


class _ConfiguredNetworkService:
    """Open the explicitly configured derived index for each request."""

    def overview(self) -> dict[str, object]:
        with self._reader() as reader:
            status = reader.status()
            return {
                "coverage": {
                    "start_height": status.start_height,
                    "last_height": status.last_height,
                    "blocks_indexed": status.blocks_indexed,
                },
                "coordinator": _coordinator_dict(
                    reader.coordinator_summary()
                ),
                "pools": [
                    _snapshot_dict(snapshot)
                    for snapshot in reader.latest_pool_snapshots()
                ],
            }

    def history(
        self,
        pool_id: str,
        *,
        start_height: int | None,
        end_height: int | None,
        limit: int,
    ) -> dict[str, object]:
        with self._reader() as reader:
            snapshots = reader.pool_history(
                pool_id,
                start_height=start_height,
                end_height=end_height,
                limit=limit,
            )
        return {
            "pool_id": pool_id,
            "snapshots": [
                _snapshot_dict(snapshot) for snapshot in snapshots
            ],
        }

    @staticmethod
    def _reader() -> ChainIndexReader:
        if "DEWHIRLPOOLER_CHAIN_DB" not in os.environ:
            raise ChainIndexError(
                "The chain index database is not configured."
            )
        try:
            settings = ChainIndexSettings.from_env()
        except ValueError:
            raise ChainIndexError(
                "The chain index database is not configured."
            ) from None
        return ChainIndexReader(
            settings.path,
            busy_timeout_ms=settings.busy_timeout_ms,
        )


def _snapshot_dict(snapshot: PoolSnapshot) -> dict[str, object]:
    return {
        "height": snapshot.height,
        "pool_id": snapshot.pool_id,
        "liquidity_sats": snapshot.liquidity_sats,
        "utxo_count": snapshot.utxo_count,
        "entry_sats": snapshot.entry_sats,
        "exit_sats": snapshot.exit_sats,
        "tx0_count": snapshot.tx0_count,
        "round_count": snapshot.round_count,
    }


def _coordinator_dict(
    summary: CoordinatorSummary,
) -> dict[str, object]:
    return {
        "gross_revenue_sats": summary.gross_revenue_sats,
        "known_mining_cost_sats": summary.known_mining_cost_sats,
        "net_known_profit_sats": summary.net_known_profit_sats,
        "fee_output_count": summary.fee_output_count,
        "ambiguous_spend_count": summary.ambiguous_spend_count,
        "ambiguous_input_sats": summary.ambiguous_input_sats,
    }


def create_app(
    trace_service: TraceService | None = None,
    trace_cache: TraceCache | None = None,
    network_service: NetworkService | None = None,
) -> FastAPI:
    """Create the local web app without evaluating node configuration."""

    service = (
        _trace_with_configured_node
        if trace_service is None
        else trace_service
    )
    network = (
        _ConfiguredNetworkService()
        if network_service is None
        else network_service
    )
    cache = trace_cache
    if cache is None:
        cache_settings = CacheSettings.from_env()
        if cache_settings.path is not None:
            try:
                cache = TraceCache(cache_settings)
            except CacheError:
                cache = None
    app = FastAPI(
        title="DeWhirlpooler",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )
    app.mount(
        "/static",
        StaticFiles(directory=_STATIC_DIRECTORY),
        name="static",
    )

    @app.get("/", include_in_schema=False)
    def index() -> FileResponse:
        return FileResponse(
            _STATIC_DIRECTORY / "index.html",
            media_type="text/html",
        )

    @app.get("/health", include_in_schema=False)
    def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/api/network", include_in_schema=False)
    def network_overview() -> dict[str, object]:
        try:
            return network.overview()
        except Exception as exc:
            raise HTTPException(
                status_code=503,
                detail=_NETWORK_UNAVAILABLE_DETAIL,
            ) from exc

    @app.get(
        "/api/network/pools/{pool_id}/history",
        include_in_schema=False,
    )
    def pool_history(
        pool_id: str,
        start_height: Annotated[int | None, Query(ge=0)] = None,
        end_height: Annotated[int | None, Query(ge=0)] = None,
        limit: Annotated[int, Query(ge=1, le=2_000)] = 500,
    ) -> dict[str, object]:
        if (
            start_height is not None
            and end_height is not None
            and start_height > end_height
        ):
            raise HTTPException(
                status_code=422,
                detail="Start height may not exceed end height.",
            )
        try:
            return network.history(
                pool_id,
                start_height=start_height,
                end_height=end_height,
                limit=limit,
            )
        except ValueError as exc:
            raise HTTPException(
                status_code=404,
                detail=_UNKNOWN_POOL_DETAIL,
            ) from exc
        except Exception as exc:
            raise HTTPException(
                status_code=503,
                detail=_NETWORK_UNAVAILABLE_DETAIL,
            ) from exc

    @app.post("/api/trace", include_in_schema=False)
    def trace(
        request: _TraceRequest,
        response: Response,
    ) -> dict[str, object]:
        limits = request.trace_limits()
        cache_bypassed = cache is None
        if cache is not None:
            try:
                cached_report = cache.get(request.txid, limits)
            except CacheError:
                cache_bypassed = True
            else:
                if cached_report is not None:
                    response.headers["X-DeWhirlpooler-Cache"] = "HIT"
                    return cached_report

        try:
            report = service(request.txid, limits)
            report_dict = report.to_dict()
        except Exception as exc:
            raise HTTPException(
                status_code=502,
                detail=_SAFE_FAILURE_DETAIL,
            ) from exc

        if cache is not None and not cache_bypassed:
            try:
                cache.put(request.txid, limits, report_dict)
            except CacheError:
                cache_bypassed = True

        response.headers["X-DeWhirlpooler-Cache"] = (
            "BYPASS" if cache_bypassed else "MISS"
        )
        return report_dict

    return app
