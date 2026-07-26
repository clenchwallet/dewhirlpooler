"""Command-line entry point for safe Fulcrum probes."""

from __future__ import annotations

import argparse
import json
import sqlite3
import sys
from collections.abc import Sequence
from decimal import ROUND_HALF_UP, Decimal

from .bitcoin import Transaction, TransactionParseError, TxOutput
from .blocksource import CoreBlockError, CoreBlockSource
from .chainindex import (
    ChainIndex,
    ChainIndexError,
    ChainIndexSettings,
    ChainIndexStatus,
    ChainScanner,
)
from .config import FulcrumSettings
from .core import CoreClient, CoreRpcError, CoreSettings
from .electrum import ElectrumClient, ElectrumError
from .resolver import TransactionResolutionError, TransactionResolver
from .trace import ExposureTracer, TraceFindingKind, TraceLimits, TraceReport
from .whirlpool import (
    DEFAULT_POOLS,
    OutputRole,
    TransactionKind,
    WhirlpoolDetection,
    detect_whirlpool,
)


def main(argv: Sequence[str] | None = None) -> int:
    """Run a dewhirlpooler command and return its process exit code."""

    parser = _build_parser()
    args = parser.parse_args(argv)

    if args.command == "probe":
        return _run_probe(args)
    if args.command == "inspect":
        return _run_inspect(args)
    if args.command == "core-probe":
        return _run_core_probe(args)
    if args.command == "chain-index":
        return _run_chain_index(args)
    if args.command == "chain-status":
        return _run_chain_status(args)
    return _run_trace(args)


def _run_probe(args: argparse.Namespace) -> int:
    try:
        settings = FulcrumSettings.from_env()
        client = ElectrumClient(settings)
        server_version, protocol_version = client.server_version()
        chain_tip = client.chain_tip()
        transaction_hex = (
            client.transaction_hex(args.txid) if args.txid is not None else None
        )
    except (ValueError, ElectrumError) as exc:
        print(f"Connection failed: {exc}", file=sys.stderr)
        return 2

    print(
        f"Connected to Fulcrum {server_version} "
        f"(protocol {protocol_version})"
    )
    print(f"Chain height: {chain_tip.height}")
    if transaction_hex is not None:
        print(
            f"Transaction available: {args.txid} "
            f"({len(transaction_hex)} raw hex characters)"
        )
    return 0


def _run_inspect(args: argparse.Namespace) -> int:
    try:
        settings = FulcrumSettings.from_env()
        resolver = TransactionResolver(ElectrumClient(settings))
        transaction = resolver.transaction(args.txid)
        prevouts = resolver.prevouts(transaction)
        detection = detect_whirlpool(transaction, prevouts)
    except (
        ValueError,
        ElectrumError,
        TransactionParseError,
        TransactionResolutionError,
    ) as exc:
        print(f"Inspection failed: {exc}", file=sys.stderr)
        return 2

    _print_detection(transaction, detection)
    return 0


def _run_core_probe(args: argparse.Namespace) -> int:
    try:
        requested_height = (
            _parse_nonnegative(args.height, "block height")
            if args.height is not None
            else None
        )
        source = CoreBlockSource(
            CoreClient(CoreSettings.from_env())
        )
        chain_height = source.chain_height()
        block = (
            source.block_at_height(requested_height)
            if requested_height is not None
            else None
        )
    except (ValueError, CoreRpcError, CoreBlockError) as exc:
        print(f"Core connection failed: {exc}", file=sys.stderr)
        return 2

    print("Connected to Bitcoin Core read-only block RPC")
    print(f"Chain height: {chain_height}")
    if block is not None:
        resolved_inputs = sum(
            len(transaction.prevouts)
            for transaction in block.transactions
        )
        print(f"Block height: {block.height}")
        print(f"Block hash: {block.block_hash}")
        print(f"Transactions: {len(block.transactions)}")
        print(f"Resolved non-coinbase inputs: {resolved_inputs}")
    return 0


def _run_chain_index(args: argparse.Namespace) -> int:
    try:
        stop_height = (
            _parse_nonnegative(args.stop_height, "stop height")
            if args.stop_height is not None
            else None
        )
        max_blocks = (
            _parse_limit(args.max_blocks, "maximum blocks")
            if args.max_blocks is not None
            else None
        )
        source = CoreBlockSource(CoreClient(CoreSettings.from_env()))
        settings = ChainIndexSettings.from_env()
        completed = 0

        def report_progress(height: int, tip: int) -> None:
            nonlocal completed
            completed += 1
            if completed % 100 == 0:
                print(
                    f"Indexed {completed} blocks through height "
                    f"{height} (target {tip})",
                    file=sys.stderr,
                )

        with ChainIndex(settings) as index:
            result = ChainScanner(
                source,
                index,
                prefetch_workers=settings.prefetch_workers,
            ).scan(
                stop_height=stop_height,
                max_blocks=max_blocks,
                progress=report_progress,
            )
            tip_height = source.chain_height()
            status = index.status(tip_height=tip_height)
    except KeyboardInterrupt:
        print(
            "Chain indexing interrupted; completed blocks remain resumable.",
            file=sys.stderr,
        )
        return 130
    except (
        ValueError,
        CoreRpcError,
        CoreBlockError,
        ChainIndexError,
    ) as exc:
        print(f"Chain indexing failed: {exc}", file=sys.stderr)
        return 2
    except (OSError, sqlite3.Error):
        print(
            "Chain indexing failed: the chain index database "
            "could not be accessed.",
            file=sys.stderr,
        )
        return 2

    print(f"Blocks scanned: {result.blocks_scanned}")
    print(
        "Reorganization blocks rolled back: "
        f"{result.reorg_blocks_rolled_back}"
    )
    _print_chain_coverage(status)
    return 0


def _run_chain_status(args: argparse.Namespace) -> int:
    try:
        requested_height = (
            _parse_nonnegative(args.height, "block height")
            if args.height is not None
            else None
        )
        supported_pools = {
            pool.identifier for pool in DEFAULT_POOLS
        }
        if (
            args.pool is not None
            and args.pool not in supported_pools
        ):
            raise ValueError(
                "The Whirlpool pool identifier is unsupported."
            )
        source = CoreBlockSource(CoreClient(CoreSettings.from_env()))
        settings = ChainIndexSettings.from_env()
        tip_height = source.chain_height()
        with ChainIndex(settings) as index:
            status = index.status(tip_height=tip_height)
            if args.pool is not None:
                if requested_height is None:
                    snapshots = tuple(
                        snapshot
                        for snapshot in index.latest_pool_snapshots()
                        if snapshot.pool_id == args.pool
                    )
                else:
                    snapshot = index.pool_snapshot(
                        args.pool,
                        requested_height,
                    )
                    snapshots = (
                        (snapshot,) if snapshot is not None else ()
                    )
            elif requested_height is not None:
                snapshots = tuple(
                    snapshot
                    for pool in DEFAULT_POOLS
                    if (
                        snapshot := index.pool_snapshot(
                            pool.identifier,
                            requested_height,
                        )
                    )
                    is not None
                )
            else:
                snapshots = index.latest_pool_snapshots()
            if requested_height is not None and not snapshots:
                raise ChainIndexError(
                    "No pool snapshot exists at the requested height."
                )
            coordinator = index.coordinator_summary()
    except (
        ValueError,
        CoreRpcError,
        CoreBlockError,
        ChainIndexError,
    ) as exc:
        print(f"Chain status failed: {exc}", file=sys.stderr)
        return 2
    except (OSError, sqlite3.Error):
        print(
            "Chain status failed: the chain index database "
            "could not be accessed.",
            file=sys.stderr,
        )
        return 2

    _print_chain_coverage(status)
    for snapshot in snapshots:
        print(
            f"Pool {snapshot.pool_id} at height {snapshot.height}: "
            f"{snapshot.liquidity_sats} sats in "
            f"{snapshot.utxo_count} output(s)"
        )
        print(
            f"  Entries: +{snapshot.entry_sats} sats across "
            f"{snapshot.tx0_count} Tx0(s); "
            f"exits: -{snapshot.exit_sats} sats; "
            f"rounds: {snapshot.round_count}"
        )
    print(f"Coordinator gross fees: {coordinator.gross_revenue_sats} sats")
    print(
        "Known coordinator consolidation mining costs: "
        f"{coordinator.known_mining_cost_sats} sats"
    )
    print(
        f"Coordinator net known profit: "
        f"{coordinator.net_known_profit_sats} sats"
    )
    print(
        "Ambiguous coordinator spends: "
        f"{coordinator.ambiguous_spend_count} "
        f"({coordinator.ambiguous_input_sats} tracked sats)"
    )
    return 0


def _print_chain_coverage(status: ChainIndexStatus) -> None:
    start_height = status.start_height
    last_height = status.last_height
    coverage = (
        f"{start_height}-{last_height}"
        if last_height is not None
        else f"not started (configured start {start_height})"
    )
    print(f"Chain index coverage: {coverage}")
    print(f"Blocks indexed: {status.blocks_indexed}")
    print(f"Core tip: {status.tip_height}")
    print(
        "Complete to tip: "
        f"{'yes' if status.complete_to_tip else 'no'}"
    )


def _run_trace(args: argparse.Namespace) -> int:
    try:
        limits = TraceLimits(
            max_depth=_parse_limit(args.max_depth, "max depth"),
            max_transactions=_parse_limit(
                args.max_transactions,
                "max transactions",
            ),
            max_outputs=_parse_limit(args.max_outputs, "max outputs"),
            max_history_lookups=_parse_limit(
                args.max_history_lookups,
                "max history lookups",
            ),
        )
        settings = FulcrumSettings.from_env()
        resolver = TransactionResolver(ElectrumClient(settings))
        report = ExposureTracer(resolver, limits).trace(args.txid)
    except (
        ValueError,
        ElectrumError,
        TransactionParseError,
        TransactionResolutionError,
    ) as exc:
        print(f"Trace failed: {exc}", file=sys.stderr)
        return 2

    if args.json:
        print(json.dumps(report.to_dict(), indent=2, sort_keys=True))
    else:
        _print_trace(report)
    return 0


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="dewhirlpooler",
        description="Inspect possible Whirlpool transaction exposure.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    probe_parser = subparsers.add_parser(
        "probe",
        help="Check the Fulcrum server and chain height.",
    )
    probe_parser.add_argument(
        "--txid",
        help="Also check whether this transaction is available.",
    )
    inspect_parser = subparsers.add_parser(
        "inspect",
        help="Inspect one transaction for supported Whirlpool patterns.",
    )
    inspect_parser.add_argument(
        "--txid",
        required=True,
        help="Transaction ID to inspect.",
    )
    core_probe_parser = subparsers.add_parser(
        "core-probe",
        help="Check a read-only Bitcoin Core block source.",
    )
    core_probe_parser.add_argument(
        "--height",
        help="Also fetch and validate one nonnegative block height.",
    )
    chain_index_parser = subparsers.add_parser(
        "chain-index",
        help="Build or resume the chain-wide Whirlpool index.",
    )
    chain_index_parser.add_argument(
        "--stop-height",
        help="Stop at this nonnegative block height.",
    )
    chain_index_parser.add_argument(
        "--max-blocks",
        help="Index at most this positive number of blocks.",
    )
    chain_status_parser = subparsers.add_parser(
        "chain-status",
        help="Show chain-index coverage and aggregate results.",
    )
    chain_status_parser.add_argument(
        "--pool",
        help="Show only this Whirlpool pool identifier.",
    )
    chain_status_parser.add_argument(
        "--height",
        help="Show pool values at this indexed block height.",
    )
    trace_parser = subparsers.add_parser(
        "trace",
        help="Follow a bounded possible-exposure trail.",
    )
    trace_parser.add_argument(
        "--txid",
        required=True,
        help="Root transaction ID to trace.",
    )
    trace_parser.add_argument("--max-depth", default="8")
    trace_parser.add_argument("--max-transactions", default="100")
    trace_parser.add_argument("--max-outputs", default="250")
    trace_parser.add_argument("--max-history-lookups", default="250")
    trace_parser.add_argument(
        "--json",
        action="store_true",
        help="Print the stable report as JSON.",
    )
    return parser


def _print_detection(
    transaction: Transaction,
    detection: WhirlpoolDetection,
) -> None:
    print(f"Transaction: {transaction.txid}")

    if detection.kind is TransactionKind.TX0:
        print("Type: Whirlpool Tx0 candidate")
        _print_pool(detection)
        print(f"Confidence: {detection.confidence.value}")
        premix = _outputs_with_role(
            transaction,
            detection,
            OutputRole.PREMIX,
        )
        print(f"Premix outputs: {len(premix)}")
        print(
            "Inputs grouped by this transaction "
            "(common-input-ownership heuristic): "
            f"{_display_number(detection.input_count)}"
        )
        print(
            "Input value grouped by this transaction "
            "(common-input-ownership heuristic): "
            f"{_display_sats(detection.input_value_sats)}"
        )
        print(f"Miner fee: {_display_sats(detection.miner_fee_sats)}")
        print(
            "Coordinator fee candidate: "
            f"{_display_sats(detection.coordinator_fee_sats)}"
        )
        print(
            f"Total Tx0 fee cost: "
            f"{_display_sats(detection.total_fee_cost_sats)}"
        )
        print(
            f"Entered pool capacity: "
            f"{_display_sats(detection.entered_pool_sats)}"
        )
        print(
            "Fee cost as percentage of equal denominations: "
            f"{_display_percent(detection.fee_cost_percent)}"
        )
        change_outputs = _outputs_with_role(
            transaction,
            detection,
            OutputRole.DOXXIC_CHANGE,
        )
        if change_outputs:
            print(
                f"Doxxic change candidate: {change_outputs[0].value_sats} sats"
            )
    elif detection.kind is TransactionKind.WHIRLPOOL_ROUND:
        print("Type: Whirlpool round candidate")
        _print_pool(detection)
        print(f"Confidence: {detection.confidence.value}")
        print(
            "Round size: "
            f"{detection.round_size}:{detection.round_size}"
            if detection.round_size is not None
            else "Round size: unavailable"
        )
        entrant_display = _display_round_group(
            detection.premix_input_count,
            (
                detection.round_size
                if detection.input_count is not None
                else None
            ),
        )
        print(f"New entrants: {entrant_display}")
        remixer_display = _display_round_group(
            detection.remix_input_count,
            (
                detection.round_size
                if detection.input_count is not None
                else None
            ),
        )
        print(f"Remixers: {remixer_display}")
        print(f"Miner fee: {_display_sats(detection.miner_fee_sats)}")
    else:
        print("Type: No supported Whirlpool pattern detected")
        print(f"Confidence: {detection.confidence.value}")

    for warning in detection.warnings:
        print(f"Warning: {warning}")


def _print_pool(detection: WhirlpoolDetection) -> None:
    if detection.pool is None:
        return
    print(
        f"Protocol/pool: {detection.pool.protocol} / "
        f"{detection.pool.identifier}"
    )


def _outputs_with_role(
    transaction: Transaction,
    detection: WhirlpoolDetection,
    role: OutputRole,
) -> list[TxOutput]:
    indices = {
        classification.index
        for classification in detection.outputs
        if classification.role is role
    }
    return [output for output in transaction.outputs if output.index in indices]


def _print_trace(report: TraceReport) -> None:
    summary = report.summary
    print(f"Root transaction: {report.root_txid}")
    print(f"Transactions examined: {summary.transactions_examined}")
    print(f"Outputs examined: {summary.outputs_examined}")
    print(f"Whirlpool rounds: {summary.whirlpool_rounds}")
    print(f"Later Tx0s: {summary.later_tx0s}")
    print(f"Postmix consolidations: {summary.postmix_consolidations}")
    print(
        "3+ coin one-output consolidations: "
        f"{summary.postmix_payment_consolidations}"
    )
    print(f"Cross-role address reuse: {summary.address_reuse_findings}")
    print(f"Whirlpool CPFP candidates: {summary.whirlpool_cpfp_findings}")
    print(f"Stonewall candidates: {summary.stonewall_spends}")
    print(f"Ricochet candidates: {summary.ricochet_spends}")
    print(
        "Possible Payjoin / Cahoots fingerprint leak: "
        f"{summary.postmix_payjoin_fingerprint_candidates}"
    )
    print(f"Possible payments: {summary.possible_payments}")
    print(
        f"Unspent tracked funds: {summary.unspent_sats} sats across "
        f"{summary.unspent_output_count} output(s)"
    )
    print(f"Trace truncated: {'yes' if report.truncated else 'no'}")

    for finding in report.findings:
        if finding.kind is TraceFindingKind.LATER_TX0:
            print(
                f"Later Tx0 candidate: {finding.txid} "
                f"({finding.confidence.value} confidence)"
            )
        elif finding.kind is TraceFindingKind.POSTMIX_CONSOLIDATION:
            print(
                f"Postmix consolidation candidate: {finding.txid} "
                f"({len(finding.outpoints)} co-spent tracked outputs)"
            )
        elif (
            finding.kind
            is TraceFindingKind.POSTMIX_PAYMENT_CONSOLIDATION
        ):
            print(
                "Possible Tx0 -> Whirlpool -> payment consolidation: "
                f"{finding.txid} "
                f"({len(finding.outpoints)} tracked postmix inputs)"
            )
        elif finding.kind is TraceFindingKind.STONEWALL:
            print(
                f"Possible Stonewall / StonewallX2: {finding.txid} "
                f"({finding.confidence.value} confidence)"
            )
            print(
                "Repeated output amounts: "
                + ", ".join(
                    _display_sats(value)
                    for value in finding.repeated_output_values_sats
                )
            )
        elif finding.kind is TraceFindingKind.RICOCHET:
            print(
                f"Possible Ricochet: {finding.txid} "
                f"({finding.confidence.value} confidence)"
            )
            print(
                "Ricochet service fee: "
                f"{_display_sats(finding.service_fee_sats)}"
            )
            print(
                "Ricochet fee address: "
                f"{finding.service_fee_address or 'unavailable'}"
            )
            print(
                f"Four observed hops: {len(finding.hop_txids)} "
                f"({', '.join(finding.hop_txids)})"
            )
        elif (
            finding.kind
            is TraceFindingKind.POSTMIX_PAYJOIN_FINGERPRINT
        ):
            print(
                "Possible Payjoin / Cahoots fingerprint leak: "
                f"{finding.txid} ({finding.confidence.value} confidence)"
            )
            print(
                "Unnecessary-input clue: "
                + (
                    finding.payjoin_unnecessary_input_heuristic.upper()
                    if finding.payjoin_unnecessary_input_heuristic
                    in {"uih1", "uih2"}
                    else "none"
                )
            )
            signals = finding.payjoin_fingerprint_signals
            print(
                "Input fingerprint differences: "
                + (
                    ", ".join(
                        _display_payjoin_signal(signal)
                        for signal in signals
                    )
                    if signals
                    else "none"
                )
            )
            groups = finding.payjoin_input_clusters
            print(
                f"Observable input groups: {len(groups)}"
                + (
                    " ("
                    + "; ".join(
                        "inputs "
                        + ", ".join(
                            str(index + 1) for index in group
                        )
                        for group in groups
                    )
                    + ")"
                    if groups
                    else ""
                )
            )
            print(
                "This is consistent with Payjoin/Cahoots, not proof; "
                "observable groups are not proven owners."
            )
        elif finding.kind is TraceFindingKind.ADDRESS_REUSE:
            roles = ", ".join(
                _display_reused_role(role)
                for role in finding.reused_roles
            )
            print(
                "Address reused across roles: "
                f"{finding.reused_address or 'unavailable'} "
                f"({roles})"
            )
        elif finding.kind is TraceFindingKind.WHIRLPOOL_CPFP:
            print(
                "Possible Whirlpool CPFP: "
                f"{finding.cpfp_parent_txid or 'unavailable'} -> "
                f"{finding.txid} at block "
                f"{finding.cpfp_block_height or 'unavailable'}"
            )
            print(
                "Fee rates (parent / child / package): "
                f"{finding.cpfp_parent_fee_rate or 'unavailable'} / "
                f"{finding.cpfp_child_fee_rate or 'unavailable'} / "
                f"{finding.cpfp_package_fee_rate or 'unavailable'} sat/vB"
            )
    for warning in report.warnings:
        print(f"Warning: {warning}")


def _parse_limit(value: object, label: str) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        raise ValueError(f"{label} must be a positive integer") from None
    if parsed <= 0 or str(parsed) != str(value).strip():
        raise ValueError(f"{label} must be a positive integer")
    return parsed


def _display_reused_role(role: str) -> str:
    return {
        "coordinator_fee": "coordinator fee",
        "tx0_premix": "Tx0 premix",
        "whirlpool_coinjoin_output": "Whirlpool output",
        "stonewall_equal_output": "Stonewall equal output",
    }.get(role, role.replace("_", " "))


def _display_payjoin_signal(signal: str) -> str:
    return {
        "prevout_script_type": "previous-output script type",
        "sequence": "input sequence",
        "ecdsa_r_length": "ECDSA signature R length",
        "ecdsa_sighash": "ECDSA sighash",
        "taproot_sighash_form": "Taproot sighash form",
    }.get(signal, signal.replace("_", " "))


def _parse_nonnegative(value: object, label: str) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        raise ValueError(
            f"{label} must be a nonnegative integer"
        ) from None
    if parsed < 0 or str(parsed) != str(value).strip():
        raise ValueError(f"{label} must be a nonnegative integer")
    return parsed


def _display_number(value: int | None) -> str:
    return str(value) if value is not None else "unavailable"


def _display_sats(value: int | None) -> str:
    return f"{value} sats" if value is not None else "unavailable"


def _display_percent(value: str | None) -> str:
    return f"{value}%" if value is not None else "unavailable"


def _display_round_group(count: int, round_size: int | None) -> str:
    if round_size is None or round_size <= 0:
        return "unavailable"
    percentage = (
        Decimal(count) * Decimal(100) / Decimal(round_size)
    ).quantize(Decimal("0.0001"), rounding=ROUND_HALF_UP)
    return f"{count} ({format(percentage, '.4f')}%)"
