from __future__ import annotations

import json
from pathlib import Path

import pytest

from dewhirlpooler import cli
from dewhirlpooler.bitcoin import (
    OutPoint,
    ScriptType,
    Transaction,
    TxOutput,
    parse_transaction_hex,
)
from dewhirlpooler.blocksource import (
    BlockTransaction,
    CoreBlock,
)
from dewhirlpooler.config import FulcrumSettings
from dewhirlpooler.core import CoreRpcError
from dewhirlpooler.electrum import (
    ChainTip,
    ElectrumConnectionError,
)
from dewhirlpooler.resolver import TransactionResolutionError
from dewhirlpooler.trace import (
    TraceFinding,
    TraceFindingKind,
    TraceLimits,
    TraceReport,
    TraceSummary,
)
from dewhirlpooler.whirlpool import Confidence

TXID = "b" * 64
FIXTURES = Path(__file__).parent / "fixtures"


class SuccessfulClient:
    def __init__(self, settings: FulcrumSettings) -> None:
        self.settings = settings

    def server_version(self) -> tuple[str, str]:
        return "Fulcrum 2.0", "1.4"

    def chain_tip(self) -> ChainTip:
        return ChainTip(height=850_000, header_hex="ab" * 80)

    def transaction_hex(self, txid: str) -> str:
        assert txid == TXID
        return "01000000"


def _configure_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DEWHIRLPOOLER_FULCRUM_HOST", "fulcrum.example")
    monkeypatch.delenv("DEWHIRLPOOLER_FULCRUM_PORT", raising=False)
    monkeypatch.delenv("DEWHIRLPOOLER_FULCRUM_TLS", raising=False)
    monkeypatch.delenv("DEWHIRLPOOLER_FULCRUM_TIMEOUT", raising=False)


def test_cli_success_without_txid(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    _configure_environment(monkeypatch)
    monkeypatch.setattr(cli, "ElectrumClient", SuccessfulClient)

    result = cli.main(["probe"])

    captured = capsys.readouterr()
    assert result == 0
    assert captured.out == (
        "Connected to Fulcrum Fulcrum 2.0 (protocol 1.4)\n"
        "Chain height: 850000\n"
    )
    assert "Transaction available" not in captured.out
    assert captured.err == ""


def test_cli_success_with_txid(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    _configure_environment(monkeypatch)
    monkeypatch.setattr(cli, "ElectrumClient", SuccessfulClient)

    result = cli.main(["probe", "--txid", TXID])

    captured = capsys.readouterr()
    assert result == 0
    assert captured.out == (
        "Connected to Fulcrum Fulcrum 2.0 (protocol 1.4)\n"
        "Chain height: 850000\n"
        f"Transaction available: {TXID} (8 raw hex characters)\n"
    )
    assert captured.err == ""


def test_cli_configuration_failure_is_concise(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.delenv("DEWHIRLPOOLER_FULCRUM_HOST", raising=False)

    result = cli.main(["probe"])

    captured = capsys.readouterr()
    assert result == 2
    assert captured.out == ""
    assert captured.err.startswith("Connection failed: ")
    assert "DEWHIRLPOOLER_FULCRUM_HOST" in captured.err
    assert "Traceback" not in captured.err


def test_cli_connection_failure_hides_host_and_traceback(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    hidden_host = "hidden.fulcrum.example"
    monkeypatch.setenv("DEWHIRLPOOLER_FULCRUM_HOST", hidden_host)

    class FailingClient:
        def __init__(self, settings: FulcrumSettings) -> None:
            pass

        def server_version(self) -> tuple[str, str]:
            raise ElectrumConnectionError(
                "Unable to communicate with the Fulcrum server."
            )

    monkeypatch.setattr(cli, "ElectrumClient", FailingClient)

    result = cli.main(["probe"])

    captured = capsys.readouterr()
    assert result == 2
    assert captured.out == ""
    assert captured.err == (
        "Connection failed: "
        "Unable to communicate with the Fulcrum server.\n"
    )
    assert hidden_host not in captured.err
    assert "Traceback" not in captured.err


def test_core_probe_prints_tip_only(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    requested = _configure_core_probe(monkeypatch)

    result = cli.main(["core-probe"])

    captured = capsys.readouterr()
    assert result == 0
    assert captured.out == (
        "Connected to Bitcoin Core read-only block RPC\n"
        "Chain height: 959575\n"
    )
    assert captured.err == ""
    assert requested == []


def test_core_probe_prints_validated_block(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    requested = _configure_core_probe(monkeypatch)

    result = cli.main(["core-probe", "--height", "123"])

    captured = capsys.readouterr()
    assert result == 0
    assert captured.out == (
        "Connected to Bitcoin Core read-only block RPC\n"
        "Chain height: 959575\n"
        "Block height: 123\n"
        f"Block hash: {'a' * 64}\n"
        "Transactions: 1\n"
        "Resolved non-coinbase inputs: 1\n"
    )
    assert captured.err == ""
    assert requested == [123]


@pytest.mark.parametrize("height", ["-1", "1.5", "abc", "01"])
def test_core_probe_rejects_invalid_height_before_configuration(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    height: str,
) -> None:
    monkeypatch.delenv("DEWHIRLPOOLER_CORE_HOST", raising=False)

    result = cli.main(["core-probe", "--height", height])

    captured = capsys.readouterr()
    assert result == 2
    assert captured.out == ""
    assert captured.err == (
        "Core connection failed: "
        "block height must be a nonnegative integer\n"
    )


def test_core_probe_failure_is_concise_and_secret_safe(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    hidden_host = "private-core.example"
    hidden_password = "private-core-password"
    monkeypatch.setenv("DEWHIRLPOOLER_CORE_HOST", hidden_host)
    monkeypatch.setenv("DEWHIRLPOOLER_CORE_USER", "reader")
    monkeypatch.setenv("DEWHIRLPOOLER_CORE_PASSWORD", hidden_password)

    class FailingSource:
        def __init__(self, client: object) -> None:
            pass

        def chain_height(self) -> int:
            raise CoreRpcError("Bitcoin Core RPC request failed.")

    monkeypatch.setattr(cli, "CoreBlockSource", FailingSource)

    result = cli.main(["core-probe"])

    captured = capsys.readouterr()
    assert result == 2
    assert captured.out == ""
    assert captured.err == (
        "Core connection failed: Bitcoin Core RPC request failed.\n"
    )
    assert hidden_host not in captured.err
    assert hidden_password not in captured.err
    assert "Traceback" not in captured.err


def test_chain_index_and_status_use_resumable_database(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
) -> None:
    _configure_chain_commands(monkeypatch, tmp_path, tip=102)

    result = cli.main(["chain-index", "--max-blocks", "2"])

    captured = capsys.readouterr()
    assert result == 0
    assert captured.err == ""
    assert captured.out == (
        "Blocks scanned: 2\n"
        "Reorganization blocks rolled back: 0\n"
        "Chain index coverage: 100-101\n"
        "Blocks indexed: 2\n"
        "Core tip: 102\n"
        "Complete to tip: no\n"
    )

    result = cli.main(
        [
            "chain-status",
            "--pool",
            "ashigaru-0.025",
            "--height",
            "101",
        ]
    )

    captured = capsys.readouterr()
    assert result == 0
    assert captured.err == ""
    assert "Chain index coverage: 100-101\n" in captured.out
    assert "Complete to tip: no\n" in captured.out
    assert (
        "Pool ashigaru-0.025 at height 101: "
        "0 sats in 0 output(s)\n"
    ) in captured.out
    assert "Coordinator gross fees: 0 sats\n" in captured.out
    assert "Ambiguous coordinator spends: 0 (0 tracked sats)\n" in (
        captured.out
    )


def test_chain_index_reports_progress_every_hundred_blocks(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
) -> None:
    _configure_chain_commands(monkeypatch, tmp_path, tip=199)

    result = cli.main(["chain-index"])

    captured = capsys.readouterr()
    assert result == 0
    assert captured.err == (
        "Indexed 100 blocks through height 199 (target 199)\n"
    )
    assert "Blocks scanned: 100\n" in captured.out
    assert "Complete to tip: yes\n" in captured.out


def test_chain_index_passes_configured_prefetch_workers(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
) -> None:
    _configure_chain_commands(monkeypatch, tmp_path, tip=100)
    monkeypatch.setenv("DEWHIRLPOOLER_CHAIN_PREFETCH_WORKERS", "16")
    observed: list[int] = []
    scanner = cli.ChainScanner

    class RecordingScanner:
        def __init__(
            self,
            source: object,
            index: object,
            *,
            prefetch_workers: int,
        ) -> None:
            observed.append(prefetch_workers)
            self._scanner = scanner(
                source,
                index,
                prefetch_workers=prefetch_workers,
            )

        def scan(self, **kwargs: object):
            return self._scanner.scan(**kwargs)

    monkeypatch.setattr(cli, "ChainScanner", RecordingScanner)

    result = cli.main(["chain-index", "--max-blocks", "1"])

    captured = capsys.readouterr()
    assert result == 0
    assert captured.err == ""
    assert observed == [16]


@pytest.mark.parametrize(
    ("arguments", "message"),
    [
        (
            ["chain-index", "--max-blocks", "0"],
            "maximum blocks must be a positive integer",
        ),
        (
            ["chain-status", "--height", "-1"],
            "block height must be a nonnegative integer",
        ),
        (
            ["chain-status", "--pool", "unknown"],
            "The Whirlpool pool identifier is unsupported.",
        ),
    ],
)
def test_chain_commands_reject_bad_arguments_before_configuration(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    arguments: list[str],
    message: str,
) -> None:
    monkeypatch.delenv("DEWHIRLPOOLER_CORE_HOST", raising=False)

    result = cli.main(arguments)

    captured = capsys.readouterr()
    assert result == 2
    assert captured.out == ""
    assert message in captured.err
    assert "Traceback" not in captured.err


def test_inspect_prints_current_tx0(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    transaction = _fixture("ashigaru-tx0-0.025.hex")
    _configure_inspection(monkeypatch, transaction, {})

    result = cli.main(["inspect", "--txid", transaction.txid])

    captured = capsys.readouterr()
    assert result == 0
    assert captured.err == ""
    assert captured.out == (
        f"Transaction: {transaction.txid}\n"
        "Type: Whirlpool Tx0 candidate\n"
        "Protocol/pool: Ashigaru / ashigaru-0.025\n"
        "Confidence: high\n"
        "Premix outputs: 9\n"
        "Inputs grouped by this transaction "
        "(common-input-ownership heuristic): unavailable\n"
        "Input value grouped by this transaction "
        "(common-input-ownership heuristic): unavailable\n"
        "Miner fee: unavailable\n"
        "Coordinator fee candidate: 125000 sats\n"
        "Total Tx0 fee cost: unavailable\n"
        "Entered pool capacity: 22500000 sats\n"
        "Fee cost as percentage of equal denominations: unavailable\n"
        "Doxxic change candidate: 2481116 sats\n"
    )


def test_inspect_prints_resolved_tx0_accounting(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    transaction = _fixture("ashigaru-tx0-0.025.hex")
    output_total = sum(output.value_sats for output in transaction.outputs)
    values = [0] * len(transaction.inputs)
    values[0] = output_total + 15_000
    prevouts = {
        transaction_input.previous_output: TxOutput(
            index=transaction_input.previous_output.index,
            value_sats=value,
            script_pubkey=b"\x00\x14" + bytes((position + 1,)) * 20,
            script_type=ScriptType.P2WPKH,
        )
        for position, (transaction_input, value) in enumerate(
            zip(transaction.inputs, values, strict=True)
        )
    }
    _configure_inspection(monkeypatch, transaction, prevouts)

    result = cli.main(["inspect", "--txid", transaction.txid])

    captured = capsys.readouterr()
    assert result == 0
    assert (
        "Inputs grouped by this transaction "
        f"(common-input-ownership heuristic): {len(transaction.inputs)}\n"
        in captured.out
    )
    assert (
        "Input value grouped by this transaction "
        f"(common-input-ownership heuristic): {output_total + 15_000} sats\n"
        in captured.out
    )
    assert "Miner fee: 15000 sats\n" in captured.out
    assert "Coordinator fee candidate: 125000 sats\n" in captured.out
    assert "Total Tx0 fee cost: 140000 sats\n" in captured.out
    assert "Entered pool capacity: 22500000 sats\n" in captured.out
    assert (
        "Fee cost as percentage of equal denominations: 0.6222%\n"
        in captured.out
    )


def test_inspect_prints_validated_round(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    transaction = _fixture("ashigaru-round-0.025.hex")
    values = [2_500_605] * 2 + [2_500_000] * 3
    prevouts = {
        transaction_input.previous_output: TxOutput(
            index=transaction_input.previous_output.index,
            value_sats=value,
            script_pubkey=b"\x00\x14" + bytes((position + 1,)) * 20,
            script_type=ScriptType.P2WPKH,
        )
        for position, (transaction_input, value) in enumerate(
            zip(transaction.inputs, values, strict=True)
        )
    }
    _configure_inspection(monkeypatch, transaction, prevouts)

    result = cli.main(["inspect", "--txid", transaction.txid])

    captured = capsys.readouterr()
    assert result == 0
    assert captured.err == ""
    assert "Type: Whirlpool round candidate\n" in captured.out
    assert "Confidence: high\n" in captured.out
    assert "Round size: 5:5\n" in captured.out
    assert "New entrants: 2 (40.0000%)\n" in captured.out
    assert "Remixers: 3 (60.0000%)\n" in captured.out
    assert "Miner fee: 1210 sats\n" in captured.out


def test_inspect_prints_unknown_transaction(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    template = _fixture("ashigaru-tx0-0.025.hex")
    transaction = Transaction(
        version=template.version,
        inputs=template.inputs,
        outputs=(
            TxOutput(
                index=0,
                value_sats=42_000,
                script_pubkey=b"\x51\x20" + b"\x11" * 32,
                script_type=ScriptType.P2TR,
            ),
        ),
        lock_time=template.lock_time,
        has_witness=template.has_witness,
        txid=template.txid,
        wtxid=template.wtxid,
        size=template.size,
        weight=template.weight,
        vsize=template.vsize,
    )
    _configure_inspection(monkeypatch, transaction, {})

    result = cli.main(["inspect", "--txid", transaction.txid])

    captured = capsys.readouterr()
    assert result == 0
    assert captured.err == ""
    assert "Type: No supported Whirlpool pattern detected\n" in captured.out


def test_inspect_failure_is_concise(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    _configure_environment(monkeypatch)

    class FailingResolver:
        def __init__(self, client: object) -> None:
            pass

        def transaction(self, txid: str) -> Transaction:
            raise TransactionResolutionError(
                "Fulcrum returned invalid transaction data."
            )

    monkeypatch.setattr(cli, "TransactionResolver", FailingResolver)

    result = cli.main(["inspect", "--txid", "a" * 64])

    captured = capsys.readouterr()
    assert result == 2
    assert captured.out == ""
    assert captured.err == (
        "Inspection failed: Fulcrum returned invalid transaction data.\n"
    )
    assert "Traceback" not in captured.err


def test_trace_prints_text_summary_and_key_findings(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    report = _trace_report()
    _configure_trace(monkeypatch, report)

    result = cli.main(["trace", "--txid", report.root_txid])

    captured = capsys.readouterr()
    assert result == 0
    assert captured.err == ""
    assert captured.out == (
        f"Root transaction: {report.root_txid}\n"
        "Transactions examined: 4\n"
        "Outputs examined: 20\n"
        "Whirlpool rounds: 1\n"
        "Later Tx0s: 1\n"
        "Postmix consolidations: 1\n"
        "3+ coin one-output consolidations: 1\n"
        "Cross-role address reuse: 1\n"
        "Whirlpool CPFP candidates: 1\n"
        "Stonewall candidates: 1\n"
        "Ricochet candidates: 1\n"
        "Possible Payjoin / Cahoots fingerprint leak: 1\n"
        "Possible payments: 2\n"
        "Unspent tracked funds: 3500000 sats across 3 output(s)\n"
        "Trace truncated: no\n"
        f"Later Tx0 candidate: {'c' * 64} (high confidence)\n"
        f"Postmix consolidation candidate: {'d' * 64} "
        "(2 co-spent tracked outputs)\n"
        "Possible Tx0 -> Whirlpool -> payment consolidation: "
        f"{'7' * 64} (3 one-to-one matched inputs)\n"
        f"Source Tx0: {'a' * 64}\n"
        f"Possible Stonewall / StonewallX2: {'e' * 64} "
        "(medium confidence)\n"
        "Repeated output amounts: 408297 sats, 4588406 sats\n"
        f"Possible Ricochet: {'f' * 64} (medium confidence)\n"
        "Ricochet service fee: 100000 sats\n"
        "Ricochet fee address: bc1qexample\n"
        "Four observed hops: 4 "
        f"({'1' * 64}, {'2' * 64}, {'3' * 64}, {'4' * 64})\n"
        "Possible Payjoin / Cahoots fingerprint leak: "
        f"{'5' * 64} (medium confidence)\n"
        "Unnecessary-input clue: UIH1\n"
        "Input fingerprint differences: ECDSA signature R length\n"
        "Observable input groups: 2 (inputs 1; inputs 2)\n"
        "This is consistent with Payjoin/Cahoots, not proof; "
        "observable groups are not proven owners.\n"
        "Address reused across roles: bc1qreused "
        "(coordinator fee, Whirlpool output)\n"
        f"Possible Whirlpool CPFP: {'8' * 64} -> {'9' * 64} "
        "at block 577604\n"
        "Fee rates (parent / child / package): "
        "59.41 / 141.80 / 74.14 sat/vB\n"
    )


def test_trace_prints_json_only(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    report = _trace_report(truncated=True)
    _configure_trace(monkeypatch, report)

    result = cli.main(["trace", "--txid", report.root_txid, "--json"])

    captured = capsys.readouterr()
    assert result == 0
    assert captured.err == ""
    content = json.loads(captured.out)
    assert content["root_txid"] == report.root_txid
    assert content["truncated"] is True
    assert content["summary"]["transactions_examined"] == 4


@pytest.mark.parametrize("value", ["0", "-1", "1.5", "abc", "01"])
def test_trace_invalid_limit_is_concise(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    value: str,
) -> None:
    _configure_environment(monkeypatch)

    result = cli.main(
        [
            "trace",
            "--txid",
            "a" * 64,
            "--max-depth",
            value,
        ]
    )

    captured = capsys.readouterr()
    assert result == 2
    assert captured.out == ""
    assert captured.err == (
        "Trace failed: max depth must be a positive integer\n"
    )


def test_trace_failure_is_concise(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    _configure_environment(monkeypatch)

    class FailingTracer:
        def __init__(self, resolver: object, limits: object) -> None:
            pass

        def trace(self, txid: str) -> TraceReport:
            raise TransactionResolutionError(
                "Output history is too large for bounded spend resolution."
            )

    monkeypatch.setattr(cli, "ExposureTracer", FailingTracer)

    result = cli.main(["trace", "--txid", "a" * 64])

    captured = capsys.readouterr()
    assert result == 2
    assert captured.out == ""
    assert captured.err == (
        "Trace failed: Output history is too large for bounded spend "
        "resolution.\n"
    )
    assert "Traceback" not in captured.err


def _fixture(name: str) -> Transaction:
    return parse_transaction_hex((FIXTURES / name).read_text().strip())


def _configure_inspection(
    monkeypatch: pytest.MonkeyPatch,
    transaction: Transaction,
    prevouts: dict[OutPoint, TxOutput],
) -> None:
    _configure_environment(monkeypatch)

    class FakeResolver:
        def __init__(self, client: object) -> None:
            pass

        def transaction(self, txid: str) -> Transaction:
            assert txid == transaction.txid
            return transaction

        def prevouts(
            self,
            inspected: Transaction,
        ) -> dict[OutPoint, TxOutput]:
            assert inspected is transaction
            return prevouts

    monkeypatch.setattr(cli, "TransactionResolver", FakeResolver)


def _configure_trace(
    monkeypatch: pytest.MonkeyPatch,
    report: TraceReport,
) -> None:
    _configure_environment(monkeypatch)

    class FakeTracer:
        def __init__(self, resolver: object, limits: object) -> None:
            assert limits == TraceLimits()

        def trace(self, txid: str) -> TraceReport:
            assert txid == report.root_txid
            return report

    monkeypatch.setattr(cli, "ExposureTracer", FakeTracer)


def _configure_core_probe(
    monkeypatch: pytest.MonkeyPatch,
) -> list[int]:
    monkeypatch.setenv("DEWHIRLPOOLER_CORE_HOST", "core.example")
    monkeypatch.setenv("DEWHIRLPOOLER_CORE_USER", "reader")
    monkeypatch.setenv("DEWHIRLPOOLER_CORE_PASSWORD", "synthetic-secret")
    requested: list[int] = []
    entry = _fixture("ricochet-testnet-entry.hex")
    transaction = _fixture("ricochet-testnet-hop-1.hex")
    previous_output = entry.outputs[2]
    block = CoreBlock(
        height=123,
        block_hash="a" * 64,
        previous_block_hash="b" * 64,
        block_time=1_700_000_000,
        transactions=(
            BlockTransaction(
                transaction=transaction,
                prevouts={
                    transaction.inputs[0].previous_output: previous_output
                },
            ),
        ),
    )

    class FakeCoreClient:
        def __init__(self, settings: object) -> None:
            pass

    class FakeCoreSource:
        def __init__(self, client: object) -> None:
            pass

        def chain_height(self) -> int:
            return 959_575

        def block_at_height(self, height: int) -> CoreBlock:
            requested.append(height)
            return block

    monkeypatch.setattr(cli, "CoreClient", FakeCoreClient)
    monkeypatch.setattr(cli, "CoreBlockSource", FakeCoreSource)
    return requested


def _configure_chain_commands(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    *,
    tip: int,
) -> None:
    monkeypatch.setenv("DEWHIRLPOOLER_CORE_HOST", "core.example")
    monkeypatch.setenv("DEWHIRLPOOLER_CORE_USER", "reader")
    monkeypatch.setenv(
        "DEWHIRLPOOLER_CORE_PASSWORD",
        "synthetic-secret",
    )
    monkeypatch.setenv(
        "DEWHIRLPOOLER_CHAIN_DB",
        str(tmp_path / "chain.sqlite3"),
    )
    monkeypatch.setenv("DEWHIRLPOOLER_CHAIN_START_HEIGHT", "100")

    class FakeCoreSource:
        def __init__(self, client: object) -> None:
            pass

        def chain_height(self) -> int:
            return tip

        def block_hash_at_height(self, height: int) -> str:
            return f"{height + 1:064x}"

        def block_at_height(self, height: int) -> CoreBlock:
            return CoreBlock(
                height=height,
                block_hash=f"{height + 1:064x}",
                previous_block_hash=(
                    f"{height:064x}" if height > 100 else None
                ),
                block_time=1_700_000_000 + height,
                transactions=(),
            )

    monkeypatch.setattr(cli, "CoreBlockSource", FakeCoreSource)


def _trace_report(*, truncated: bool = False) -> TraceReport:
    later = TraceFinding(
        kind=TraceFindingKind.LATER_TX0,
        confidence=Confidence.HIGH,
        txid="c" * 64,
        outpoints=(OutPoint("a" * 64, 2),),
        explanation="Candidate doxxic change enters another candidate Tx0.",
    )
    consolidation = TraceFinding(
        kind=TraceFindingKind.POSTMIX_CONSOLIDATION,
        confidence=Confidence.HIGH,
        txid="d" * 64,
        outpoints=(
            OutPoint("b" * 64, 0),
            OutPoint("b" * 64, 1),
        ),
        explanation="Two possible postmix descendants are co-spent.",
    )
    payment_consolidation = TraceFinding(
        kind=TraceFindingKind.POSTMIX_PAYMENT_CONSOLIDATION,
        confidence=Confidence.MEDIUM,
        txid="7" * 64,
        outpoints=(
            OutPoint("b" * 64, 0),
            OutPoint("b" * 64, 1),
            OutPoint("b" * 64, 2),
        ),
        explanation=(
            "Three possible postmix descendants create one spendable output."
        ),
        source_txids=("a" * 64,),
    )
    stonewall = TraceFinding(
        kind=TraceFindingKind.STONEWALL,
        confidence=Confidence.MEDIUM,
        txid="e" * 64,
        outpoints=(OutPoint("b" * 64, 2),),
        explanation="Four outputs contain repeated values.",
        repeated_output_values_sats=(408_297, 4_588_406),
    )
    ricochet = TraceFinding(
        kind=TraceFindingKind.RICOCHET,
        confidence=Confidence.MEDIUM,
        txid="f" * 64,
        outpoints=(OutPoint("f" * 64, 0),),
        explanation="A service fee and four serial hops were observed.",
        service_fee_sats=100_000,
        service_fee_address="bc1qexample",
        hop_txids=("1" * 64, "2" * 64, "3" * 64, "4" * 64),
    )
    payjoin = TraceFinding(
        kind=TraceFindingKind.POSTMIX_PAYJOIN_FINGERPRINT,
        confidence=Confidence.MEDIUM,
        txid="5" * 64,
        outpoints=(OutPoint("b" * 64, 0),),
        explanation=(
            "The public shape is consistent with Payjoin/Cahoots, not proof."
        ),
        payjoin_unnecessary_input_heuristic="uih1",
        payjoin_fingerprint_signals=("ecdsa_r_length",),
        payjoin_input_clusters=((0,), (1,)),
    )
    address_reuse = TraceFinding(
        kind=TraceFindingKind.ADDRESS_REUSE,
        confidence=Confidence.MEDIUM,
        txid="6" * 64,
        outpoints=(
            OutPoint("6" * 64, 0),
            OutPoint("7" * 64, 1),
        ),
        explanation="One address appears across two classified roles.",
        reused_address="bc1qreused",
        reused_roles=(
            "coordinator_fee",
            "whirlpool_coinjoin_output",
        ),
    )
    cpfp = TraceFinding(
        kind=TraceFindingKind.WHIRLPOOL_CPFP,
        confidence=Confidence.MEDIUM,
        txid="9" * 64,
        outpoints=(OutPoint("8" * 64, 0),),
        explanation="A same-block higher-fee child may raise package fees.",
        cpfp_parent_txid="8" * 64,
        cpfp_block_height=577_604,
        cpfp_parent_fee_sats=30_000,
        cpfp_parent_vsize=505,
        cpfp_child_fee_sats=15_598,
        cpfp_child_vsize=110,
        cpfp_parent_fee_rate="59.41",
        cpfp_child_fee_rate="141.80",
        cpfp_package_fee_rate="74.14",
    )
    return TraceReport(
        root_txid="a" * 64,
        nodes=(),
        edges=(),
        findings=(
            later,
            consolidation,
            payment_consolidation,
            stonewall,
            ricochet,
            payjoin,
            address_reuse,
            cpfp,
        ),
        summary=TraceSummary(
            transactions_examined=4,
            outputs_examined=20,
            whirlpool_rounds=1,
            later_tx0s=1,
            postmix_consolidations=1,
            postmix_payment_consolidations=1,
            stonewall_spends=1,
            ricochet_spends=1,
            address_reuse_findings=1,
            whirlpool_cpfp_findings=1,
            postmix_payjoin_fingerprint_candidates=1,
            possible_payments=2,
            unspent_output_count=3,
            unspent_sats=3_500_000,
        ),
        warnings=(
            ("Maximum trace depth reached; deeper spends were not followed.",)
            if truncated
            else ()
        ),
        truncated=truncated,
    )
