from __future__ import annotations

from pathlib import Path

import pytest

from dewhirlpooler.bitcoin import (
    MAX_MONEY_SATS,
    OutPoint,
    ScriptType,
    Transaction,
    TxInput,
    TxOutput,
    parse_transaction_hex,
)
from dewhirlpooler.whirlpool import (
    DEFAULT_POOLS,
    Confidence,
    OutputRole,
    PoolDefinition,
    TransactionKind,
    detect_whirlpool,
)

FIXTURES = Path(__file__).parent / "fixtures"


def _fixture(name: str) -> Transaction:
    return parse_transaction_hex((FIXTURES / name).read_text().strip())


def _role_indices(detection, role: OutputRole) -> list[int]:
    return [
        output.index
        for output in detection.outputs
        if output.role is role
    ]


def test_detects_current_ashigaru_tx0_and_roles() -> None:
    transaction = _fixture("ashigaru-tx0-0.025.hex")

    detection = detect_whirlpool(transaction)

    assert detection.kind is TransactionKind.TX0
    assert detection.confidence is Confidence.HIGH
    assert detection.pool == DEFAULT_POOLS[0]
    assert _role_indices(detection, OutputRole.OP_RETURN) == [0]
    assert _role_indices(detection, OutputRole.COORDINATOR_FEE) == [1]
    assert _role_indices(detection, OutputRole.DOXXIC_CHANGE) == [2]
    assert _role_indices(detection, OutputRole.PREMIX) == list(range(3, 12))
    assert transaction.outputs[1].value_sats == 125_000
    assert transaction.outputs[2].value_sats == 2_481_116
    assert {transaction.outputs[index].value_sats for index in range(3, 12)} == {
        2_500_605
    }
    assert detection.input_count is None
    assert detection.input_value_sats is None
    assert detection.miner_fee_sats is None
    assert detection.coordinator_fee_sats == 125_000
    assert detection.premix_output_count == 9
    assert detection.entered_pool_sats == 22_500_000
    assert detection.total_fee_cost_sats is None
    assert detection.fee_cost_percent is None


def test_tx0_accounting_uses_resolved_prevouts_exactly() -> None:
    transaction = _fixture("ashigaru-tx0-0.025.hex")
    output_total = sum(output.value_sats for output in transaction.outputs)
    prevouts = _tx0_prevouts(transaction, output_total + 15_000)

    detection = detect_whirlpool(transaction, prevouts)

    assert detection.kind is TransactionKind.TX0
    assert detection.input_count == len(transaction.inputs)
    assert detection.input_value_sats == output_total + 15_000
    assert detection.miner_fee_sats == 15_000
    assert detection.coordinator_fee_sats == 125_000
    assert detection.premix_output_count == 9
    assert detection.entered_pool_sats == 22_500_000
    assert detection.total_fee_cost_sats == 140_000
    assert detection.fee_cost_percent == "0.6222"


def test_tx0_rejects_negative_fee_and_partial_prevout_map() -> None:
    transaction = _fixture("ashigaru-tx0-0.025.hex")
    output_total = sum(output.value_sats for output in transaction.outputs)
    negative_fee = _tx0_prevouts(transaction, output_total - 1)

    assert (
        detect_whirlpool(transaction, negative_fee).kind
        is TransactionKind.UNKNOWN
    )

    if len(transaction.inputs) > 1:
        partial = dict(list(negative_fee.items())[:-1])
    else:
        partial = {
            OutPoint("f" * 64, 0): TxOutput(
                index=0,
                value_sats=output_total,
                script_pubkey=b"\x00\x14" + b"\x99" * 20,
                script_type=ScriptType.P2WPKH,
            )
        }
    assert detect_whirlpool(transaction, partial).kind is TransactionKind.UNKNOWN


def test_tx0_rejects_input_total_above_max_money() -> None:
    transaction = _fixture("ashigaru-tx0-0.025.hex")
    prevouts = _tx0_prevouts(transaction, MAX_MONEY_SATS + 1)

    assert detect_whirlpool(transaction, prevouts).kind is TransactionKind.UNKNOWN


def test_detects_legacy_public_tx0() -> None:
    transaction = _fixture("legacy-tx0-0.05.hex")

    detection = detect_whirlpool(transaction)

    assert detection.kind is TransactionKind.TX0
    assert detection.confidence is Confidence.HIGH
    assert detection.pool == DEFAULT_POOLS[2]
    assert len(_role_indices(detection, OutputRole.PREMIX)) == 70
    assert _role_indices(detection, OutputRole.COORDINATOR_FEE) == [1]
    assert _role_indices(detection, OutputRole.DOXXIC_CHANGE) == [72]
    assert transaction.outputs[1].value_sats == 175_000
    assert transaction.outputs[72].value_sats == 31_400_733


def test_default_pools_cover_legacy_denominations_and_fee_eras() -> None:
    legacy = {
        pool.denomination_sats: pool
        for pool in DEFAULT_POOLS
        if pool.protocol == "Samourai legacy"
    }

    assert set(legacy) == {
        100_000,
        1_000_000,
        5_000_000,
        50_000_000,
    }
    assert legacy[100_000].documented_coordinator_fees_sats == (
        5_000,
    )
    assert legacy[1_000_000].documented_coordinator_fees_sats == (
        50_000,
    )
    assert legacy[5_000_000].documented_coordinator_fees_sats == (
        175_000,
        250_000,
    )
    assert legacy[50_000_000].documented_coordinator_fees_sats == (
        1_750_000,
        2_500_000,
    )


@pytest.mark.parametrize(
    ("pool_id", "coordinator_fee_sats"),
    [
        ("samourai-legacy-0.001", 5_000),
        ("samourai-legacy-0.01", 50_000),
        ("samourai-legacy-0.05", 175_000),
        ("samourai-legacy-0.05", 250_000),
        ("samourai-legacy-0.5", 1_750_000),
        ("samourai-legacy-0.5", 2_500_000),
    ],
)
def test_detects_documented_legacy_pool_fee_schedules(
    pool_id: str,
    coordinator_fee_sats: int,
) -> None:
    pool = next(
        item for item in DEFAULT_POOLS if item.identifier == pool_id
    )
    transaction = _synthetic_tx0(
        pool,
        coordinator_fee_sats=coordinator_fee_sats,
    )

    detection = detect_whirlpool(transaction)

    assert detection.kind is TransactionKind.TX0
    assert detection.confidence is Confidence.HIGH
    assert detection.pool == pool
    assert detection.coordinator_fee_sats == coordinator_fee_sats
    assert detection.premix_output_count == 5
    assert detection.entered_pool_sats == (
        5 * pool.denomination_sats
    )
    assert _role_indices(detection, OutputRole.COORDINATOR_FEE) == [1]


def test_round_is_medium_confidence_without_prevouts() -> None:
    transaction = _fixture("ashigaru-round-0.025.hex")

    detection = detect_whirlpool(transaction)

    assert detection.kind is TransactionKind.WHIRLPOOL_ROUND
    assert detection.confidence is Confidence.MEDIUM
    assert len(_role_indices(detection, OutputRole.COINJOIN)) == 5
    assert detection.round_size == 5
    assert detection.input_count is None
    assert detection.miner_fee_sats is None
    assert detection.warnings


def test_round_is_high_confidence_with_two_premix_and_three_remix_inputs() -> None:
    transaction = _fixture("ashigaru-round-0.025.hex")
    prevouts = _round_prevouts(transaction, [2_500_605] * 2 + [2_500_000] * 3)

    detection = detect_whirlpool(transaction, prevouts)

    assert detection.kind is TransactionKind.WHIRLPOOL_ROUND
    assert detection.confidence is Confidence.HIGH
    assert detection.premix_input_count == 2
    assert detection.remix_input_count == 3
    assert detection.input_count == 5
    assert detection.input_value_sats == 12_501_210
    assert detection.miner_fee_sats == 1_210
    assert detection.round_size == 5
    assert detection.warnings == ()


@pytest.mark.parametrize("round_size", [5, 6, 7, 8])
def test_detects_variable_size_rounds(round_size: int) -> None:
    transaction = _variable_round(round_size)
    premix_count = 2
    values = [2_500_605] * premix_count + [2_500_000] * (
        round_size - premix_count
    )

    detection = detect_whirlpool(
        transaction,
        _round_prevouts(transaction, values),
    )

    assert detection.kind is TransactionKind.WHIRLPOOL_ROUND
    assert detection.confidence is Confidence.HIGH
    assert detection.round_size == round_size
    assert detection.premix_input_count == premix_count
    assert detection.remix_input_count == round_size - premix_count
    assert detection.miner_fee_sats == premix_count * 605
    assert detection.evidence[0].code == "equal_denomination_round"
    assert f"{round_size} inputs and {round_size}" in detection.evidence[0].description
    assert {
        code
        for output in detection.outputs
        for code in output.evidence_codes
    } == {"equal_denomination_round"}


@pytest.mark.parametrize("round_size", [4, 9])
def test_rejects_out_of_range_round_sizes(round_size: int) -> None:
    assert (
        detect_whirlpool(_variable_round(round_size)).kind
        is TransactionKind.UNKNOWN
    )


def test_rejects_mismatched_round_input_output_counts() -> None:
    transaction = _variable_round(6)
    modified = _replace_transaction(
        transaction,
        inputs=transaction.inputs[:-1],
    )

    assert detect_whirlpool(modified).kind is TransactionKind.UNKNOWN


def test_round_rejects_implausible_prevout_value() -> None:
    transaction = _fixture("ashigaru-round-0.025.hex")
    prevouts = _round_prevouts(transaction, [2_500_605] * 4 + [2_700_000])

    detection = detect_whirlpool(transaction, prevouts)

    assert detection.kind is TransactionKind.UNKNOWN


def test_round_rejects_mixed_output_script_types() -> None:
    transaction = _fixture("ashigaru-round-0.025.hex")
    outputs = list(transaction.outputs)
    outputs[0] = TxOutput(
        index=0,
        value_sats=2_500_000,
        script_pubkey=b"\x51\x20" + b"\x11" * 32,
        script_type=ScriptType.P2TR,
    )
    modified = _replace_outputs(transaction, tuple(outputs))

    detection = detect_whirlpool(modified)

    assert detection.kind is TransactionKind.UNKNOWN


def test_equal_output_batch_without_tx0_signals_is_unknown() -> None:
    transaction = _fixture("ashigaru-tx0-0.025.hex")
    outputs = tuple(
        TxOutput(
            index=index,
            value_sats=2_500_605,
            script_pubkey=b"\x00\x14" + bytes((index,)) * 20,
            script_type=ScriptType.P2WPKH,
        )
        for index in range(2)
    )

    detection = detect_whirlpool(_replace_outputs(transaction, outputs))

    assert detection.kind is TransactionKind.UNKNOWN


def test_multiple_residual_tx0_outputs_lower_confidence() -> None:
    transaction = _fixture("ashigaru-tx0-0.025.hex")
    extra_output = TxOutput(
        index=len(transaction.outputs),
        value_sats=50_000,
        script_pubkey=b"\x00\x14" + b"\x44" * 20,
        script_type=ScriptType.P2WPKH,
    )
    modified = _replace_outputs(
        transaction,
        transaction.outputs + (extra_output,),
    )

    detection = detect_whirlpool(modified)

    assert detection.kind is TransactionKind.TX0
    assert detection.confidence is Confidence.MEDIUM
    assert not _role_indices(detection, OutputRole.DOXXIC_CHANGE)
    assert detection.warnings


def test_ordinary_single_payment_is_unknown() -> None:
    transaction = _fixture("ashigaru-tx0-0.025.hex")
    outputs = (
        TxOutput(
            index=0,
            value_sats=84_000,
            script_pubkey=b"\x51\x20" + b"\x22" * 32,
            script_type=ScriptType.P2TR,
        ),
    )

    detection = detect_whirlpool(_replace_outputs(transaction, outputs))

    assert detection.kind is TransactionKind.UNKNOWN


def test_ambiguous_pool_match_returns_unknown() -> None:
    transaction = _fixture("ashigaru-tx0-0.025.hex")
    duplicate = PoolDefinition(
        identifier="duplicate",
        protocol="Test",
        denomination_sats=2_500_000,
        coordinator_fee_sats=125_000,
        max_premix_outputs=20,
        max_premix_reserve_sats=100_000,
    )

    detection = detect_whirlpool(
        transaction,
        pools=(DEFAULT_POOLS[0], duplicate),
    )

    assert detection.kind is TransactionKind.UNKNOWN
    assert "More than one pool" in detection.warnings[0]


def _round_prevouts(
    transaction: Transaction,
    values: list[int],
) -> dict[OutPoint, TxOutput]:
    return {
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


def _tx0_prevouts(
    transaction: Transaction,
    total_value_sats: int,
) -> dict[OutPoint, TxOutput]:
    values = [0] * len(transaction.inputs)
    values[0] = total_value_sats
    return {
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


def _variable_round(round_size: int) -> Transaction:
    template = _fixture("ashigaru-round-0.025.hex")
    inputs = tuple(
        TxInput(
            previous_output=OutPoint(f"{position + 1:064x}", position),
            script_sig=b"",
            sequence=0xFFFFFFFD,
            witness=(),
        )
        for position in range(round_size)
    )
    outputs = tuple(
        TxOutput(
            index=position,
            value_sats=2_500_000,
            script_pubkey=b"\x00\x14" + bytes((position + 1,)) * 20,
            script_type=ScriptType.P2WPKH,
        )
        for position in range(round_size)
    )
    return _replace_transaction(template, inputs=inputs, outputs=outputs)


def _synthetic_tx0(
    pool: PoolDefinition,
    *,
    coordinator_fee_sats: int,
) -> Transaction:
    template = _fixture("legacy-tx0-0.05.hex")
    outputs = (
        template.outputs[0],
        TxOutput(
            index=1,
            value_sats=coordinator_fee_sats,
            script_pubkey=b"\x00\x14" + b"\x81" * 20,
            script_type=ScriptType.P2WPKH,
        ),
        TxOutput(
            index=2,
            value_sats=pool.denomination_sats // 2 + 123,
            script_pubkey=b"\x00\x14" + b"\x82" * 20,
            script_type=ScriptType.P2WPKH,
        ),
        *(
            TxOutput(
                index=index,
                value_sats=pool.denomination_sats + 1_000,
                script_pubkey=b"\x00\x14" + bytes((index,)) * 20,
                script_type=ScriptType.P2WPKH,
            )
            for index in range(3, 8)
        ),
    )
    return _replace_transaction(template, outputs=outputs)


def _replace_outputs(
    transaction: Transaction,
    outputs: tuple[TxOutput, ...],
) -> Transaction:
    return _replace_transaction(transaction, outputs=outputs)


def _replace_transaction(
    transaction: Transaction,
    *,
    inputs: tuple[TxInput, ...] | None = None,
    outputs: tuple[TxOutput, ...] | None = None,
) -> Transaction:
    return Transaction(
        version=transaction.version,
        inputs=inputs if inputs is not None else transaction.inputs,
        outputs=outputs if outputs is not None else transaction.outputs,
        lock_time=transaction.lock_time,
        has_witness=transaction.has_witness,
        txid=transaction.txid,
        wtxid=transaction.wtxid,
        size=transaction.size,
        weight=transaction.weight,
        vsize=transaction.vsize,
    )
