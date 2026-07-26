from __future__ import annotations

from dataclasses import replace
from pathlib import Path

import pytest

from dewhirlpooler.bitcoin import (
    MAX_MONEY_SATS,
    OutPoint,
    ScriptType,
    Transaction,
    TxInput,
    TxOutput,
    encode_p2wpkh_address,
    parse_transaction_hex,
)
from dewhirlpooler.postmix import (
    RICOCHET_SERVICE_FEE_SATS,
    detect_payjoin_fingerprints,
    detect_ricochet_entry,
    detect_ricochet_hop,
    detect_stonewall,
    detect_whirlpool_cpfp,
)
from dewhirlpooler.whirlpool import Confidence

FIXTURES = Path(__file__).parent / "fixtures"


def _fixture(name: str) -> Transaction:
    return parse_transaction_hex((FIXTURES / name).read_text().strip())


def test_detects_public_mainnet_stonewall_shape() -> None:
    transaction = _fixture("stonewall-mainnet.hex")
    parent_a = _fixture("stonewall-mainnet-parent-a.hex")
    parent_b = _fixture("stonewall-mainnet-parent-b.hex")
    prevouts = {
        transaction.inputs[0].previous_output: parent_a.outputs[3],
        transaction.inputs[1].previous_output: parent_b.outputs[0],
    }

    detection = detect_stonewall(
        transaction,
        prevouts,
        tracked_postmix_inputs=(transaction.inputs[0].previous_output,),
    )

    assert detection is not None
    assert detection.confidence is Confidence.MEDIUM
    assert detection.tracked_postmix_inputs == (
        transaction.inputs[0].previous_output,
    )
    assert detection.repeated_output_values_sats == (408_297, 4_588_406)
    assert detection.repeated_output_indices == ((0, 1), (2, 3))
    assert detection.input_count == 2
    assert detection.input_value_sats == 10_000_000
    assert detection.miner_fee_sats == 6_594


def test_detects_public_samourai_testnet_payjoin_fingerprints() -> None:
    transaction = _fixture("payjoin-samourai-testnet.hex")
    parent_a = _fixture("payjoin-samourai-testnet-parent-a.hex")
    parent_b = _fixture("payjoin-samourai-testnet-parent-b.hex")
    assert transaction.txid == (
        "8dba6657ab9bb44824b3317c8cc3f333"
        "c2f465d3668c678691a091cdd6e5984c"
    )
    assert parent_a.txid == (
        "4c18c8880f70b34fb5fc693921fe35a4"
        "0e355bdc297526452dee9cd9ac29c7fb"
    )
    assert parent_b.txid == (
        "d0bbde77cd404773ef7f94a960332888"
        "83eb2dac2bc1b5ac6cfb36484c8c028d"
    )
    prevouts = {
        transaction.inputs[0].previous_output: parent_a.outputs[1],
        transaction.inputs[1].previous_output: parent_b.outputs[2],
    }

    detection = detect_payjoin_fingerprints(
        transaction,
        prevouts,
        tracked_postmix_inputs=(transaction.inputs[0].previous_output,),
    )

    assert detection is not None
    assert detection.confidence is Confidence.MEDIUM
    assert tuple(output.value_sats for output in prevouts.values()) == (
        50_000,
        3_999_216,
    )
    assert tuple(output.value_sats for output in transaction.outputs) == (
        9_752,
        4_039_216,
    )
    assert detection.input_value_sats == 4_049_216
    assert detection.miner_fee_sats == 248
    assert detection.unnecessary_input_heuristic == "uih1"
    assert detection.fingerprint_signals == ("ecdsa_r_length",)
    assert detection.input_clusters == ((0,), (1,))
    assert detection.tracked_postmix_inputs == (
        transaction.inputs[0].previous_output,
    )
    assert detection.other_inputs == (
        transaction.inputs[1].previous_output,
    )


def test_payjoin_requires_mixed_tracked_inputs() -> None:
    transaction, prevouts = _payjoin_fixture()
    all_inputs = tuple(
        transaction_input.previous_output
        for transaction_input in transaction.inputs
    )

    assert detect_payjoin_fingerprints(transaction, prevouts) is None
    assert (
        detect_payjoin_fingerprints(
            transaction,
            prevouts,
            tracked_postmix_inputs=all_inputs,
        )
        is None
    )


def test_payjoin_rejects_incomplete_extra_and_invalid_accounting() -> None:
    transaction, prevouts = _payjoin_fixture()
    tracked = (transaction.inputs[0].previous_output,)
    first_outpoint = transaction.inputs[0].previous_output
    extra = {
        **prevouts,
        OutPoint("e" * 64, 0): next(iter(prevouts.values())),
    }
    zero_input = {
        **prevouts,
        first_outpoint: replace(prevouts[first_outpoint], value_sats=0),
    }
    over_max_input = {
        **prevouts,
        first_outpoint: replace(
            prevouts[first_outpoint],
            value_sats=MAX_MONEY_SATS + 1,
        ),
    }
    invalid_outputs = tuple(
        replace(output, value_sats=3_000_000)
        for output in transaction.outputs
    )

    for candidate, candidate_prevouts in (
        (transaction, {first_outpoint: prevouts[first_outpoint]}),
        (transaction, extra),
        (transaction, zero_input),
        (transaction, over_max_input),
        (replace(transaction, outputs=invalid_outputs), prevouts),
    ):
        assert (
            detect_payjoin_fingerprints(
                candidate,
                candidate_prevouts,
                tracked_postmix_inputs=tracked,
            )
            is None
        )


def test_payjoin_rejects_duplicate_coinbase_and_same_parent_inputs() -> None:
    transaction, prevouts = _payjoin_fixture()
    tracked = (transaction.inputs[0].previous_output,)
    duplicate = replace(
        transaction,
        inputs=(transaction.inputs[0], transaction.inputs[0]),
    )
    coinbase_input = replace(
        transaction.inputs[1],
        previous_output=OutPoint("0" * 64, 0xFFFFFFFF),
    )
    coinbase = replace(
        transaction,
        inputs=(transaction.inputs[0], coinbase_input),
    )
    same_parent_input = replace(
        transaction.inputs[1],
        previous_output=OutPoint(
            transaction.inputs[0].previous_output.txid,
            1,
        ),
    )
    same_parent = replace(
        transaction,
        inputs=(transaction.inputs[0], same_parent_input),
    )
    coinbase_prevouts = {
        transaction.inputs[0].previous_output: next(iter(prevouts.values())),
        coinbase_input.previous_output: next(iter(prevouts.values())),
    }
    same_parent_prevouts = {
        transaction.inputs[0].previous_output: next(iter(prevouts.values())),
        same_parent_input.previous_output: next(iter(prevouts.values())),
    }

    for candidate, candidate_prevouts in (
        (
            duplicate,
            {
                transaction.inputs[0].previous_output: next(
                    iter(prevouts.values())
                )
            },
        ),
        (coinbase, coinbase_prevouts),
        (same_parent, same_parent_prevouts),
    ):
        assert (
            detect_payjoin_fingerprints(
                candidate,
                candidate_prevouts,
                tracked_postmix_inputs=tracked,
            )
            is None
        )


@pytest.mark.parametrize(
    "outputs",
    [
        (TxOutput(0, 9_000, b"\x00\x14" + b"\x01" * 20, ScriptType.P2WPKH),),
        tuple(
            TxOutput(
                index,
                3_000,
                b"\x00\x14" + bytes((index + 1,)) * 20,
                ScriptType.P2WPKH,
            )
            for index in range(3)
        ),
        (
            TxOutput(0, 4_900, b"\x6a\x01\x01", ScriptType.OP_RETURN),
            TxOutput(1, 5_000, b"\x00\x14" + b"\x02" * 20, ScriptType.P2WPKH),
        ),
        (
            TxOutput(0, 4_900, b"\x51", ScriptType.UNKNOWN),
            TxOutput(1, 5_000, b"\x00\x14" + b"\x02" * 20, ScriptType.P2WPKH),
        ),
        (
            TxOutput(0, 0, b"\x00\x14" + b"\x01" * 20, ScriptType.P2WPKH),
            TxOutput(1, 9_900, b"\x00\x14" + b"\x02" * 20, ScriptType.P2WPKH),
        ),
        (
            TxOutput(0, 4_900, b"\x51", ScriptType.P2WPKH),
            TxOutput(1, 5_000, b"\x00\x14" + b"\x02" * 20, ScriptType.P2WPKH),
        ),
    ],
)
def test_payjoin_rejects_nonstandard_output_shapes(
    outputs: tuple[TxOutput, ...],
) -> None:
    transaction, prevouts = _fingerprint_spend()

    assert (
        detect_payjoin_fingerprints(
            replace(transaction, outputs=outputs),
            prevouts,
            tracked_postmix_inputs=(transaction.inputs[0].previous_output,),
        )
        is None
    )


def test_payjoin_rejects_normal_two_output_spend_without_evidence() -> None:
    transaction, prevouts = _fingerprint_spend()

    assert (
        detect_payjoin_fingerprints(
            transaction,
            prevouts,
            tracked_postmix_inputs=(transaction.inputs[0].previous_output,),
        )
        is None
    )


def test_payjoin_confidence_rules() -> None:
    fixture_transaction, fixture_prevouts = _payjoin_fixture()
    homogeneous = replace(
        fixture_transaction,
        inputs=(
            fixture_transaction.inputs[0],
            replace(
                fixture_transaction.inputs[1],
                witness=fixture_transaction.inputs[0].witness,
            ),
        ),
    )
    uih1_only = detect_payjoin_fingerprints(
        homogeneous,
        fixture_prevouts,
        tracked_postmix_inputs=(
            homogeneous.inputs[0].previous_output,
        ),
    )
    assert uih1_only is not None
    assert uih1_only.confidence is Confidence.LOW
    assert uih1_only.input_clusters == ((0, 1),)

    balanced, balanced_prevouts = _fingerprint_spend()
    fingerprint_only = detect_payjoin_fingerprints(
        replace(
            balanced,
            inputs=(
                balanced.inputs[0],
                replace(balanced.inputs[1], sequence=0xFFFFFFFE),
            ),
        ),
        balanced_prevouts,
        tracked_postmix_inputs=(balanced.inputs[0].previous_output,),
    )
    assert fingerprint_only is not None
    assert fingerprint_only.unnecessary_input_heuristic is None
    assert fingerprint_only.fingerprint_signals == ("sequence",)
    assert fingerprint_only.confidence is Confidence.LOW

    uih2_transaction = replace(
        balanced,
        outputs=(
            replace(balanced.outputs[0], value_sats=3_000),
            replace(balanced.outputs[1], value_sats=6_900),
        ),
    )
    uih2_prevouts = {
        balanced.inputs[0].previous_output: replace(
            balanced_prevouts[balanced.inputs[0].previous_output],
            value_sats=8_000,
        ),
        balanced.inputs[1].previous_output: replace(
            balanced_prevouts[balanced.inputs[1].previous_output],
            value_sats=2_000,
        ),
    }
    uih2 = detect_payjoin_fingerprints(
        uih2_transaction,
        uih2_prevouts,
        tracked_postmix_inputs=(balanced.inputs[0].previous_output,),
    )
    assert uih2 is not None
    assert uih2.unnecessary_input_heuristic == "uih2"
    assert uih2.confidence is Confidence.MEDIUM

    two_fingerprints = detect_payjoin_fingerprints(
        replace(
            balanced,
            inputs=(
                replace(
                    balanced.inputs[0],
                    witness=(_ecdsa_signature(32), b"\x02" * 33),
                ),
                replace(
                    balanced.inputs[1],
                    sequence=0xFFFFFFFE,
                    witness=(_ecdsa_signature(33), b"\x03" * 33),
                ),
            ),
        ),
        balanced_prevouts,
        tracked_postmix_inputs=(balanced.inputs[0].previous_output,),
    )
    assert two_fingerprints is not None
    assert two_fingerprints.unnecessary_input_heuristic is None
    assert two_fingerprints.fingerprint_signals == (
        "sequence",
        "ecdsa_r_length",
    )
    assert two_fingerprints.confidence is Confidence.MEDIUM


def test_payjoin_reports_prevout_script_and_ecdsa_sighash_dimensions() -> None:
    transaction, prevouts = _fingerprint_spend()
    second_outpoint = transaction.inputs[1].previous_output
    mixed_scripts = {
        **prevouts,
        second_outpoint: replace(
            prevouts[second_outpoint],
            script_pubkey=b"\x51\x20" + b"\x44" * 32,
            script_type=ScriptType.P2TR,
        ),
    }
    script_detection = detect_payjoin_fingerprints(
        transaction,
        mixed_scripts,
        tracked_postmix_inputs=(transaction.inputs[0].previous_output,),
    )
    assert script_detection is not None
    assert script_detection.fingerprint_signals == (
        "prevout_script_type",
    )

    sighash_transaction = replace(
        transaction,
        inputs=(
            replace(
                transaction.inputs[0],
                witness=(_ecdsa_signature(32, 1), b"\x02" * 33),
            ),
            replace(
                transaction.inputs[1],
                witness=(_ecdsa_signature(32, 0x81), b"\x03" * 33),
            ),
        ),
    )
    sighash_detection = detect_payjoin_fingerprints(
        sighash_transaction,
        prevouts,
        tracked_postmix_inputs=(
            sighash_transaction.inputs[0].previous_output,
        ),
    )
    assert sighash_detection is not None
    assert sighash_detection.fingerprint_signals == ("ecdsa_sighash",)
    assert sighash_detection.input_clusters == ((0,), (1,))


def test_payjoin_ignores_incomplete_or_malformed_ecdsa_evidence() -> None:
    transaction, prevouts = _fingerprint_spend()
    valid = (_ecdsa_signature(32), b"\x02" * 33)
    malformed = (b"\x30\x05\x02\x01\x01\x02\x01\x01\x01", b"\x03" * 33)
    partial = replace(
        transaction,
        inputs=(
            replace(transaction.inputs[0], witness=valid),
            transaction.inputs[1],
        ),
    )
    malformed_pair = replace(
        transaction,
        inputs=(
            replace(transaction.inputs[0], witness=valid),
            replace(transaction.inputs[1], witness=malformed),
        ),
    )

    for candidate in (partial, malformed_pair):
        assert (
            detect_payjoin_fingerprints(
                candidate,
                prevouts,
                tracked_postmix_inputs=(
                    candidate.inputs[0].previous_output,
                ),
            )
            is None
        )

    homogeneous = replace(
        transaction,
        inputs=tuple(
            replace(transaction_input, witness=valid)
            for transaction_input in transaction.inputs
        ),
    )
    assert (
        detect_payjoin_fingerprints(
            homogeneous,
            prevouts,
            tracked_postmix_inputs=(homogeneous.inputs[0].previous_output,),
        )
        is None
    )


def test_payjoin_taproot_keypath_forms_and_script_path_rejection() -> None:
    transaction, prevouts = _fingerprint_spend(
        script_type=ScriptType.P2TR
    )
    keypath = replace(
        transaction,
        inputs=(
            replace(transaction.inputs[0], witness=(b"\x11" * 64,)),
            replace(
                transaction.inputs[1],
                witness=(b"\x22" * 64 + b"\x01",),
            ),
        ),
    )
    detection = detect_payjoin_fingerprints(
        keypath,
        prevouts,
        tracked_postmix_inputs=(keypath.inputs[0].previous_output,),
    )
    assert detection is not None
    assert detection.fingerprint_signals == ("taproot_sighash_form",)
    assert detection.input_clusters == ((0,), (1,))
    assert detection.confidence is Confidence.LOW

    script_path = replace(
        keypath,
        inputs=(
            keypath.inputs[0],
            replace(
                keypath.inputs[1],
                witness=(b"\x22" * 64, b"\x51", b"\xc0" + b"\x33" * 32),
            ),
        ),
    )
    assert (
        detect_payjoin_fingerprints(
            script_path,
            prevouts,
            tracked_postmix_inputs=(script_path.inputs[0].previous_output,),
        )
        is None
    )


def test_payjoin_cluster_order_is_deterministic() -> None:
    transaction, prevouts = _fingerprint_spend(input_count=3)
    transaction = replace(
        transaction,
        inputs=(
            replace(transaction.inputs[0], sequence=1),
            replace(transaction.inputs[1], sequence=2),
            replace(transaction.inputs[2], sequence=1),
        ),
    )

    detection = detect_payjoin_fingerprints(
        transaction,
        prevouts,
        tracked_postmix_inputs=(transaction.inputs[0].previous_output,),
    )

    assert detection is not None
    assert detection.input_clusters == ((0, 2), (1,))


def test_detects_public_testnet_ricochet_entry_and_four_hops() -> None:
    entry_transaction = _fixture("ricochet-testnet-entry.hex")
    hop_transactions = tuple(
        _fixture(f"ricochet-testnet-hop-{position}.hex")
        for position in range(1, 5)
    )

    entry = detect_ricochet_entry(
        entry_transaction,
        tracked_postmix_inputs=(
            entry_transaction.inputs[0].previous_output,
        ),
    )

    assert entry is not None
    assert entry.confidence is Confidence.MEDIUM
    assert entry.fee_outpoint == OutPoint(entry_transaction.txid, 0)
    assert entry.fee_output.value_sats == RICOCHET_SERVICE_FEE_SATS
    assert entry.continuation_candidates == (
        OutPoint(entry_transaction.txid, 1),
        OutPoint(entry_transaction.txid, 2),
    )
    assert (
        encode_p2wpkh_address(
            entry.fee_output.script_pubkey,
            network="testnet",
        )
        == "tb1q740ynw2jj83gak0q38ktfkl65kwkata0jqlsj6"
    )

    expected_outpoint = OutPoint(entry_transaction.txid, 2)
    previous_output = entry_transaction.outputs[2]
    hop_txids: list[str] = []
    for transaction in hop_transactions:
        hop = detect_ricochet_hop(
            transaction,
            expected_input=expected_outpoint,
            previous_output=previous_output,
        )
        assert hop is not None
        assert hop.miner_fee_sats == 202
        hop_txids.append(hop.txid)
        expected_outpoint = hop.output_outpoint
        previous_output = hop.output

    assert hop_txids == [
        "68058a625adf7c9fabaf8b690490b3b6ffdf844abca2db785a5445014095d2ef",
        "def5aa171c67da36b87fc3f191ac994639cf2b3ef5fab4cc5ad7fa943ac250da",
        "36e100bbe053e9e8533d4f0f6d29d92887f53ae1e5735e2a3e5f1e5eadcc8ff9",
        "dd13e8d79a0b5ae43b610b14d31c72e709fbaf43b4c54c611122be4e54fa0eaf",
    ]
    assert previous_output.value_sats == 420_000


def test_detects_same_block_higher_fee_whirlpool_child() -> None:
    parent, parent_prevouts, child, child_prevouts, tracked = (
        _cpfp_transactions()
    )

    detection = detect_whirlpool_cpfp(
        parent,
        parent_prevouts,
        child,
        child_prevouts,
        tracked_parent_outpoints=(tracked,),
        parent_height=577_604,
        child_height=577_604,
        parent_is_whirlpool_round=True,
    )

    assert detection is not None
    assert detection.confidence is Confidence.MEDIUM
    assert detection.parent_txid == parent.txid
    assert detection.child_txid == child.txid
    assert detection.block_height == 577_604
    assert detection.tracked_parent_outpoints == (tracked,)
    assert detection.parent_fee_sats == 5_000
    assert detection.parent_vsize == 200
    assert detection.child_fee_sats == 10_000
    assert detection.child_vsize == 100
    assert detection.parent_fee_rate == "25.00"
    assert detection.child_fee_rate == "100.00"
    assert detection.package_fee_rate == "50.00"


@pytest.mark.parametrize(
    ("parent_height", "child_height"),
    [
        (None, 577_604),
        (577_604, None),
        (0, 577_604),
        (-1, 577_604),
        (577_603, 577_604),
    ],
)
def test_cpfp_rejects_missing_unconfirmed_or_different_heights(
    parent_height: int | None,
    child_height: int | None,
) -> None:
    parent, parent_prevouts, child, child_prevouts, tracked = (
        _cpfp_transactions()
    )

    assert (
        detect_whirlpool_cpfp(
            parent,
            parent_prevouts,
            child,
            child_prevouts,
            tracked_parent_outpoints=(tracked,),
            parent_height=parent_height,
            child_height=child_height,
            parent_is_whirlpool_round=True,
        )
        is None
    )


def test_cpfp_rejects_incomplete_or_invalid_accounting() -> None:
    parent, parent_prevouts, child, child_prevouts, tracked = (
        _cpfp_transactions()
    )
    too_small = {
        tracked: replace(child_prevouts[tracked], value_sats=1),
    }

    for incomplete_parent, invalid_child in (
        ({}, child_prevouts),
        (parent_prevouts, {}),
        (parent_prevouts, too_small),
    ):
        assert (
            detect_whirlpool_cpfp(
                parent,
                incomplete_parent,
                child,
                invalid_child,
                tracked_parent_outpoints=(tracked,),
                parent_height=577_604,
                child_height=577_604,
                parent_is_whirlpool_round=True,
            )
            is None
        )


def test_cpfp_rejects_nonround_untracked_and_nonlifting_child() -> None:
    parent, parent_prevouts, child, child_prevouts, tracked = (
        _cpfp_transactions()
    )
    low_fee_child = replace(
        child,
        outputs=(
            replace(child.outputs[0], value_sats=39_000),
        ),
    )

    for is_round, tracked_outpoints, candidate in (
        (False, (tracked,), child),
        (True, (), child),
        (True, (OutPoint(parent.txid, 1),), child),
        (True, (tracked,), low_fee_child),
    ):
        assert (
            detect_whirlpool_cpfp(
                parent,
                parent_prevouts,
                candidate,
                child_prevouts,
                tracked_parent_outpoints=tracked_outpoints,
                parent_height=577_604,
                child_height=577_604,
                parent_is_whirlpool_round=is_round,
            )
            is None
        )


def test_stonewall_requires_tracked_postmix_and_complete_prevouts() -> None:
    transaction = _fixture("stonewall-mainnet.hex")
    parent_a = _fixture("stonewall-mainnet-parent-a.hex")
    parent_b = _fixture("stonewall-mainnet-parent-b.hex")
    prevouts = {
        transaction.inputs[0].previous_output: parent_a.outputs[3],
        transaction.inputs[1].previous_output: parent_b.outputs[0],
    }

    assert detect_stonewall(transaction, prevouts) is None
    assert (
        detect_stonewall(
            transaction,
            {transaction.inputs[0].previous_output: parent_a.outputs[3]},
            tracked_postmix_inputs=(
                transaction.inputs[0].previous_output,
            ),
        )
        is None
    )


@pytest.mark.parametrize(
    "output_values",
    [
        (1, 2, 3, 4),
        (1, 1, 1, 2),
        (1, 1, 1, 1),
        (0, 1, 1, 2),
    ],
)
def test_stonewall_rejects_invalid_output_shapes(
    output_values: tuple[int, int, int, int],
) -> None:
    transaction, prevouts = _synthetic_spend(output_values)

    assert (
        detect_stonewall(
            transaction,
            prevouts,
            tracked_postmix_inputs=(
                transaction.inputs[0].previous_output,
            ),
        )
        is None
    )


def test_stonewall_rejects_same_parent_and_negative_fee() -> None:
    transaction, prevouts = _synthetic_spend((100, 100, 200, 300))
    same_parent = replace(
        transaction,
        inputs=(
            transaction.inputs[0],
            replace(
                transaction.inputs[1],
                previous_output=OutPoint(
                    transaction.inputs[0].previous_output.txid,
                    1,
                ),
            ),
        ),
    )
    same_parent_prevouts = {
        same_parent.inputs[0].previous_output: next(iter(prevouts.values())),
        same_parent.inputs[1].previous_output: next(iter(prevouts.values())),
    }
    assert (
        detect_stonewall(
            same_parent,
            same_parent_prevouts,
            tracked_postmix_inputs=(
                same_parent.inputs[0].previous_output,
            ),
        )
        is None
    )

    too_small = {
        outpoint: replace(output, value_sats=100)
        for outpoint, output in prevouts.items()
    }
    assert (
        detect_stonewall(
            transaction,
            too_small,
            tracked_postmix_inputs=(
                transaction.inputs[0].previous_output,
            ),
        )
        is None
    )


def test_ricochet_entry_rejects_missing_ancestry_fee_and_native_outputs() -> None:
    entry = _fixture("ricochet-testnet-entry.hex")
    tracked = (entry.inputs[0].previous_output,)

    assert detect_ricochet_entry(entry) is None

    wrong_fee_outputs = tuple(
        replace(output, value_sats=99_999 if output.index == 0 else output.value_sats)
        for output in entry.outputs
    )
    assert (
        detect_ricochet_entry(
            replace(entry, outputs=wrong_fee_outputs),
            tracked_postmix_inputs=tracked,
        )
        is None
    )

    duplicate_fee_outputs = tuple(
        replace(output, value_sats=100_000)
        if output.index in {0, 1}
        else output
        for output in entry.outputs
    )
    assert (
        detect_ricochet_entry(
            replace(entry, outputs=duplicate_fee_outputs),
            tracked_postmix_inputs=tracked,
        )
        is None
    )

    non_native_outputs = tuple(
        replace(
            output,
            script_pubkey=b"\x76\xa9\x14" + b"\x11" * 20 + b"\x88\xac",
            script_type=ScriptType.P2PKH,
        )
        if output.index == 1
        else output
        for output in entry.outputs
    )
    assert (
        detect_ricochet_entry(
            replace(entry, outputs=non_native_outputs),
            tracked_postmix_inputs=tracked,
        )
        is None
    )


def test_ricochet_hop_rejects_wrong_outpoint_and_nondecreasing_value() -> None:
    entry = _fixture("ricochet-testnet-entry.hex")
    first_hop = _fixture("ricochet-testnet-hop-1.hex")
    expected = OutPoint(entry.txid, 2)
    previous_output = entry.outputs[2]

    assert (
        detect_ricochet_hop(
            first_hop,
            expected_input=OutPoint("f" * 64, 0),
            previous_output=previous_output,
        )
        is None
    )
    nondecreasing = replace(
        first_hop,
        outputs=(
            replace(
                first_hop.outputs[0],
                value_sats=previous_output.value_sats,
            ),
        ),
    )
    assert (
        detect_ricochet_hop(
            nondecreasing,
            expected_input=expected,
            previous_output=previous_output,
        )
        is None
    )


def _synthetic_spend(
    output_values: tuple[int, int, int, int],
) -> tuple[Transaction, dict[OutPoint, TxOutput]]:
    input_outpoints = (OutPoint("a" * 64, 0), OutPoint("b" * 64, 0))
    inputs = tuple(
        TxInput(
            previous_output=outpoint,
            script_sig=b"",
            sequence=0xFFFFFFFF,
            witness=(b"signature",),
        )
        for outpoint in input_outpoints
    )
    outputs = tuple(
        TxOutput(
            index=index,
            value_sats=value,
            script_pubkey=b"\x00\x14" + bytes((index + 1,)) * 20,
            script_type=ScriptType.P2WPKH,
        )
        for index, value in enumerate(output_values)
    )
    transaction = Transaction(
        version=2,
        inputs=inputs,
        outputs=outputs,
        lock_time=0,
        has_witness=True,
        txid="c" * 64,
        wtxid="c" * 64,
        size=200,
        weight=800,
        vsize=200,
    )
    output_total = sum(output_values)
    prevouts = {
        outpoint: TxOutput(
            index=outpoint.index,
            value_sats=output_total // 2 + 1_000,
            script_pubkey=b"\x00\x14" + bytes((index + 10,)) * 20,
            script_type=ScriptType.P2WPKH,
        )
        for index, outpoint in enumerate(input_outpoints)
    }
    return transaction, prevouts


def _payjoin_fixture() -> tuple[Transaction, dict[OutPoint, TxOutput]]:
    transaction = _fixture("payjoin-samourai-testnet.hex")
    parent_a = _fixture("payjoin-samourai-testnet-parent-a.hex")
    parent_b = _fixture("payjoin-samourai-testnet-parent-b.hex")
    return transaction, {
        transaction.inputs[0].previous_output: parent_a.outputs[1],
        transaction.inputs[1].previous_output: parent_b.outputs[2],
    }


def _fingerprint_spend(
    *,
    script_type: ScriptType = ScriptType.P2WPKH,
    input_count: int = 2,
) -> tuple[Transaction, dict[OutPoint, TxOutput]]:
    outpoints = tuple(
        OutPoint(chr(ord("a") + index) * 64, 0)
        for index in range(input_count)
    )
    inputs = tuple(
        TxInput(
            previous_output=outpoint,
            script_sig=b"",
            sequence=0xFFFFFFFF,
            witness=(),
        )
        for outpoint in outpoints
    )
    outputs = (
        TxOutput(
            0,
            4_951,
            b"\x00\x14" + b"\x11" * 20,
            ScriptType.P2WPKH,
        ),
        TxOutput(
            1,
            4_949,
            b"\x00\x14" + b"\x22" * 20,
            ScriptType.P2WPKH,
        ),
    )
    transaction = Transaction(
        version=2,
        inputs=inputs,
        outputs=outputs,
        lock_time=0,
        has_witness=True,
        txid="f" * 64,
        wtxid="f" * 64,
        size=200,
        weight=800,
        vsize=200,
    )
    if script_type is ScriptType.P2TR:
        script_pubkey = b"\x51\x20" + b"\x33" * 32
    else:
        script_pubkey = b"\x00\x14" + b"\x33" * 20
    value = 10_000 // input_count
    prevouts = {
        outpoint: TxOutput(
            index=0,
            value_sats=value,
            script_pubkey=script_pubkey,
            script_type=script_type,
        )
        for outpoint in outpoints
    }
    return transaction, prevouts


def _ecdsa_signature(r_length: int, sighash: int = 1) -> bytes:
    r_value = (
        b"\x00" + b"\x80" + b"\x11" * 31
        if r_length == 33
        else b"\x11" * r_length
    )
    s_value = b"\x22" * 32
    body = (
        b"\x02"
        + bytes((len(r_value),))
        + r_value
        + b"\x02"
        + bytes((len(s_value),))
        + s_value
    )
    return b"\x30" + bytes((len(body),)) + body + bytes((sighash,))


def _cpfp_transactions() -> tuple[
    Transaction,
    dict[OutPoint, TxOutput],
    Transaction,
    dict[OutPoint, TxOutput],
    OutPoint,
]:
    parent_inputs = (OutPoint("a" * 64, 0), OutPoint("b" * 64, 0))
    parent = Transaction(
        version=2,
        inputs=tuple(
            TxInput(
                previous_output=outpoint,
                script_sig=b"",
                sequence=0xFFFFFFFF,
                witness=(b"signature",),
            )
            for outpoint in parent_inputs
        ),
        outputs=(
            TxOutput(
                index=0,
                value_sats=40_000,
                script_pubkey=b"\x00\x14" + b"\x11" * 20,
                script_type=ScriptType.P2WPKH,
            ),
            TxOutput(
                index=1,
                value_sats=55_000,
                script_pubkey=b"\x00\x14" + b"\x12" * 20,
                script_type=ScriptType.P2WPKH,
            ),
        ),
        lock_time=0,
        has_witness=True,
        txid="c" * 64,
        wtxid="c" * 64,
        size=300,
        weight=800,
        vsize=200,
    )
    parent_prevouts = {
        outpoint: TxOutput(
            index=outpoint.index,
            value_sats=50_000,
            script_pubkey=b"\x00\x14" + bytes((position + 20,)) * 20,
            script_type=ScriptType.P2WPKH,
        )
        for position, outpoint in enumerate(parent_inputs)
    }
    tracked = OutPoint(parent.txid, 0)
    child = Transaction(
        version=2,
        inputs=(
            TxInput(
                previous_output=tracked,
                script_sig=b"",
                sequence=0xFFFFFFFF,
                witness=(b"signature",),
            ),
        ),
        outputs=(
            TxOutput(
                index=0,
                value_sats=30_000,
                script_pubkey=b"\x00\x14" + b"\x13" * 20,
                script_type=ScriptType.P2WPKH,
            ),
        ),
        lock_time=0,
        has_witness=True,
        txid="d" * 64,
        wtxid="d" * 64,
        size=150,
        weight=400,
        vsize=100,
    )
    return (
        parent,
        parent_prevouts,
        child,
        {tracked: parent.outputs[0]},
        tracked,
    )
