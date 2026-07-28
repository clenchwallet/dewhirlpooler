from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path

import pytest

from dewhirlpooler.bitcoin import (
    OutPoint,
    ScriptType,
    Transaction,
    TxInput,
    TxOutput,
    encode_p2wpkh_address,
    parse_transaction_hex,
)
from dewhirlpooler.trace import (
    ExposureTracer,
    TraceEdgeKind,
    TraceFindingKind,
    TraceLimits,
    TraceNodeKind,
)
from dewhirlpooler.whirlpool import Confidence

FIXTURES = Path(__file__).parent / "fixtures"


def _fixture(name: str) -> Transaction:
    return parse_transaction_hex((FIXTURES / name).read_text().strip())


class FakeResolver:
    def __init__(
        self,
        transactions: dict[str, Transaction],
        prevouts: dict[str, dict[OutPoint, TxOutput]],
        spends: dict[OutPoint, Transaction | None],
        heights: dict[str, int | None] | None = None,
    ) -> None:
        self.transactions = transactions
        self.prevout_maps = prevouts
        self.spends = spends
        self.heights = heights or {}
        self.transaction_calls: list[str] = []
        self.spend_calls: list[OutPoint] = []

    def transaction(self, txid: str) -> Transaction:
        self.transaction_calls.append(txid)
        return self.transactions[txid]

    def prevouts(
        self,
        transaction: Transaction,
    ) -> dict[OutPoint, TxOutput]:
        return self.prevout_maps.get(transaction.txid, {})

    def spending_transaction(
        self,
        outpoint: OutPoint,
        output: TxOutput,
    ) -> Transaction | None:
        self.spend_calls.append(outpoint)
        return self.spends.get(outpoint)

    def transaction_height(self, txid: str) -> int | None:
        return self.heights.get(txid)


def test_unknown_root_returns_root_only_report() -> None:
    ordinary = _ordinary_transaction(
        "a" * 64,
        (OutPoint("b" * 64, 0),),
        (42_000,),
    )
    resolver = FakeResolver({ordinary.txid: ordinary}, {}, {})

    report = ExposureTracer(resolver).trace(ordinary.txid)  # type: ignore[arg-type]

    assert report.summary.transactions_examined == 1
    assert report.summary.outputs_examined == 1
    assert report.findings == ()
    assert report.warnings
    assert report.truncated is False


def test_unresolved_round_ratios_are_unavailable_not_zero() -> None:
    round_transaction = _fixture("ashigaru-round-0.025.hex")
    resolver = FakeResolver(
        {round_transaction.txid: round_transaction},
        {},
        {},
    )

    report = ExposureTracer(resolver).trace(  # type: ignore[arg-type]
        round_transaction.txid
    )

    record = report.transactions[0]
    assert record.round_size == 5
    assert record.premix_input_count == 0
    assert record.remix_input_count == 0
    assert record.new_entrant_ratio is None
    assert record.remixer_ratio is None


def test_traces_tx0_round_later_tx0_consolidation_and_unspent_outputs() -> None:
    resolver, root, round_transaction, later_tx0, consolidation = _chain()

    report = ExposureTracer(resolver).trace(root.txid)  # type: ignore[arg-type]

    finding_kinds = {finding.kind for finding in report.findings}
    assert TraceFindingKind.WHIRLPOOL_ENTRY in finding_kinds
    assert TraceFindingKind.DOXXIC_CHANGE_SPEND in finding_kinds
    assert TraceFindingKind.LATER_TX0 in finding_kinds
    assert TraceFindingKind.POSTMIX_CONSOLIDATION in finding_kinds
    assert TraceFindingKind.POSSIBLE_PAYMENT in finding_kinds
    assert TraceFindingKind.UNSPENT in finding_kinds
    assert report.summary.transactions_examined == 4
    assert report.summary.whirlpool_rounds == 1
    assert report.summary.later_tx0s == 1
    assert report.summary.postmix_consolidations == 1
    assert report.summary.stonewall_spends == 0
    assert report.summary.ricochet_spends == 0
    assert report.summary.whirlpool_cpfp_findings == 0
    assert report.summary.possible_payments == 1
    assert report.summary.unspent_output_count == 21
    assert report.summary.unspent_sats > 0
    assert report.truncated is False
    transaction_records = {
        transaction.txid: transaction for transaction in report.transactions
    }
    assert transaction_records[root.txid].doxxic_change_enters_later_tx0 is True
    assert (
        transaction_records[later_tx0.txid].doxxic_change_enters_later_tx0
        is False
    )
    round_record = transaction_records[round_transaction.txid]
    assert round_record.round_size == 5
    assert round_record.premix_input_count == 2
    assert round_record.remix_input_count == 3
    assert round_record.new_entrant_ratio == "40.0000"
    assert round_record.remixer_ratio == "60.0000"
    assert round_record.miner_fee_sats == 1_210

    possible_links = [
        edge
        for edge in report.edges
        if edge.kind is TraceEdgeKind.POSSIBLE_COINJOIN_LINK
    ]
    assert len(possible_links) == 5
    assert {edge.target for edge in possible_links} == {
        f"out:{round_transaction.txid}:{index}" for index in range(5)
    }
    consolidation_finding = next(
        finding
        for finding in report.findings
        if finding.kind is TraceFindingKind.POSTMIX_CONSOLIDATION
    )
    assert consolidation_finding.txid == consolidation.txid
    assert len(consolidation_finding.outpoints) == 2
    assert any(
        node.id == f"tx:{later_tx0.txid}"
        for node in report.nodes
        if node.kind is TraceNodeKind.TRANSACTION
    )


def test_flags_same_block_higher_fee_whirlpool_child_once() -> None:
    resolver, root, round_transaction, _, consolidation = _chain()
    resolver.heights.update(
        {
            round_transaction.txid: 577_604,
            consolidation.txid: 577_604,
        }
    )

    report = ExposureTracer(resolver).trace(root.txid)  # type: ignore[arg-type]

    findings = tuple(
        finding
        for finding in report.findings
        if finding.kind is TraceFindingKind.WHIRLPOOL_CPFP
    )
    assert len(findings) == 1
    finding = findings[0]
    assert finding.confidence is Confidence.MEDIUM
    assert finding.txid == consolidation.txid
    assert finding.outpoints == (
        OutPoint(round_transaction.txid, 0),
        OutPoint(round_transaction.txid, 1),
    )
    assert finding.cpfp_parent_txid == round_transaction.txid
    assert finding.cpfp_block_height == 577_604
    assert finding.cpfp_parent_fee_sats == 1_210
    assert finding.cpfp_parent_vsize == 505
    assert finding.cpfp_child_fee_sats == 4_000_000
    assert finding.cpfp_child_vsize == 100
    assert finding.cpfp_parent_fee_rate == "2.40"
    assert finding.cpfp_child_fee_rate == "40000.00"
    assert finding.cpfp_package_fee_rate == "6613.57"
    assert "intent" in finding.explanation
    assert "not proven" in finding.explanation
    assert report.summary.whirlpool_cpfp_findings == 1

    serialized = report.to_dict()
    cpfp = next(
        item
        for item in serialized["findings"]
        if item["kind"] == "whirlpool_cpfp"
    )
    assert cpfp["cpfp_parent_txid"] == round_transaction.txid
    assert cpfp["cpfp_block_height"] == 577_604
    assert cpfp["cpfp_package_fee_rate"] == "6613.57"
    assert serialized["summary"]["whirlpool_cpfp_findings"] == 1


def test_flags_three_coin_one_output_payment_consolidation() -> None:
    resolver, root, consolidation, tracked = (
        _three_coin_payment_consolidation()
    )

    report = ExposureTracer(resolver).trace(root.txid)  # type: ignore[arg-type]

    bonus = [
        finding
        for finding in report.findings
        if finding.kind
        is TraceFindingKind.POSTMIX_PAYMENT_CONSOLIDATION
    ]
    assert len(bonus) == 1
    assert bonus[0].txid == consolidation.txid
    assert bonus[0].confidence.value == "medium"
    assert bonus[0].outpoints == tuple(
        sorted(tracked, key=lambda item: (item.txid, item.index))
    )
    assert "one spendable output" in bonus[0].explanation
    assert "remain heuristic" in bonus[0].explanation
    assert report.summary.postmix_consolidations == 1
    assert report.summary.postmix_payment_consolidations == 1
    assert report.to_dict()["summary"][
        "postmix_payment_consolidations"
    ] == 1


def test_flags_exact_address_reuse_across_tx0_and_round_roles() -> None:
    resolver, root, expected_address, expected_outpoints = (
        _address_reuse_chain()
    )

    report = ExposureTracer(resolver).trace(root.txid)  # type: ignore[arg-type]

    findings = [
        finding
        for finding in report.findings
        if finding.kind is TraceFindingKind.ADDRESS_REUSE
    ]
    assert len(findings) == 1
    finding = findings[0]
    assert finding.confidence.value == "medium"
    assert finding.txid == expected_outpoints[0].txid
    assert finding.outpoints == expected_outpoints
    assert finding.reused_address == expected_address
    assert finding.reused_roles == (
        "coordinator_fee",
        "tx0_premix",
        "whirlpool_coinjoin_output",
    )
    assert "Address reuse is observed" in finding.explanation
    assert "common ownership is not proven" in finding.explanation
    assert report.summary.address_reuse_findings == 1
    serialized = report.to_dict()
    serialized_finding = next(
        item
        for item in serialized["findings"]
        if item["kind"] == "address_reuse"
    )
    assert serialized_finding["reused_address"] == expected_address
    assert serialized_finding["reused_roles"] == list(finding.reused_roles)
    assert serialized["summary"]["address_reuse_findings"] == 1


def test_flags_address_reuse_across_coinjoin_and_stonewall_roles() -> None:
    shared_script = b"\x00\x14" + b"\x98" * 20
    root_template = _fixture("stonewall-mainnet-parent-a.hex")
    root = _replace_outputs(root_template, {3: shared_script})
    other_parent = _fixture("stonewall-mainnet-parent-b.hex")
    stonewall_template = _fixture("stonewall-mainnet.hex")
    stonewall = _replace_outputs(stonewall_template, {0: shared_script})
    tracked_outpoint = stonewall.inputs[0].previous_output
    resolver = FakeResolver(
        {
            root.txid: root,
            stonewall.txid: stonewall,
        },
        {
            root.txid: {},
            stonewall.txid: {
                stonewall.inputs[0].previous_output: root.outputs[3],
                stonewall.inputs[1].previous_output: other_parent.outputs[0],
            },
        },
        {tracked_outpoint: stonewall},
    )

    report = ExposureTracer(resolver).trace(root.txid)  # type: ignore[arg-type]

    finding = next(
        finding
        for finding in report.findings
        if finding.kind is TraceFindingKind.ADDRESS_REUSE
    )
    assert finding.reused_address == encode_p2wpkh_address(shared_script)
    assert finding.reused_roles == (
        "stonewall_equal_output",
        "whirlpool_coinjoin_output",
    )
    assert finding.outpoints == tuple(
        sorted(
            (
                OutPoint(root.txid, 3),
                OutPoint(stonewall.txid, 0),
            ),
            key=lambda item: (item.txid, item.index),
        )
    )
    assert report.summary.address_reuse_findings == 1


def test_flags_reuse_between_tx0_input_and_change() -> None:
    shared_script = b"\x00\x14" + b"\x97" * 20
    root = _replace_outputs(
        _fixture("ashigaru-tx0-0.025.hex"),
        {2: shared_script},
    )
    input_outpoint = root.inputs[0].previous_output
    input_output = TxOutput(
        index=input_outpoint.index,
        value_sats=sum(output.value_sats for output in root.outputs) + 15_000,
        script_pubkey=shared_script,
        script_type=ScriptType.P2WPKH,
    )
    resolver = FakeResolver(
        {root.txid: root},
        {root.txid: {input_outpoint: input_output}},
        {},
    )

    report = ExposureTracer(resolver).trace(root.txid)  # type: ignore[arg-type]

    finding = next(
        finding
        for finding in report.findings
        if finding.kind is TraceFindingKind.ADDRESS_REUSE
    )
    assert finding.reused_address == encode_p2wpkh_address(shared_script)
    assert finding.reused_roles == ("tx0_change", "tx0_input")
    assert finding.outpoints == tuple(
        sorted(
            (input_outpoint, OutPoint(root.txid, 2)),
            key=lambda item: (item.txid, item.index),
        )
    )


def test_flags_reuse_between_whirlpool_input_and_output() -> None:
    shared_script = b"\x00\x14" + b"\x96" * 20
    root = _replace_outputs(
        _fixture("ashigaru-round-0.025.hex"),
        {0: shared_script},
    )
    input_values = [2_500_605] * 2 + [2_500_000] * 3
    prevouts = {
        transaction_input.previous_output: TxOutput(
            index=transaction_input.previous_output.index,
            value_sats=value,
            script_pubkey=(
                shared_script
                if position == 0
                else b"\x00\x14" + bytes((position + 1,)) * 20
            ),
            script_type=ScriptType.P2WPKH,
        )
        for position, (transaction_input, value) in enumerate(
            zip(root.inputs, input_values, strict=True)
        )
    }
    resolver = FakeResolver(
        {root.txid: root},
        {root.txid: prevouts},
        {},
    )

    report = ExposureTracer(resolver).trace(root.txid)  # type: ignore[arg-type]

    finding = next(
        finding
        for finding in report.findings
        if finding.kind is TraceFindingKind.ADDRESS_REUSE
    )
    assert finding.reused_address == encode_p2wpkh_address(shared_script)
    assert finding.reused_roles == (
        "whirlpool_coinjoin_output",
        "whirlpool_input",
    )
    assert finding.outpoints == tuple(
        sorted(
            (
                root.inputs[0].previous_output,
                OutPoint(root.txid, 0),
            ),
            key=lambda item: (item.txid, item.index),
        )
    )


def test_same_role_address_reuse_is_not_flagged() -> None:
    template = _fixture("ashigaru-tx0-0.025.hex")
    shared_script = b"\x00\x14" + b"\x99" * 20
    transaction = _replace_outputs(
        template,
        {
            3: shared_script,
            4: shared_script,
        },
    )
    resolver = FakeResolver(
        {transaction.txid: transaction},
        {transaction.txid: {}},
        {},
    )

    report = ExposureTracer(resolver).trace(transaction.txid)  # type: ignore[arg-type]

    assert report.summary.address_reuse_findings == 0
    assert all(
        finding.kind is not TraceFindingKind.ADDRESS_REUSE
        for finding in report.findings
    )


def test_same_outpoint_becoming_whirlpool_input_is_not_reuse() -> None:
    resolver, root, _, _, _ = _chain()

    report = ExposureTracer(resolver).trace(root.txid)  # type: ignore[arg-type]

    assert report.summary.address_reuse_findings == 0
    assert all(
        finding.kind is not TraceFindingKind.ADDRESS_REUSE
        for finding in report.findings
    )


@pytest.mark.parametrize(
    ("input_indices", "output_values", "op_return_only"),
    [
        ((0, 1), (1_000_000,), False),
        ((0, 1, 2), (1_000_000, 900_000), False),
        ((0, 1, 2), (), True),
    ],
)
def test_rejects_nonmatching_three_coin_payment_consolidation(
    input_indices: tuple[int, ...],
    output_values: tuple[int, ...],
    op_return_only: bool,
) -> None:
    resolver, root, _, _ = _three_coin_payment_consolidation(
        input_indices=input_indices,
        output_values=output_values,
        op_return_only=op_return_only,
    )

    report = ExposureTracer(resolver).trace(root.txid)  # type: ignore[arg-type]

    assert report.summary.postmix_payment_consolidations == 0
    assert all(
        finding.kind
        is not TraceFindingKind.POSTMIX_PAYMENT_CONSOLIDATION
        for finding in report.findings
    )


def test_traces_public_mainnet_stonewall_shape_from_postmix() -> None:
    root = _fixture("stonewall-mainnet-parent-a.hex")
    other_parent = _fixture("stonewall-mainnet-parent-b.hex")
    stonewall = _fixture("stonewall-mainnet.hex")
    tracked_outpoint = stonewall.inputs[0].previous_output
    resolver = FakeResolver(
        {
            root.txid: root,
            stonewall.txid: stonewall,
        },
        {
            root.txid: {},
            stonewall.txid: {
                stonewall.inputs[0].previous_output: root.outputs[3],
                stonewall.inputs[1].previous_output: other_parent.outputs[0],
            },
        },
        {tracked_outpoint: stonewall},
    )

    report = ExposureTracer(resolver).trace(root.txid)  # type: ignore[arg-type]

    finding = next(
        finding
        for finding in report.findings
        if finding.kind is TraceFindingKind.STONEWALL
    )
    assert finding.txid == stonewall.txid
    assert finding.confidence.value == "medium"
    assert finding.outpoints == (tracked_outpoint,)
    assert finding.repeated_output_values_sats == (408_297, 4_588_406)
    assert "StonewallX2" in finding.explanation
    assert report.summary.stonewall_spends == 1
    assert report.summary.ricochet_spends == 0
    assert {
        node.output_index
        for node in report.nodes
        if node.txid == stonewall.txid
        and node.role == "stonewall_equal_output"
    } == {0, 1, 2, 3}


def test_traces_postmix_payjoin_fingerprint_without_losing_ambiguity() -> None:
    resolver, root, candidate, tracked = _payjoin_trace_chain()

    report = ExposureTracer(resolver).trace(root.txid)  # type: ignore[arg-type]

    findings = tuple(
        finding
        for finding in report.findings
        if finding.kind
        is TraceFindingKind.POSTMIX_PAYJOIN_FINGERPRINT
    )
    assert len(findings) == 1
    finding = findings[0]
    assert finding.txid == candidate.txid
    assert finding.confidence is Confidence.MEDIUM
    assert finding.outpoints == (tracked,)
    assert finding.payjoin_unnecessary_input_heuristic == "uih1"
    assert finding.payjoin_fingerprint_signals == ("ecdsa_r_length",)
    assert finding.payjoin_input_clusters == ((0,), (1,))
    assert "consistent with Payjoin/Cahoots" in finding.explanation
    assert "not proof" in finding.explanation
    assert "ownership is unknown" in finding.explanation
    assert "not proven owners" in finding.explanation
    assert report.summary.postmix_payjoin_fingerprint_candidates == 1

    candidate_payments = tuple(
        item
        for item in report.findings
        if item.kind is TraceFindingKind.POSSIBLE_PAYMENT
        and item.txid == candidate.txid
    )
    assert len(candidate_payments) == 2
    assert {item.outpoints[0].index for item in candidate_payments} == {0, 1}

    serialized = report.to_dict()
    serialized_finding = next(
        item
        for item in serialized["findings"]
        if item["kind"] == "postmix_payjoin_fingerprint"
    )
    assert {
        "kind": serialized_finding["kind"],
        "confidence": serialized_finding["confidence"],
        "payjoin_unnecessary_input_heuristic": serialized_finding[
            "payjoin_unnecessary_input_heuristic"
        ],
        "payjoin_fingerprint_signals": serialized_finding[
            "payjoin_fingerprint_signals"
        ],
        "payjoin_input_clusters": serialized_finding[
            "payjoin_input_clusters"
        ],
    } == {
        "kind": "postmix_payjoin_fingerprint",
        "confidence": "medium",
        "payjoin_unnecessary_input_heuristic": "uih1",
        "payjoin_fingerprint_signals": ["ecdsa_r_length"],
        "payjoin_input_clusters": [[0], [1]],
    }
    assert serialized_finding["outpoints"] == [
        {"txid": tracked.txid, "index": tracked.index}
    ]
    assert (
        serialized["summary"]["postmix_payjoin_fingerprint_candidates"]
        == 1
    )
    unrelated = next(
        item
        for item in serialized["findings"]
        if item["kind"] == "possible_payment"
    )
    assert unrelated["payjoin_unnecessary_input_heuristic"] is None
    assert unrelated["payjoin_fingerprint_signals"] == []
    assert unrelated["payjoin_input_clusters"] == []


def test_traces_unique_four_hop_ricochet_chain() -> None:
    resolver, root, entry, hops = _ricochet_chain()

    report = ExposureTracer(resolver).trace(root.txid)  # type: ignore[arg-type]

    finding = next(
        finding
        for finding in report.findings
        if finding.kind is TraceFindingKind.RICOCHET
    )
    assert finding.txid == entry.txid
    assert finding.service_fee_sats == 100_000
    assert finding.service_fee_address is not None
    assert finding.service_fee_address.startswith("bc1q")
    assert finding.hop_txids == tuple(hop.txid for hop in hops)
    assert len(finding.hop_txids) == 4
    proof_outpoints = (
        OutPoint(entry.txid, 1),
        OutPoint(entry.txid, 2),
        OutPoint(hops[0].txid, 0),
        OutPoint(hops[1].txid, 0),
        OutPoint(hops[2].txid, 0),
    )
    assert all(
        resolver.spend_calls.count(outpoint) == 1
        for outpoint in proof_outpoints
    )
    assert report.summary.ricochet_spends == 1
    assert report.summary.stonewall_spends == 0
    serialized = report.to_dict()
    serialized_finding = next(
        item
        for item in serialized["findings"]
        if item["kind"] == "ricochet"
    )
    assert serialized_finding["service_fee_sats"] == 100_000
    assert serialized_finding["hop_txids"] == [
        hop.txid for hop in hops
    ]
    assert any(
        node.txid == entry.txid
        and node.output_index == 0
        and node.role == "ricochet_fee"
        for node in report.nodes
    )
    assert any(
        node.txid == hops[-1].txid
        and node.output_index == 0
        and node.role == "possible_payment"
        for node in report.nodes
    )
    assert not any(
        finding.kind is TraceFindingKind.POSSIBLE_PAYMENT
        and finding.outpoints
        and finding.outpoints[0] == OutPoint(entry.txid, 0)
        for finding in report.findings
    )


@pytest.mark.parametrize(
    "limits",
    [
        TraceLimits(max_depth=4),
        TraceLimits(max_history_lookups=4),
        TraceLimits(max_transactions=5),
        TraceLimits(max_outputs=11),
    ],
)
def test_ricochet_proof_respects_every_trace_budget(
    limits: TraceLimits,
) -> None:
    resolver, root, _, _ = _ricochet_chain()

    report = ExposureTracer(resolver, limits).trace(  # type: ignore[arg-type]
        root.txid
    )

    assert report.summary.ricochet_spends == 0
    assert report.truncated is True
    assert report.warnings


def test_short_ricochet_shape_is_not_labelled() -> None:
    resolver, root, _, hops = _ricochet_chain()
    resolver.spends.pop(OutPoint(hops[1].txid, 0))

    report = ExposureTracer(resolver).trace(root.txid)  # type: ignore[arg-type]

    assert report.summary.ricochet_spends == 0
    assert all(
        finding.kind is not TraceFindingKind.RICOCHET
        for finding in report.findings
    )


def test_two_valid_ricochet_paths_are_rejected_as_ambiguous() -> None:
    resolver, root, entry, _ = _ricochet_chain()
    previous_outpoint = OutPoint(entry.txid, 1)
    previous_output = entry.outputs[1]
    for position in range(4):
        hop = _ordinary_transaction(
            str(position + 6) * 64,
            (previous_outpoint,),
            (previous_output.value_sats - 200,),
        )
        resolver.transactions[hop.txid] = hop
        resolver.prevout_maps[hop.txid] = {
            previous_outpoint: previous_output
        }
        resolver.spends[previous_outpoint] = hop
        previous_outpoint = OutPoint(hop.txid, 0)
        previous_output = hop.outputs[0]

    report = ExposureTracer(resolver).trace(root.txid)  # type: ignore[arg-type]

    assert report.summary.ricochet_spends == 0
    assert all(
        finding.kind is not TraceFindingKind.RICOCHET
        for finding in report.findings
    )


def test_cycle_in_ricochet_path_is_rejected() -> None:
    resolver, root, _, hops = _ricochet_chain()
    resolver.spends[OutPoint(hops[1].txid, 0)] = hops[0]

    report = ExposureTracer(resolver).trace(root.txid)  # type: ignore[arg-type]

    assert report.summary.ricochet_spends == 0
    assert all(
        finding.kind is not TraceFindingKind.RICOCHET
        for finding in report.findings
    )
    assert len(resolver.spend_calls) <= TraceLimits().max_history_lookups


def test_possible_payment_follows_only_one_additional_spend() -> None:
    resolver, root, _, _, consolidation = _chain()
    payment_outpoint = OutPoint(consolidation.txid, 0)
    second = _ordinary_transaction(
        "d" * 64,
        (payment_outpoint,),
        (500_000,),
    )
    third = _ordinary_transaction(
        "e" * 64,
        (OutPoint(second.txid, 0),),
        (400_000,),
    )
    resolver.transactions[second.txid] = second
    resolver.transactions[third.txid] = third
    resolver.spends[payment_outpoint] = second
    resolver.spends[OutPoint(second.txid, 0)] = third

    report = ExposureTracer(resolver).trace(root.txid)  # type: ignore[arg-type]

    transaction_ids = {
        node.txid
        for node in report.nodes
        if node.kind is TraceNodeKind.TRANSACTION
    }
    assert second.txid in transaction_ids
    assert third.txid not in transaction_ids


@pytest.mark.parametrize(
    "limits",
    [
        TraceLimits(max_depth=1),
        TraceLimits(max_transactions=1),
        TraceLimits(max_outputs=1),
        TraceLimits(max_history_lookups=1),
    ],
)
def test_each_limit_returns_partial_report(limits: TraceLimits) -> None:
    resolver, root, _, _, _ = _chain()

    report = ExposureTracer(resolver, limits).trace(root.txid)  # type: ignore[arg-type]

    assert report.truncated is True
    assert report.warnings


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("max_depth", 0),
        ("max_transactions", -1),
        ("max_outputs", True),
        ("max_history_lookups", 1.5),
    ],
)
def test_limits_require_positive_integers(field: str, value: object) -> None:
    values = {
        "max_depth": 4,
        "max_transactions": 100,
        "max_outputs": 250,
        "max_history_lookups": 250,
    }
    values[field] = value

    with pytest.raises(ValueError, match="positive integer"):
        TraceLimits(**values)  # type: ignore[arg-type]


def test_report_dictionary_is_byte_stable() -> None:
    resolver, root, _, _, _ = _chain()
    report = ExposureTracer(resolver).trace(root.txid)  # type: ignore[arg-type]

    first = json.dumps(report.to_dict(), sort_keys=True)
    second = json.dumps(report.to_dict(), sort_keys=True)

    assert first == second
    assert [node.id for node in report.nodes] == sorted(
        node.id for node in report.nodes
    )
    assert [edge.id for edge in report.edges] == sorted(
        edge.id for edge in report.edges
    )
    serialized = report.to_dict()
    assert "transactions" in serialized
    assert [
        transaction["txid"] for transaction in serialized["transactions"]
    ] == sorted(
        transaction.txid for transaction in report.transactions
    )


def test_malformed_cycle_terminates_deterministically() -> None:
    resolver, root, round_transaction, _, _ = _chain()
    resolver.spends[OutPoint(round_transaction.txid, 2)] = root

    report = ExposureTracer(
        resolver,
        TraceLimits(
            max_depth=4,
            max_transactions=20,
            max_outputs=100,
            max_history_lookups=100,
        ),
    ).trace(root.txid)  # type: ignore[arg-type]

    assert report.summary.transactions_examined <= 4
    assert len(resolver.spend_calls) <= 100


def _chain() -> tuple[
    FakeResolver,
    Transaction,
    Transaction,
    Transaction,
    Transaction,
]:
    root_template = _fixture("ashigaru-tx0-0.025.hex")
    root_outputs = list(root_template.outputs)
    root_outputs[2] = TxOutput(
        index=2,
        value_sats=30_000_000,
        script_pubkey=root_outputs[2].script_pubkey,
        script_type=root_outputs[2].script_type,
    )
    root = Transaction(
        version=root_template.version,
        inputs=root_template.inputs,
        outputs=tuple(root_outputs),
        lock_time=root_template.lock_time,
        has_witness=root_template.has_witness,
        txid=root_template.txid,
        wtxid=root_template.wtxid,
        size=root_template.size,
        weight=root_template.weight,
        vsize=root_template.vsize,
    )
    round_transaction = _fixture("ashigaru-round-0.025.hex")
    root_change = OutPoint(root.txid, 2)
    later_tx0 = _clone_tx0(
        root,
        txid="c" * 64,
        previous_output=root_change,
    )
    round_output_zero = OutPoint(round_transaction.txid, 0)
    round_output_one = OutPoint(round_transaction.txid, 1)
    consolidation = _ordinary_transaction(
        "f" * 64,
        (round_output_zero, round_output_one),
        (1_000_000,),
    )

    round_values = [2_500_605] * 2 + [2_500_000] * 3
    round_prevouts = {
        transaction_input.previous_output: TxOutput(
            index=transaction_input.previous_output.index,
            value_sats=value,
            script_pubkey=b"\x00\x14" + bytes((position + 1,)) * 20,
            script_type=ScriptType.P2WPKH,
        )
        for position, (transaction_input, value) in enumerate(
            zip(round_transaction.inputs, round_values, strict=True)
        )
    }
    consolidation_prevouts = {
        round_output_zero: round_transaction.outputs[0],
        round_output_one: round_transaction.outputs[1],
    }
    transactions = {
        root.txid: root,
        round_transaction.txid: round_transaction,
        later_tx0.txid: later_tx0,
        consolidation.txid: consolidation,
    }
    prevouts = {
        root.txid: {},
        round_transaction.txid: round_prevouts,
        later_tx0.txid: {root_change: root.outputs[2]},
        consolidation.txid: consolidation_prevouts,
    }
    spends: dict[OutPoint, Transaction | None] = {
        root_change: later_tx0,
        OutPoint(root.txid, 10): round_transaction,
        round_output_zero: consolidation,
        round_output_one: consolidation,
    }
    return (
        FakeResolver(transactions, prevouts, spends),
        root,
        round_transaction,
        later_tx0,
        consolidation,
    )


def _three_coin_payment_consolidation(
    *,
    input_indices: tuple[int, ...] = (2, 0, 1),
    output_values: tuple[int, ...] = (1_000_000,),
    op_return_only: bool = False,
) -> tuple[FakeResolver, Transaction, Transaction, tuple[OutPoint, ...]]:
    resolver, root, round_transaction, _, _ = _chain()
    tracked = tuple(
        OutPoint(round_transaction.txid, index)
        for index in input_indices
    )
    consolidation = _ordinary_transaction(
        "9" * 64,
        tracked,
        output_values or (0,),
    )
    if op_return_only:
        consolidation = Transaction(
            version=consolidation.version,
            inputs=consolidation.inputs,
            outputs=(
                TxOutput(
                    index=0,
                    value_sats=0,
                    script_pubkey=b"\x6a",
                    script_type=ScriptType.OP_RETURN,
                ),
            ),
            lock_time=consolidation.lock_time,
            has_witness=consolidation.has_witness,
            txid=consolidation.txid,
            wtxid=consolidation.wtxid,
            size=consolidation.size,
            weight=consolidation.weight,
            vsize=consolidation.vsize,
        )
    resolver.transactions[consolidation.txid] = consolidation
    resolver.prevout_maps[consolidation.txid] = {
        outpoint: round_transaction.outputs[outpoint.index]
        for outpoint in tracked
    }
    for outpoint in tracked:
        resolver.spends[outpoint] = consolidation
    return resolver, root, consolidation, tracked


def _address_reuse_chain() -> tuple[
    FakeResolver,
    Transaction,
    str,
    tuple[OutPoint, ...],
]:
    shared_script = b"\x00\x14" + b"\x99" * 20
    root_template = _fixture("ashigaru-tx0-0.025.hex")
    root = _replace_outputs(
        root_template,
        {
            1: shared_script,
            10: shared_script,
        },
    )

    round_template = _fixture("ashigaru-round-0.025.hex")
    round_inputs = list(round_template.inputs)
    round_inputs[0] = TxInput(
        previous_output=OutPoint(root.txid, 10),
        script_sig=round_inputs[0].script_sig,
        sequence=round_inputs[0].sequence,
        witness=round_inputs[0].witness,
    )
    round_transaction = _replace_outputs(
        _replace_inputs(round_template, tuple(round_inputs)),
        {0: shared_script},
    )

    round_values = [2_500_605] * 2 + [2_500_000] * 3
    round_prevouts = {
        transaction_input.previous_output: TxOutput(
            index=transaction_input.previous_output.index,
            value_sats=value,
            script_pubkey=b"\x00\x14" + bytes((position + 1,)) * 20,
            script_type=ScriptType.P2WPKH,
        )
        for position, (transaction_input, value) in enumerate(
            zip(round_transaction.inputs, round_values, strict=True)
        )
    }
    round_prevouts[round_transaction.inputs[0].previous_output] = (
        root.outputs[10]
    )
    resolver = FakeResolver(
        {
            root.txid: root,
            round_transaction.txid: round_transaction,
        },
        {
            root.txid: {},
            round_transaction.txid: round_prevouts,
        },
        {
            OutPoint(root.txid, 10): round_transaction,
        },
    )
    outpoints = tuple(
        sorted(
            (
                OutPoint(root.txid, 1),
                OutPoint(root.txid, 10),
                OutPoint(round_transaction.txid, 0),
            ),
            key=lambda item: (item.txid, item.index),
        )
    )
    return (
        resolver,
        root,
        encode_p2wpkh_address(shared_script),
        outpoints,
    )


def _ricochet_chain() -> tuple[
    FakeResolver,
    Transaction,
    Transaction,
    tuple[Transaction, ...],
]:
    root = _fixture("ashigaru-round-0.025.hex")
    root_outpoint = OutPoint(root.txid, 0)
    entry = _ordinary_transaction(
        "1" * 64,
        (root_outpoint,),
        (100_000, 300_000, 2_099_000),
    )
    hops: list[Transaction] = []
    previous_outpoint = OutPoint(entry.txid, 2)
    previous_value = entry.outputs[2].value_sats
    for position in range(4):
        hop = _ordinary_transaction(
            str(position + 2) * 64,
            (previous_outpoint,),
            (previous_value - 200,),
        )
        hops.append(hop)
        previous_outpoint = OutPoint(hop.txid, 0)
        previous_value = hop.outputs[0].value_sats

    transactions = {
        root.txid: root,
        entry.txid: entry,
        **{hop.txid: hop for hop in hops},
    }
    prevouts: dict[str, dict[OutPoint, TxOutput]] = {
        root.txid: {},
        entry.txid: {root_outpoint: root.outputs[0]},
    }
    previous_outpoint = OutPoint(entry.txid, 2)
    previous_output = entry.outputs[2]
    for hop in hops:
        prevouts[hop.txid] = {previous_outpoint: previous_output}
        previous_outpoint = OutPoint(hop.txid, 0)
        previous_output = hop.outputs[0]

    spends: dict[OutPoint, Transaction | None] = {
        root_outpoint: entry,
        OutPoint(entry.txid, 1): None,
        OutPoint(entry.txid, 2): hops[0],
    }
    for current, following in zip(hops, hops[1:], strict=False):
        spends[OutPoint(current.txid, 0)] = following
    return FakeResolver(transactions, prevouts, spends), root, entry, tuple(hops)


def _payjoin_trace_chain() -> tuple[
    FakeResolver,
    Transaction,
    Transaction,
    OutPoint,
]:
    resolver, root, round_transaction, _, old_consolidation = _chain()
    tracked = OutPoint(round_transaction.txid, 0)
    external = OutPoint("9" * 64, 1)
    candidate = replace(
        old_consolidation,
        inputs=(
            TxInput(
                previous_output=tracked,
                script_sig=b"",
                sequence=0xFFFFFFFD,
                witness=(_ecdsa_signature(32), b"\x02" * 33),
            ),
            TxInput(
                previous_output=external,
                script_sig=b"",
                sequence=0xFFFFFFFD,
                witness=(_ecdsa_signature(33), b"\x03" * 33),
            ),
        ),
        outputs=(
            TxOutput(
                index=0,
                value_sats=50_000,
                script_pubkey=b"\x00\x14" + b"\x44" * 20,
                script_type=ScriptType.P2WPKH,
            ),
            TxOutput(
                index=1,
                value_sats=2_540_000,
                script_pubkey=b"\x00\x14" + b"\x55" * 20,
                script_type=ScriptType.P2WPKH,
            ),
        ),
    )
    resolver.transactions[candidate.txid] = candidate
    resolver.prevout_maps[candidate.txid] = {
        tracked: round_transaction.outputs[0],
        external: TxOutput(
            index=1,
            value_sats=100_000,
            script_pubkey=b"\x00\x14" + b"\x66" * 20,
            script_type=ScriptType.P2WPKH,
        ),
    }
    resolver.spends[tracked] = candidate
    resolver.spends.pop(OutPoint(round_transaction.txid, 1))
    return resolver, root, candidate, tracked


def _ecdsa_signature(r_length: int) -> bytes:
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
    return b"\x30" + bytes((len(body),)) + body + b"\x01"


def _clone_tx0(
    template: Transaction,
    *,
    txid: str,
    previous_output: OutPoint,
) -> Transaction:
    outputs = tuple(
        TxOutput(
            index=new_index,
            value_sats=output.value_sats,
            script_pubkey=output.script_pubkey,
            script_type=output.script_type,
        )
        for new_index, output in enumerate(
            output
            for output in template.outputs
            if output.index != 2
        )
    )
    return Transaction(
        version=template.version,
        inputs=(
            TxInput(
                previous_output=previous_output,
                script_sig=b"",
                sequence=0xFFFFFFFF,
                witness=(b"signature",),
            ),
        ),
        outputs=outputs,
        lock_time=template.lock_time,
        has_witness=True,
        txid=txid,
        wtxid=txid,
        size=template.size,
        weight=template.weight,
        vsize=template.vsize,
    )


def _replace_outputs(
    transaction: Transaction,
    scripts: dict[int, bytes],
) -> Transaction:
    outputs = tuple(
        TxOutput(
            index=output.index,
            value_sats=output.value_sats,
            script_pubkey=scripts.get(output.index, output.script_pubkey),
            script_type=(
                ScriptType.P2WPKH
                if output.index in scripts
                else output.script_type
            ),
        )
        for output in transaction.outputs
    )
    return Transaction(
        version=transaction.version,
        inputs=transaction.inputs,
        outputs=outputs,
        lock_time=transaction.lock_time,
        has_witness=transaction.has_witness,
        txid=transaction.txid,
        wtxid=transaction.wtxid,
        size=transaction.size,
        weight=transaction.weight,
        vsize=transaction.vsize,
    )


def _replace_inputs(
    transaction: Transaction,
    inputs: tuple[TxInput, ...],
) -> Transaction:
    return Transaction(
        version=transaction.version,
        inputs=inputs,
        outputs=transaction.outputs,
        lock_time=transaction.lock_time,
        has_witness=transaction.has_witness,
        txid=transaction.txid,
        wtxid=transaction.wtxid,
        size=transaction.size,
        weight=transaction.weight,
        vsize=transaction.vsize,
    )


def _ordinary_transaction(
    txid: str,
    inputs: tuple[OutPoint, ...],
    output_values: tuple[int, ...],
) -> Transaction:
    transaction_inputs = tuple(
        TxInput(
            previous_output=outpoint,
            script_sig=b"",
            sequence=0xFFFFFFFF,
            witness=(b"signature",),
        )
        for outpoint in inputs
    )
    outputs = tuple(
        TxOutput(
            index=index,
            value_sats=value,
            script_pubkey=b"\x00\x14" + bytes((index + 90,)) * 20,
            script_type=ScriptType.P2WPKH,
        )
        for index, value in enumerate(output_values)
    )
    return Transaction(
        version=2,
        inputs=transaction_inputs,
        outputs=outputs,
        lock_time=0,
        has_witness=True,
        txid=txid,
        wtxid=txid,
        size=100,
        weight=400,
        vsize=100,
    )
