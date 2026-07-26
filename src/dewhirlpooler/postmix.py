"""Clean-room, evidence-labelled postmix spend classifiers."""

from __future__ import annotations

from collections import Counter, defaultdict
from collections.abc import Collection, Iterable, Mapping
from dataclasses import dataclass
from decimal import ROUND_HALF_UP, Decimal
from enum import StrEnum

from .bitcoin import (
    MAX_MONEY_SATS,
    OutPoint,
    ScriptType,
    Transaction,
    TxInput,
    TxOutput,
    classify_script,
)
from .whirlpool import Confidence

RICOCHET_SERVICE_FEE_SATS = 100_000
_STANDARD_SPENDABLE_SCRIPT_TYPES = frozenset(
    {
        ScriptType.P2PKH,
        ScriptType.P2SH,
        ScriptType.P2WPKH,
        ScriptType.P2WSH,
        ScriptType.P2TR,
    }
)


class PostmixSpendKind(StrEnum):
    STONEWALL = "stonewall"
    RICOCHET = "ricochet"


@dataclass(frozen=True, slots=True)
class StonewallDetection:
    confidence: Confidence
    tracked_postmix_inputs: tuple[OutPoint, ...]
    repeated_output_values_sats: tuple[int, ...]
    repeated_output_indices: tuple[tuple[int, ...], ...]
    input_count: int
    input_value_sats: int
    miner_fee_sats: int


@dataclass(frozen=True, slots=True)
class RicochetEntry:
    confidence: Confidence
    fee_outpoint: OutPoint
    fee_output: TxOutput
    continuation_candidates: tuple[OutPoint, ...]


@dataclass(frozen=True, slots=True)
class RicochetHop:
    txid: str
    input_outpoint: OutPoint
    output_outpoint: OutPoint
    output: TxOutput
    miner_fee_sats: int


@dataclass(frozen=True, slots=True)
class WhirlpoolCpfpDetection:
    confidence: Confidence
    parent_txid: str
    child_txid: str
    block_height: int
    tracked_parent_outpoints: tuple[OutPoint, ...]
    parent_fee_sats: int
    parent_vsize: int
    child_fee_sats: int
    child_vsize: int
    parent_fee_rate: str
    child_fee_rate: str
    package_fee_rate: str


@dataclass(frozen=True, slots=True)
class PayjoinFingerprintDetection:
    confidence: Confidence
    tracked_postmix_inputs: tuple[OutPoint, ...]
    other_inputs: tuple[OutPoint, ...]
    unnecessary_input_heuristic: str | None
    fingerprint_signals: tuple[str, ...]
    input_clusters: tuple[tuple[int, ...], ...]
    input_value_sats: int
    miner_fee_sats: int


def detect_payjoin_fingerprints(
    transaction: Transaction,
    prevouts: Mapping[OutPoint, TxOutput],
    *,
    tracked_postmix_inputs: Collection[OutPoint] = (),
) -> PayjoinFingerprintDetection | None:
    """Return bounded public shape and input-fingerprint evidence."""

    input_outpoints = tuple(
        transaction_input.previous_output
        for transaction_input in transaction.inputs
    )
    if (
        len(input_outpoints) < 2
        or any(_is_coinbase(outpoint) for outpoint in input_outpoints)
        or len(set(input_outpoints)) != len(input_outpoints)
        or len({outpoint.txid for outpoint in input_outpoints}) < 2
        or set(prevouts) != set(input_outpoints)
    ):
        return None

    tracked = set(tracked_postmix_inputs)
    tracked_inputs = tuple(
        outpoint for outpoint in input_outpoints if outpoint in tracked
    )
    other_inputs = tuple(
        outpoint for outpoint in input_outpoints if outpoint not in tracked
    )
    if not tracked_inputs or not other_inputs:
        return None

    if (
        len(transaction.outputs) != 2
        or any(
            not _is_standard_spendable_output(output)
            for output in transaction.outputs
        )
    ):
        return None

    input_values = tuple(
        prevouts[outpoint].value_sats for outpoint in input_outpoints
    )
    input_total = _bounded_positive_sum(input_values)
    output_total = _bounded_positive_sum(
        output.value_sats for output in transaction.outputs
    )
    if (
        input_total is None
        or output_total is None
        or input_total < output_total
    ):
        return None
    miner_fee = input_total - output_total

    proper_subset_capacity = input_total - min(input_values)
    small_required = min(
        output.value_sats for output in transaction.outputs
    ) + miner_fee
    large_required = max(
        output.value_sats for output in transaction.outputs
    ) + miner_fee
    unnecessary_input_heuristic: str | None = None
    if proper_subset_capacity >= large_required:
        unnecessary_input_heuristic = "uih2"
    elif proper_subset_capacity >= small_required:
        unnecessary_input_heuristic = "uih1"

    dimensions: list[tuple[str, tuple[object, ...]]] = []
    script_types = tuple(
        prevouts[outpoint].script_type for outpoint in input_outpoints
    )
    if (
        all(
            script_type in _STANDARD_SPENDABLE_SCRIPT_TYPES
            for script_type in script_types
        )
        and len(set(script_types)) > 1
    ):
        dimensions.append(("prevout_script_type", script_types))

    sequences = tuple(
        transaction_input.sequence for transaction_input in transaction.inputs
    )
    if len(set(sequences)) > 1:
        dimensions.append(("sequence", sequences))

    ecdsa_fingerprints = tuple(
        _ecdsa_fingerprint(transaction_input, prevouts[outpoint].script_type)
        for transaction_input, outpoint in zip(
            transaction.inputs,
            input_outpoints,
            strict=True,
        )
    )
    if all(fingerprint is not None for fingerprint in ecdsa_fingerprints):
        r_lengths = tuple(
            fingerprint[0]
            for fingerprint in ecdsa_fingerprints
            if fingerprint is not None
        )
        sighashes = tuple(
            fingerprint[1]
            for fingerprint in ecdsa_fingerprints
            if fingerprint is not None
        )
        if len(set(r_lengths)) > 1:
            dimensions.append(("ecdsa_r_length", r_lengths))
        if len(set(sighashes)) > 1:
            dimensions.append(("ecdsa_sighash", sighashes))

    taproot_forms = tuple(
        _taproot_sighash_form(
            transaction_input,
            prevouts[outpoint].script_type,
        )
        for transaction_input, outpoint in zip(
            transaction.inputs,
            input_outpoints,
            strict=True,
        )
    )
    if (
        all(form is not None for form in taproot_forms)
        and len(set(taproot_forms)) > 1
    ):
        dimensions.append(("taproot_sighash_form", taproot_forms))

    fingerprint_signals = tuple(name for name, _ in dimensions)
    if unnecessary_input_heuristic is None and not fingerprint_signals:
        return None

    if dimensions:
        clusters: dict[tuple[object, ...], list[int]] = {}
        for index in range(len(input_outpoints)):
            key = tuple(values[index] for _, values in dimensions)
            clusters.setdefault(key, []).append(index)
        input_clusters = tuple(
            tuple(indices)
            for indices in sorted(
                clusters.values(),
                key=lambda indices: indices[0],
            )
        )
    else:
        input_clusters = (tuple(range(len(input_outpoints))),)

    confidence = (
        Confidence.MEDIUM
        if (
            unnecessary_input_heuristic == "uih2"
            or len(fingerprint_signals) >= 2
            or (
                unnecessary_input_heuristic == "uih1"
                and fingerprint_signals
            )
        )
        else Confidence.LOW
    )
    return PayjoinFingerprintDetection(
        confidence=confidence,
        tracked_postmix_inputs=tracked_inputs,
        other_inputs=other_inputs,
        unnecessary_input_heuristic=unnecessary_input_heuristic,
        fingerprint_signals=fingerprint_signals,
        input_clusters=input_clusters,
        input_value_sats=input_total,
        miner_fee_sats=miner_fee,
    )


def detect_whirlpool_cpfp(
    parent: Transaction,
    parent_prevouts: Mapping[OutPoint, TxOutput],
    child: Transaction,
    child_prevouts: Mapping[OutPoint, TxOutput],
    *,
    tracked_parent_outpoints: Collection[OutPoint],
    parent_height: int | None,
    child_height: int | None,
    parent_is_whirlpool_round: bool,
) -> WhirlpoolCpfpDetection | None:
    """Return a historical same-block higher-fee child candidate."""

    if (
        parent_is_whirlpool_round is not True
        or type(parent_height) is not int
        or type(child_height) is not int
        or parent_height <= 0
        or parent_height != child_height
        or parent.txid == child.txid
        or parent.vsize <= 0
        or child.vsize <= 0
    ):
        return None

    parent_inputs = _non_coinbase_outpoints(parent)
    child_inputs = _non_coinbase_outpoints(child)
    if (
        not parent_inputs
        or not child_inputs
        or len(set(parent_inputs)) != len(parent_inputs)
        or len(set(child_inputs)) != len(child_inputs)
        or set(parent_prevouts) != set(parent_inputs)
        or set(child_prevouts) != set(child_inputs)
    ):
        return None

    tracked = tuple(
        sorted(
            set(child_inputs).intersection(tracked_parent_outpoints),
            key=lambda outpoint: (outpoint.txid, outpoint.index),
        )
    )
    if (
        not tracked
        or any(outpoint.txid != parent.txid for outpoint in tracked)
    ):
        return None

    parent_fee = _transaction_fee(parent, parent_prevouts)
    child_fee = _transaction_fee(child, child_prevouts)
    if parent_fee is None or child_fee is None:
        return None

    if child_fee * parent.vsize <= parent_fee * child.vsize:
        return None
    package_fee = parent_fee + child_fee
    package_vsize = parent.vsize + child.vsize
    if package_fee * parent.vsize <= parent_fee * package_vsize:
        return None

    return WhirlpoolCpfpDetection(
        confidence=Confidence.MEDIUM,
        parent_txid=parent.txid,
        child_txid=child.txid,
        block_height=parent_height,
        tracked_parent_outpoints=tracked,
        parent_fee_sats=parent_fee,
        parent_vsize=parent.vsize,
        child_fee_sats=child_fee,
        child_vsize=child.vsize,
        parent_fee_rate=_fee_rate(parent_fee, parent.vsize),
        child_fee_rate=_fee_rate(child_fee, child.vsize),
        package_fee_rate=_fee_rate(package_fee, package_vsize),
    )


def detect_stonewall(
    transaction: Transaction,
    prevouts: Mapping[OutPoint, TxOutput],
    *,
    tracked_postmix_inputs: Collection[OutPoint] = (),
) -> StonewallDetection | None:
    """Return a conservative Stonewall/StonewallX2 shape candidate."""

    input_outpoints = tuple(
        transaction_input.previous_output
        for transaction_input in transaction.inputs
        if not _is_coinbase(transaction_input.previous_output)
    )
    if (
        len(input_outpoints) < 2
        or len(set(input_outpoints)) != len(input_outpoints)
        or len({outpoint.txid for outpoint in input_outpoints}) < 2
        or set(prevouts) != set(input_outpoints)
    ):
        return None

    tracked_inputs = tuple(
        sorted(
            set(input_outpoints).intersection(tracked_postmix_inputs),
            key=lambda outpoint: (outpoint.txid, outpoint.index),
        )
    )
    if not tracked_inputs:
        return None

    if len(transaction.outputs) != 4:
        return None
    if any(
        output.value_sats <= 0
        or output.script_type in {ScriptType.OP_RETURN, ScriptType.UNKNOWN}
        for output in transaction.outputs
    ):
        return None

    value_counts = Counter(
        output.value_sats for output in transaction.outputs
    )
    if any(count > 2 for count in value_counts.values()):
        return None
    repeated_values = tuple(
        sorted(value for value, count in value_counts.items() if count == 2)
    )
    if not repeated_values:
        return None

    input_value = _bounded_sum(
        prevouts[outpoint].value_sats for outpoint in input_outpoints
    )
    output_value = _bounded_sum(
        output.value_sats for output in transaction.outputs
    )
    if input_value is None or output_value is None or input_value < output_value:
        return None

    indices_by_value: defaultdict[int, list[int]] = defaultdict(list)
    for output in transaction.outputs:
        if output.value_sats in repeated_values:
            indices_by_value[output.value_sats].append(output.index)
    repeated_indices = tuple(
        tuple(sorted(indices_by_value[value])) for value in repeated_values
    )

    return StonewallDetection(
        confidence=Confidence.MEDIUM,
        tracked_postmix_inputs=tracked_inputs,
        repeated_output_values_sats=repeated_values,
        repeated_output_indices=repeated_indices,
        input_count=len(input_outpoints),
        input_value_sats=input_value,
        miner_fee_sats=input_value - output_value,
    )


def detect_ricochet_entry(
    transaction: Transaction,
    *,
    tracked_postmix_inputs: Collection[OutPoint] = (),
) -> RicochetEntry | None:
    """Return a service-fee-anchored Ricochet entry candidate."""

    input_outpoints = {
        transaction_input.previous_output
        for transaction_input in transaction.inputs
        if not _is_coinbase(transaction_input.previous_output)
    }
    if not input_outpoints.intersection(tracked_postmix_inputs):
        return None
    if len(transaction.outputs) not in {2, 3}:
        return None
    if any(
        output.value_sats <= 0
        or output.script_type is not ScriptType.P2WPKH
        for output in transaction.outputs
    ):
        return None

    fee_outputs = tuple(
        output
        for output in transaction.outputs
        if output.value_sats == RICOCHET_SERVICE_FEE_SATS
    )
    if len(fee_outputs) != 1:
        return None
    fee_output = fee_outputs[0]
    continuation_candidates = tuple(
        OutPoint(transaction.txid, output.index)
        for output in transaction.outputs
        if output.index != fee_output.index
    )
    if not continuation_candidates:
        return None

    return RicochetEntry(
        confidence=Confidence.MEDIUM,
        fee_outpoint=OutPoint(transaction.txid, fee_output.index),
        fee_output=fee_output,
        continuation_candidates=continuation_candidates,
    )


def detect_ricochet_hop(
    transaction: Transaction,
    *,
    expected_input: OutPoint,
    previous_output: TxOutput,
) -> RicochetHop | None:
    """Return one serial native-SegWit Ricochet hop."""

    if (
        len(transaction.inputs) != 1
        or transaction.inputs[0].previous_output != expected_input
        or len(transaction.outputs) != 1
        or previous_output.script_type is not ScriptType.P2WPKH
        or previous_output.value_sats <= 0
        or previous_output.value_sats > MAX_MONEY_SATS
    ):
        return None

    output = transaction.outputs[0]
    if (
        output.script_type is not ScriptType.P2WPKH
        or output.value_sats <= 0
        or output.value_sats >= previous_output.value_sats
        or output.value_sats > MAX_MONEY_SATS
    ):
        return None

    return RicochetHop(
        txid=transaction.txid,
        input_outpoint=expected_input,
        output_outpoint=OutPoint(transaction.txid, output.index),
        output=output,
        miner_fee_sats=previous_output.value_sats - output.value_sats,
    )


def _bounded_sum(values: Iterable[int]) -> int | None:
    total = 0
    for value in values:
        if type(value) is not int or value < 0 or value > MAX_MONEY_SATS:
            return None
        total += value
        if total > MAX_MONEY_SATS:
            return None
    return total


def _bounded_positive_sum(values: Iterable[int]) -> int | None:
    values_tuple = tuple(values)
    if not values_tuple or any(
        type(value) is not int or value <= 0 for value in values_tuple
    ):
        return None
    return _bounded_sum(values_tuple)


def _is_standard_spendable_output(output: TxOutput) -> bool:
    return (
        type(output.value_sats) is int
        and 0 < output.value_sats <= MAX_MONEY_SATS
        and output.script_type in _STANDARD_SPENDABLE_SCRIPT_TYPES
        and classify_script(output.script_pubkey) is output.script_type
    )


def _ecdsa_fingerprint(
    transaction_input: TxInput,
    prevout_script_type: ScriptType,
) -> tuple[int, int] | None:
    if prevout_script_type is ScriptType.P2WPKH:
        witness = transaction_input.witness
        if len(witness) != 2:
            return None
        signature = witness[0]
    elif prevout_script_type is ScriptType.P2PKH:
        pushes = _canonical_script_pushes(transaction_input.script_sig)
        if pushes is None or len(pushes) != 2:
            return None
        signature = pushes[0]
    else:
        return None
    return _parse_der_signature_fingerprint(signature)


def _parse_der_signature_fingerprint(
    signature: bytes,
) -> tuple[int, int] | None:
    if not isinstance(signature, bytes) or not 9 <= len(signature) <= 73:
        return None
    der = signature[:-1]
    if len(der) < 8 or der[0] != 0x30 or der[1] != len(der) - 2:
        return None
    if der[2] != 0x02:
        return None
    r_length = der[3]
    r_start = 4
    r_end = r_start + r_length
    if (
        r_length == 0
        or r_end + 2 > len(der)
        or der[r_start] & 0x80
        or (
            r_length > 1
            and der[r_start] == 0
            and not der[r_start + 1] & 0x80
        )
        or der[r_end] != 0x02
    ):
        return None
    s_length = der[r_end + 1]
    s_start = r_end + 2
    s_end = s_start + s_length
    if (
        s_length == 0
        or s_end != len(der)
        or der[s_start] & 0x80
        or (
            s_length > 1
            and der[s_start] == 0
            and not der[s_start + 1] & 0x80
        )
    ):
        return None
    sighash = signature[-1]
    if sighash not in {1, 2, 3, 0x81, 0x82, 0x83}:
        return None
    return r_length, sighash


def _canonical_script_pushes(script: bytes) -> tuple[bytes, ...] | None:
    pushes: list[bytes] = []
    position = 0
    while position < len(script):
        opcode = script[position]
        position += 1
        if opcode == 0 or opcode > 75 or position + opcode > len(script):
            return None
        pushes.append(script[position : position + opcode])
        position += opcode
    return tuple(pushes)


def _taproot_sighash_form(
    transaction_input: TxInput,
    prevout_script_type: ScriptType,
) -> str | None:
    if prevout_script_type is not ScriptType.P2TR:
        return None
    witness = transaction_input.witness
    if len(witness) == 1:
        signature = witness[0]
    elif (
        len(witness) == 2
        and witness[1]
        and witness[1][0] == 0x50
    ):
        signature = witness[0]
    else:
        return None
    if len(signature) == 64:
        return "default"
    if (
        len(signature) == 65
        and signature[-1] in {1, 2, 3, 0x81, 0x82, 0x83}
    ):
        return "explicit"
    return None


def _transaction_fee(
    transaction: Transaction,
    prevouts: Mapping[OutPoint, TxOutput],
) -> int | None:
    input_total = _bounded_sum(
        prevouts[outpoint].value_sats
        for outpoint in _non_coinbase_outpoints(transaction)
    )
    output_total = _bounded_sum(
        output.value_sats for output in transaction.outputs
    )
    if (
        input_total is None
        or output_total is None
        or input_total < output_total
    ):
        return None
    return input_total - output_total


def _non_coinbase_outpoints(
    transaction: Transaction,
) -> tuple[OutPoint, ...]:
    return tuple(
        transaction_input.previous_output
        for transaction_input in transaction.inputs
        if not _is_coinbase(transaction_input.previous_output)
    )


def _fee_rate(fee_sats: int, vsize: int) -> str:
    return format(
        (Decimal(fee_sats) / Decimal(vsize)).quantize(
            Decimal("0.01"),
            rounding=ROUND_HALF_UP,
        ),
        ".2f",
    )


def _is_coinbase(outpoint: OutPoint) -> bool:
    return outpoint.txid == "0" * 64 and outpoint.index == 0xFFFFFFFF
