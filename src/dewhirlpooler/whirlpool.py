"""Clean-room, evidence-labelled Whirlpool transaction heuristics."""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from decimal import ROUND_HALF_UP, Decimal
from enum import StrEnum

from .bitcoin import (
    MAX_MONEY_SATS,
    OutPoint,
    ScriptType,
    Transaction,
    TxOutput,
    is_tx0_marker,
)


class Confidence(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class TransactionKind(StrEnum):
    TX0 = "tx0"
    WHIRLPOOL_ROUND = "whirlpool_round"
    UNKNOWN = "unknown"


class OutputRole(StrEnum):
    PREMIX = "premix"
    COORDINATOR_FEE = "coordinator_fee"
    DOXXIC_CHANGE = "doxxic_change"
    COINJOIN = "coinjoin"
    OP_RETURN = "op_return"
    UNCLASSIFIED = "unclassified"


@dataclass(frozen=True, slots=True)
class PoolDefinition:
    identifier: str
    protocol: str
    denomination_sats: int
    coordinator_fee_sats: int
    max_premix_outputs: int
    max_premix_reserve_sats: int
    alternate_coordinator_fee_sats: tuple[int, ...] = ()

    @property
    def documented_coordinator_fees_sats(self) -> tuple[int, ...]:
        return (
            self.coordinator_fee_sats,
            *self.alternate_coordinator_fee_sats,
        )


@dataclass(frozen=True, slots=True)
class Evidence:
    code: str
    description: str


@dataclass(frozen=True, slots=True)
class OutputClassification:
    index: int
    role: OutputRole
    confidence: Confidence
    evidence_codes: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class WhirlpoolDetection:
    kind: TransactionKind
    confidence: Confidence
    pool: PoolDefinition | None
    outputs: tuple[OutputClassification, ...]
    evidence: tuple[Evidence, ...]
    warnings: tuple[str, ...]
    premix_input_count: int
    remix_input_count: int
    input_count: int | None = None
    input_value_sats: int | None = None
    miner_fee_sats: int | None = None
    coordinator_fee_sats: int | None = None
    premix_output_count: int | None = None
    entered_pool_sats: int | None = None
    total_fee_cost_sats: int | None = None
    fee_cost_percent: str | None = None
    round_size: int | None = None


DEFAULT_POOLS: tuple[PoolDefinition, ...] = (
    PoolDefinition(
        identifier="ashigaru-0.025",
        protocol="Ashigaru",
        denomination_sats=2_500_000,
        coordinator_fee_sats=125_000,
        max_premix_outputs=20,
        max_premix_reserve_sats=100_000,
    ),
    PoolDefinition(
        identifier="ashigaru-0.25",
        protocol="Ashigaru",
        denomination_sats=25_000_000,
        coordinator_fee_sats=1_250_000,
        max_premix_outputs=20,
        max_premix_reserve_sats=100_000,
    ),
    PoolDefinition(
        identifier="samourai-legacy-0.05",
        protocol="Samourai legacy",
        denomination_sats=5_000_000,
        coordinator_fee_sats=175_000,
        max_premix_outputs=100,
        max_premix_reserve_sats=100_000,
        alternate_coordinator_fee_sats=(250_000,),
    ),
    PoolDefinition(
        identifier="samourai-legacy-0.001",
        protocol="Samourai legacy",
        denomination_sats=100_000,
        coordinator_fee_sats=5_000,
        max_premix_outputs=25,
        max_premix_reserve_sats=100_000,
    ),
    PoolDefinition(
        identifier="samourai-legacy-0.01",
        protocol="Samourai legacy",
        denomination_sats=1_000_000,
        coordinator_fee_sats=50_000,
        max_premix_outputs=75,
        max_premix_reserve_sats=100_000,
    ),
    PoolDefinition(
        identifier="samourai-legacy-0.5",
        protocol="Samourai legacy",
        denomination_sats=50_000_000,
        coordinator_fee_sats=1_750_000,
        max_premix_outputs=75,
        max_premix_reserve_sats=100_000,
        alternate_coordinator_fee_sats=(2_500_000,),
    ),
)


@dataclass(frozen=True, slots=True)
class _Candidate:
    detection: WhirlpoolDetection
    score: int


def detect_whirlpool(
    transaction: Transaction,
    prevouts: Mapping[OutPoint, TxOutput] | None = None,
    pools: Sequence[PoolDefinition] = DEFAULT_POOLS,
) -> WhirlpoolDetection:
    """Classify one transaction without making wallet-ownership claims."""

    tx0_candidates = _tx0_candidates(transaction, prevouts, pools)
    selected_tx0 = _choose_candidate(tx0_candidates)
    if selected_tx0 is not None:
        return selected_tx0
    if _has_top_score_tie(tx0_candidates):
        return _unknown(
            transaction,
            "More than one pool matched the Tx0 structure equally.",
        )

    round_candidates = _round_candidates(transaction, prevouts, pools)
    selected_round = _choose_candidate(round_candidates)
    if selected_round is not None:
        return selected_round
    if _has_top_score_tie(round_candidates):
        return _unknown(
            transaction,
            "More than one pool matched the round structure equally.",
        )

    return _unknown(transaction)


def _tx0_candidates(
    transaction: Transaction,
    prevouts: Mapping[OutPoint, TxOutput] | None,
    pools: Sequence[PoolDefinition],
) -> list[_Candidate]:
    accounting = _resolved_input_accounting(transaction, prevouts)
    if accounting is _INVALID_ACCOUNTING:
        return []

    markers = [output for output in transaction.outputs if is_tx0_marker(output)]
    candidates: list[_Candidate] = []

    for pool in pools:
        fee_outputs = [
            output
            for output in transaction.outputs
            if output.script_type is ScriptType.P2WPKH
            and output.value_sats
            in pool.documented_coordinator_fees_sats
        ]
        premix_groups: dict[int, list[TxOutput]] = defaultdict(list)
        for output in transaction.outputs:
            reserve = output.value_sats - pool.denomination_sats
            if (
                output.script_type is ScriptType.P2WPKH
                and 0 < reserve <= pool.max_premix_reserve_sats
            ):
                premix_groups[output.value_sats].append(output)

        for premix_outputs in premix_groups.values():
            if not 1 <= len(premix_outputs) <= pool.max_premix_outputs:
                continue
            if not markers and not fee_outputs:
                continue

            score = 4
            evidence = [
                Evidence(
                    "equal_premix_outputs",
                    f"{len(premix_outputs)} equal native SegWit output(s) "
                    "sit just above the pool denomination.",
                )
            ]
            if len(markers) == 1:
                score += 4
                evidence.append(
                    Evidence(
                        "tx0_marker",
                        "One zero-value OP_RETURN carries 64 pushed data bytes.",
                    )
                )
            if len(fee_outputs) == 1:
                score += 4
                evidence.append(
                    Evidence(
                        "coordinator_fee",
                        "One native SegWit output matches the documented "
                        "coordinator fee.",
                    )
                )

            selected_indices = {output.index for output in premix_outputs}
            selected_indices.update(output.index for output in markers)
            selected_indices.update(output.index for output in fee_outputs)
            unclassified_outputs = [
                output
                for output in transaction.outputs
                if output.index not in selected_indices
            ]
            change_outputs = (
                unclassified_outputs
                if len(unclassified_outputs) == 1
                and unclassified_outputs[0].value_sats > 0
                and unclassified_outputs[0].script_type is ScriptType.P2WPKH
                else []
            )
            if change_outputs:
                score += 1
                evidence.append(
                    Evidence(
                        "unique_change",
                        "One positive native SegWit output remains after the "
                        "premix and fee candidates.",
                    )
                )

            warnings: list[str] = []
            confidence = (
                Confidence.HIGH
                if len(markers) == 1 and len(fee_outputs) == 1
                and (not unclassified_outputs or change_outputs)
                else Confidence.MEDIUM
            )
            if len(markers) != 1:
                warnings.append(
                    "The transaction does not have one standard Tx0 marker."
                )
            if len(fee_outputs) != 1:
                warnings.append(
                    "The transaction does not have one exact coordinator-fee output."
                )
            if unclassified_outputs and not change_outputs:
                warnings.append(
                    "Multiple or nonstandard residual outputs prevent a unique "
                    "doxxic-change classification."
                )
            if pool.protocol == "Samourai legacy":
                warnings.append(
                    "Discounted historical Samourai coordinator fees require "
                    "the coordinator address/history index and are not inferred."
                )

            coordinator_fee_sats = sum(
                output.value_sats for output in fee_outputs
            )
            premix_output_count = len(premix_outputs)
            entered_pool_sats = (
                premix_output_count * pool.denomination_sats
            )
            if entered_pool_sats <= 0 or entered_pool_sats > MAX_MONEY_SATS:
                continue
            if accounting is None:
                input_count = None
                input_value_sats = None
                miner_fee_sats = None
                total_fee_cost_sats = None
                fee_cost_percent = None
            else:
                input_count, input_value_sats, miner_fee_sats = accounting
                total_fee_cost_sats = (
                    miner_fee_sats + coordinator_fee_sats
                )
                fee_cost_percent = _percentage(
                    total_fee_cost_sats,
                    entered_pool_sats,
                )

            role_by_index = {
                output.index: OutputRole.PREMIX for output in premix_outputs
            }
            role_by_index.update(
                {output.index: OutputRole.OP_RETURN for output in markers}
            )
            role_by_index.update(
                {
                    output.index: OutputRole.COORDINATOR_FEE
                    for output in fee_outputs
                }
            )
            role_by_index.update(
                {
                    output.index: OutputRole.DOXXIC_CHANGE
                    for output in change_outputs
                }
            )
            outputs = tuple(
                OutputClassification(
                    index=output.index,
                    role=role_by_index.get(
                        output.index,
                        OutputRole.UNCLASSIFIED,
                    ),
                    confidence=(
                        confidence
                        if output.index in role_by_index
                        else Confidence.LOW
                    ),
                    evidence_codes=_role_evidence_codes(
                        role_by_index.get(
                            output.index,
                            OutputRole.UNCLASSIFIED,
                        )
                    ),
                )
                for output in transaction.outputs
            )
            candidates.append(
                _Candidate(
                    WhirlpoolDetection(
                        kind=TransactionKind.TX0,
                        confidence=confidence,
                        pool=pool,
                        outputs=outputs,
                        evidence=tuple(evidence),
                        warnings=tuple(warnings),
                        premix_input_count=0,
                        remix_input_count=0,
                        input_count=input_count,
                        input_value_sats=input_value_sats,
                        miner_fee_sats=miner_fee_sats,
                        coordinator_fee_sats=coordinator_fee_sats,
                        premix_output_count=premix_output_count,
                        entered_pool_sats=entered_pool_sats,
                        total_fee_cost_sats=total_fee_cost_sats,
                        fee_cost_percent=fee_cost_percent,
                    ),
                    score,
                )
            )

    return candidates


def _round_candidates(
    transaction: Transaction,
    prevouts: Mapping[OutPoint, TxOutput] | None,
    pools: Sequence[PoolDefinition],
) -> list[_Candidate]:
    round_size = len(transaction.inputs)
    if (
        round_size != len(transaction.outputs)
        or not 5 <= round_size <= 8
    ):
        return []
    if any(
        output.script_type is not ScriptType.P2WPKH
        for output in transaction.outputs
    ):
        return []

    candidates: list[_Candidate] = []
    for pool in pools:
        if any(
            output.value_sats != pool.denomination_sats
            for output in transaction.outputs
        ):
            continue

        evidence = [
            Evidence(
                "equal_denomination_round",
                f"The transaction has {round_size} inputs and {round_size} "
                "equal native SegWit outputs at the pool denomination.",
            )
        ]
        warnings: list[str] = []
        confidence = Confidence.MEDIUM
        score = 5
        premix_input_count = 0
        remix_input_count = 0
        input_count: int | None = None
        input_value_sats: int | None = None
        miner_fee_sats: int | None = None

        accounting = _resolved_input_accounting(transaction, prevouts)
        if accounting is _INVALID_ACCOUNTING:
            continue
        if accounting is None:
            warnings.append(
                "Direct previous outputs were unavailable, so input values "
                "could not be confirmed."
            )
        else:
            input_count, input_value_sats, miner_fee_sats = accounting
            valid_inputs = True
            for transaction_input in transaction.inputs:
                assert prevouts is not None
                previous_output = prevouts[transaction_input.previous_output]
                if previous_output.script_type is not ScriptType.P2WPKH:
                    valid_inputs = False
                    break
                reserve = previous_output.value_sats - pool.denomination_sats
                if reserve == 0:
                    remix_input_count += 1
                elif 0 < reserve <= pool.max_premix_reserve_sats:
                    premix_input_count += 1
                else:
                    valid_inputs = False
                    break

            if not valid_inputs:
                continue
            confidence = Confidence.HIGH
            score += 5
            evidence.append(
                Evidence(
                    "validated_prevouts",
                    f"All {round_size} direct inputs are plausible premix or "
                    "remix outputs and fund a nonnegative miner fee.",
                )
            )

        outputs = tuple(
            OutputClassification(
                index=output.index,
                role=OutputRole.COINJOIN,
                confidence=confidence,
                evidence_codes=("equal_denomination_round",),
            )
            for output in transaction.outputs
        )
        candidates.append(
            _Candidate(
                WhirlpoolDetection(
                    kind=TransactionKind.WHIRLPOOL_ROUND,
                    confidence=confidence,
                    pool=pool,
                    outputs=outputs,
                    evidence=tuple(evidence),
                    warnings=tuple(warnings),
                    premix_input_count=premix_input_count,
                    remix_input_count=remix_input_count,
                    input_count=input_count,
                    input_value_sats=input_value_sats,
                    miner_fee_sats=miner_fee_sats,
                    round_size=round_size,
                ),
                score,
            )
        )

    return candidates


def _choose_candidate(
    candidates: Sequence[_Candidate],
) -> WhirlpoolDetection | None:
    if not candidates:
        return None
    top_score = max(candidate.score for candidate in candidates)
    top = [candidate for candidate in candidates if candidate.score == top_score]
    return top[0].detection if len(top) == 1 else None


def _has_top_score_tie(candidates: Sequence[_Candidate]) -> bool:
    if len(candidates) < 2:
        return False
    top_score = max(candidate.score for candidate in candidates)
    return sum(candidate.score == top_score for candidate in candidates) > 1


def _unknown(
    transaction: Transaction,
    warning: str | None = None,
) -> WhirlpoolDetection:
    return WhirlpoolDetection(
        kind=TransactionKind.UNKNOWN,
        confidence=Confidence.LOW,
        pool=None,
        outputs=tuple(
            OutputClassification(
                index=output.index,
                role=OutputRole.UNCLASSIFIED,
                confidence=Confidence.LOW,
                evidence_codes=(),
            )
            for output in transaction.outputs
        ),
        evidence=(),
        warnings=(warning,) if warning else (),
        premix_input_count=0,
        remix_input_count=0,
    )


_INVALID_ACCOUNTING = object()


def _resolved_input_accounting(
    transaction: Transaction,
    prevouts: Mapping[OutPoint, TxOutput] | None,
) -> tuple[int, int, int] | None | object:
    """Return exact input count/value/miner fee, unavailable, or invalid."""

    if prevouts is None or not prevouts:
        return None
    if any(
        transaction_input.previous_output not in prevouts
        for transaction_input in transaction.inputs
    ):
        return _INVALID_ACCOUNTING

    input_total = 0
    for transaction_input in transaction.inputs:
        value_sats = prevouts[
            transaction_input.previous_output
        ].value_sats
        if value_sats < 0:
            return _INVALID_ACCOUNTING
        input_total += value_sats
        if input_total > MAX_MONEY_SATS:
            return _INVALID_ACCOUNTING

    output_total = 0
    for output in transaction.outputs:
        output_total += output.value_sats
        if output_total > MAX_MONEY_SATS:
            return _INVALID_ACCOUNTING

    miner_fee_sats = input_total - output_total
    if miner_fee_sats < 0:
        return _INVALID_ACCOUNTING
    return len(transaction.inputs), input_total, miner_fee_sats


def _percentage(numerator: int, denominator: int) -> str:
    value = (
        Decimal(numerator) * Decimal(100) / Decimal(denominator)
    ).quantize(Decimal("0.0001"), rounding=ROUND_HALF_UP)
    return format(value, ".4f")


def _role_evidence_codes(role: OutputRole) -> tuple[str, ...]:
    return {
        OutputRole.PREMIX: ("equal_premix_outputs",),
        OutputRole.COORDINATOR_FEE: ("coordinator_fee",),
        OutputRole.DOXXIC_CHANGE: ("unique_change",),
        OutputRole.OP_RETURN: ("tx0_marker",),
    }.get(role, ())
