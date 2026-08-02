"""Bounded, evidence-labelled traversal of possible Whirlpool exposure."""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, fields, replace
from decimal import ROUND_HALF_UP, Decimal
from enum import StrEnum

from .bitcoin import (
    OutPoint,
    ScriptType,
    Transaction,
    TxOutput,
    encode_p2wpkh_address,
)
from .postmix import (
    RicochetEntry,
    RicochetHop,
    detect_payjoin_fingerprints,
    detect_ricochet_entry,
    detect_ricochet_hop,
    detect_stonewall,
    detect_whirlpool_cpfp,
)
from .resolver import TransactionResolver
from .whirlpool import (
    Confidence,
    OutputRole,
    TransactionKind,
    WhirlpoolDetection,
    detect_whirlpool,
)


class TraceNodeKind(StrEnum):
    TRANSACTION = "transaction"
    OUTPUT = "output"


class TraceEdgeKind(StrEnum):
    CREATES = "creates"
    SPENDS = "spends"
    POSSIBLE_COINJOIN_LINK = "possible_coinjoin_link"


class TraceFindingKind(StrEnum):
    DOXXIC_CHANGE_SPEND = "doxxic_change_spend"
    LATER_TX0 = "later_tx0"
    WHIRLPOOL_ENTRY = "whirlpool_entry"
    POSTMIX_CONSOLIDATION = "postmix_consolidation"
    POSTMIX_PAYMENT_CONSOLIDATION = "postmix_payment_consolidation"
    STONEWALL = "stonewall"
    RICOCHET = "ricochet"
    WHIRLPOOL_CPFP = "whirlpool_cpfp"
    ADDRESS_REUSE = "address_reuse"
    POSTMIX_PAYJOIN_FINGERPRINT = "postmix_payjoin_fingerprint"
    POSSIBLE_PAYMENT = "possible_payment"
    UNSPENT = "unspent"


class _Ancestry(StrEnum):
    DOXXIC_CHANGE = "doxxic_change"
    PREMIX = "premix"
    POSTMIX = "postmix"
    POSSIBLE_PAYMENT = "possible_payment"


@dataclass(frozen=True, slots=True)
class TraceLimits:
    max_depth: int = 8
    max_transactions: int = 100
    max_outputs: int = 250
    max_history_lookups: int = 250

    def __post_init__(self) -> None:
        for field in fields(self):
            value = getattr(self, field.name)
            if type(value) is not int or value <= 0:
                raise ValueError(
                    f"{field.name.replace('_', ' ')} must be a positive integer"
                )


@dataclass(frozen=True, slots=True)
class TraceNode:
    id: str
    kind: TraceNodeKind
    txid: str
    output_index: int | None
    value_sats: int | None
    script_type: str | None
    transaction_kind: str | None
    pool: str | None
    role: str | None
    status: str | None
    confidence: Confidence


@dataclass(frozen=True, slots=True)
class TraceEdge:
    id: str
    source: str
    target: str
    kind: TraceEdgeKind
    confidence: Confidence
    explanation: str


@dataclass(frozen=True, slots=True)
class TraceFinding:
    kind: TraceFindingKind
    confidence: Confidence
    txid: str
    outpoints: tuple[OutPoint, ...]
    explanation: str
    repeated_output_values_sats: tuple[int, ...] = ()
    service_fee_sats: int | None = None
    service_fee_address: str | None = None
    hop_txids: tuple[str, ...] = ()
    reused_address: str | None = None
    reused_roles: tuple[str, ...] = ()
    cpfp_parent_txid: str | None = None
    cpfp_block_height: int | None = None
    cpfp_parent_fee_sats: int | None = None
    cpfp_parent_vsize: int | None = None
    cpfp_child_fee_sats: int | None = None
    cpfp_child_vsize: int | None = None
    cpfp_parent_fee_rate: str | None = None
    cpfp_child_fee_rate: str | None = None
    cpfp_package_fee_rate: str | None = None
    payjoin_unnecessary_input_heuristic: str | None = None
    payjoin_fingerprint_signals: tuple[str, ...] = ()
    payjoin_input_clusters: tuple[tuple[int, ...], ...] = ()


@dataclass(frozen=True, slots=True)
class TraceSummary:
    transactions_examined: int
    outputs_examined: int
    whirlpool_rounds: int
    later_tx0s: int
    postmix_consolidations: int
    possible_payments: int
    unspent_output_count: int
    unspent_sats: int
    stonewall_spends: int = 0
    ricochet_spends: int = 0
    postmix_payment_consolidations: int = 0
    address_reuse_findings: int = 0
    whirlpool_cpfp_findings: int = 0
    postmix_payjoin_fingerprint_candidates: int = 0


@dataclass(frozen=True, slots=True)
class TraceTransaction:
    txid: str
    kind: TransactionKind
    confidence: Confidence
    pool: str | None
    input_count: int | None
    input_value_sats: int | None
    miner_fee_sats: int | None
    coordinator_fee_sats: int | None
    premix_output_count: int | None
    entered_pool_sats: int | None
    total_fee_cost_sats: int | None
    fee_cost_percent: str | None
    round_size: int | None
    premix_input_count: int
    remix_input_count: int
    new_entrant_ratio: str | None
    remixer_ratio: str | None
    doxxic_change_enters_later_tx0: bool


@dataclass(frozen=True, slots=True)
class TraceReport:
    root_txid: str
    nodes: tuple[TraceNode, ...]
    edges: tuple[TraceEdge, ...]
    findings: tuple[TraceFinding, ...]
    summary: TraceSummary
    warnings: tuple[str, ...]
    truncated: bool
    transactions: tuple[TraceTransaction, ...] = ()

    def to_dict(self) -> dict[str, object]:
        return {
            "root_txid": self.root_txid,
            "transactions": [
                {
                    "txid": transaction.txid,
                    "kind": transaction.kind.value,
                    "confidence": transaction.confidence.value,
                    "pool": transaction.pool,
                    "input_count": transaction.input_count,
                    "input_value_sats": transaction.input_value_sats,
                    "miner_fee_sats": transaction.miner_fee_sats,
                    "coordinator_fee_sats": (
                        transaction.coordinator_fee_sats
                    ),
                    "premix_output_count": transaction.premix_output_count,
                    "entered_pool_sats": transaction.entered_pool_sats,
                    "total_fee_cost_sats": transaction.total_fee_cost_sats,
                    "fee_cost_percent": transaction.fee_cost_percent,
                    "round_size": transaction.round_size,
                    "premix_input_count": transaction.premix_input_count,
                    "remix_input_count": transaction.remix_input_count,
                    "new_entrant_ratio": transaction.new_entrant_ratio,
                    "remixer_ratio": transaction.remixer_ratio,
                    "doxxic_change_enters_later_tx0": (
                        transaction.doxxic_change_enters_later_tx0
                    ),
                }
                for transaction in self.transactions
            ],
            "nodes": [
                {
                    "id": node.id,
                    "kind": node.kind.value,
                    "txid": node.txid,
                    "output_index": node.output_index,
                    "value_sats": node.value_sats,
                    "script_type": node.script_type,
                    "transaction_kind": node.transaction_kind,
                    "pool": node.pool,
                    "role": node.role,
                    "status": node.status,
                    "confidence": node.confidence.value,
                }
                for node in self.nodes
            ],
            "edges": [
                {
                    "id": edge.id,
                    "source": edge.source,
                    "target": edge.target,
                    "kind": edge.kind.value,
                    "confidence": edge.confidence.value,
                    "explanation": edge.explanation,
                }
                for edge in self.edges
            ],
            "findings": [
                {
                    "kind": finding.kind.value,
                    "confidence": finding.confidence.value,
                    "txid": finding.txid,
                    "outpoints": [
                        {"txid": outpoint.txid, "index": outpoint.index}
                        for outpoint in finding.outpoints
                    ],
                    "explanation": finding.explanation,
                    "repeated_output_values_sats": list(
                        finding.repeated_output_values_sats
                    ),
                    "service_fee_sats": finding.service_fee_sats,
                    "service_fee_address": finding.service_fee_address,
                    "hop_txids": list(finding.hop_txids),
                    "reused_address": finding.reused_address,
                    "reused_roles": list(finding.reused_roles),
                    "cpfp_parent_txid": finding.cpfp_parent_txid,
                    "cpfp_block_height": finding.cpfp_block_height,
                    "cpfp_parent_fee_sats": finding.cpfp_parent_fee_sats,
                    "cpfp_parent_vsize": finding.cpfp_parent_vsize,
                    "cpfp_child_fee_sats": finding.cpfp_child_fee_sats,
                    "cpfp_child_vsize": finding.cpfp_child_vsize,
                    "cpfp_parent_fee_rate": finding.cpfp_parent_fee_rate,
                    "cpfp_child_fee_rate": finding.cpfp_child_fee_rate,
                    "cpfp_package_fee_rate": finding.cpfp_package_fee_rate,
                    "payjoin_unnecessary_input_heuristic": (
                        finding.payjoin_unnecessary_input_heuristic
                    ),
                    "payjoin_fingerprint_signals": list(
                        finding.payjoin_fingerprint_signals
                    ),
                    "payjoin_input_clusters": [
                        list(cluster)
                        for cluster in finding.payjoin_input_clusters
                    ],
                }
                for finding in self.findings
            ],
            "summary": {
                "transactions_examined": self.summary.transactions_examined,
                "outputs_examined": self.summary.outputs_examined,
                "whirlpool_rounds": self.summary.whirlpool_rounds,
                "later_tx0s": self.summary.later_tx0s,
                "postmix_consolidations": (
                    self.summary.postmix_consolidations
                ),
                "stonewall_spends": self.summary.stonewall_spends,
                "ricochet_spends": self.summary.ricochet_spends,
                "postmix_payment_consolidations": (
                    self.summary.postmix_payment_consolidations
                ),
                "address_reuse_findings": (
                    self.summary.address_reuse_findings
                ),
                "whirlpool_cpfp_findings": (
                    self.summary.whirlpool_cpfp_findings
                ),
                "postmix_payjoin_fingerprint_candidates": (
                    self.summary.postmix_payjoin_fingerprint_candidates
                ),
                "possible_payments": self.summary.possible_payments,
                "unspent_output_count": self.summary.unspent_output_count,
                "unspent_sats": self.summary.unspent_sats,
            },
            "warnings": list(self.warnings),
            "truncated": self.truncated,
        }


@dataclass(frozen=True, slots=True)
class _FrontierItem:
    outpoint: OutPoint
    output: TxOutput
    ancestry: _Ancestry
    confidence: Confidence
    depth: int
    allow_recursive: bool


class ExposureTracer:
    """Traverse public spends while preserving coinjoin ambiguity."""

    def __init__(
        self,
        resolver: TransactionResolver,
        limits: TraceLimits = TraceLimits(),
    ) -> None:
        self._resolver = resolver
        self._limits = limits

    def trace(self, root_txid: str) -> TraceReport:
        self._nodes: dict[str, TraceNode] = {}
        self._edges: dict[str, TraceEdge] = {}
        self._findings: dict[tuple[object, ...], TraceFinding] = {}
        self._warnings: set[str] = set()
        self._detections: dict[str, WhirlpoolDetection] = {}
        self._prevouts: dict[str, dict[OutPoint, TxOutput]] = {}
        self._transactions: dict[str, Transaction] = {}
        self._ancestry: dict[OutPoint, set[_Ancestry]] = {}
        self._spend_cache: dict[OutPoint, Transaction | None] = {}
        self._looked_up_outpoints: set[OutPoint] = set()
        self._visited_states: set[tuple[OutPoint, _Ancestry]] = set()
        self._truncated = False

        root = self._resolver.transaction(root_txid)
        root_detection = self._detection(root)
        self._add_transaction(root, root_detection)

        if root_detection.kind is TransactionKind.UNKNOWN:
            self._warnings.add(
                "The root transaction does not match a supported Whirlpool "
                "pattern, so no exposure branches were followed."
            )
            return self._report(root.txid)

        self._add_previous_generation(root)
        frontier: deque[_FrontierItem] = deque()
        if root_detection.kind is TransactionKind.TX0:
            self._enqueue_roles(
                frontier,
                root,
                root_detection,
                {
                    OutputRole.PREMIX: _Ancestry.PREMIX,
                    OutputRole.DOXXIC_CHANGE: _Ancestry.DOXXIC_CHANGE,
                },
                depth=0,
            )
        else:
            self._enqueue_roles(
                frontier,
                root,
                root_detection,
                {OutputRole.COINJOIN: _Ancestry.POSTMIX},
                depth=0,
                confidence_cap=Confidence.MEDIUM,
            )

        while frontier:
            item = frontier.popleft()
            state = (item.outpoint, item.ancestry)
            if state in self._visited_states:
                continue
            self._visited_states.add(state)

            if item.depth >= self._limits.max_depth:
                self._truncate(
                    "Maximum trace depth reached; deeper spends were not followed."
                )
                continue
            spending = self._spending_transaction(item)
            if spending is _LIMIT_REACHED:
                break
            if spending is None:
                self._mark_output_status(item.outpoint, "unspent")
                self._add_finding(
                    TraceFinding(
                        kind=TraceFindingKind.UNSPENT,
                        confidence=item.confidence,
                        txid=item.outpoint.txid,
                        outpoints=(item.outpoint,),
                        explanation="No spending transaction was found for this "
                        "tracked output.",
                    )
                )
                continue

            spending_detection = self._detection(spending)
            if not self._add_transaction(spending, spending_detection):
                break
            self._add_previous_generation(spending)
            self._mark_output_status(item.outpoint, "spent")
            self._add_edge(
                source=_output_node_id(item.outpoint),
                target=_transaction_node_id(spending.txid),
                kind=TraceEdgeKind.SPENDS,
                confidence=Confidence.HIGH,
                explanation="The spending transaction directly references "
                "this output.",
            )
            self._add_whirlpool_cpfp_finding(item, spending)

            if item.ancestry is _Ancestry.DOXXIC_CHANGE:
                self._add_finding(
                    TraceFinding(
                        kind=TraceFindingKind.DOXXIC_CHANGE_SPEND,
                        confidence=item.confidence,
                        txid=spending.txid,
                        outpoints=(item.outpoint,),
                        explanation="The candidate doxxic-change output is "
                        "directly spent here.",
                    )
                )

            if not item.allow_recursive:
                continue

            next_depth = item.depth + 1
            if spending_detection.kind is TransactionKind.WHIRLPOOL_ROUND:
                self._follow_round(
                    frontier,
                    item,
                    spending,
                    spending_detection,
                    next_depth,
                )
            elif spending_detection.kind is TransactionKind.TX0:
                if item.ancestry is _Ancestry.DOXXIC_CHANGE:
                    self._add_finding(
                        TraceFinding(
                            kind=TraceFindingKind.LATER_TX0,
                            confidence=spending_detection.confidence,
                            txid=spending.txid,
                            outpoints=(item.outpoint,),
                            explanation="Candidate doxxic change enters another "
                            "candidate Tx0.",
                        )
                    )
                self._enqueue_roles(
                    frontier,
                    spending,
                    spending_detection,
                    {
                        OutputRole.PREMIX: _Ancestry.PREMIX,
                        OutputRole.DOXXIC_CHANGE: _Ancestry.DOXXIC_CHANGE,
                    },
                    depth=next_depth,
                )
            else:
                self._follow_ordinary_spend(
                    frontier,
                    spending,
                    spending_detection,
                    next_depth,
                )

        return self._report(root.txid)

    def _detection(self, transaction: Transaction) -> WhirlpoolDetection:
        cached = self._detections.get(transaction.txid)
        if cached is not None:
            return cached
        prevouts = self._resolver.prevouts(transaction)
        detection = detect_whirlpool(transaction, prevouts)
        self._detections[transaction.txid] = detection
        self._prevouts[transaction.txid] = dict(prevouts)
        self._transactions[transaction.txid] = transaction
        return detection

    def _add_transaction(
        self,
        transaction: Transaction,
        detection: WhirlpoolDetection,
    ) -> bool:
        transaction_id = _transaction_node_id(transaction.txid)
        existing_transaction = self._nodes.get(transaction_id)
        if (
            existing_transaction is not None
            and existing_transaction.role != "previous_generation"
        ):
            return True
        if existing_transaction is None:
            transaction_count = sum(
                node.kind is TraceNodeKind.TRANSACTION
                for node in self._nodes.values()
            )
            if transaction_count >= self._limits.max_transactions:
                self._truncate(
                    "Maximum transaction count reached; the report is partial."
                )
                return False

        self._nodes[transaction_id] = TraceNode(
            id=transaction_id,
            kind=TraceNodeKind.TRANSACTION,
            txid=transaction.txid,
            output_index=None,
            value_sats=None,
            script_type=None,
            transaction_kind=detection.kind.value,
            pool=(
                detection.pool.identifier
                if detection.pool is not None
                else None
            ),
            role=None,
            status=None,
            confidence=detection.confidence,
        )
        roles = {
            classification.index: classification
            for classification in detection.outputs
        }
        for output in transaction.outputs:
            output_id = _output_node_id(
                OutPoint(transaction.txid, output.index)
            )
            classification = roles.get(output.index)
            if output_id not in self._nodes:
                output_count = sum(
                    node.kind is TraceNodeKind.OUTPUT
                    for node in self._nodes.values()
                )
                if output_count >= self._limits.max_outputs:
                    self._truncate(
                        "Maximum output count reached; the report is partial."
                    )
                    break
                self._nodes[output_id] = TraceNode(
                    id=output_id,
                    kind=TraceNodeKind.OUTPUT,
                    txid=transaction.txid,
                    output_index=output.index,
                    value_sats=output.value_sats,
                    script_type=output.script_type.value,
                    transaction_kind=None,
                    pool=None,
                    role=(
                        classification.role.value
                        if classification is not None
                        else OutputRole.UNCLASSIFIED.value
                    ),
                    status="unknown",
                    confidence=(
                        classification.confidence
                        if classification is not None
                        else Confidence.LOW
                    ),
                )
            elif self._nodes[output_id].role == "previous_generation":
                self._nodes[output_id] = replace(
                    self._nodes[output_id],
                    role=(
                        classification.role.value
                        if classification is not None
                        else OutputRole.UNCLASSIFIED.value
                    ),
                    confidence=(
                        classification.confidence
                        if classification is not None
                        else Confidence.LOW
                    ),
                )
            self._add_edge(
                source=transaction_id,
                target=output_id,
                kind=TraceEdgeKind.CREATES,
                confidence=Confidence.HIGH,
                explanation="The transaction creates this output.",
            )
        return True

    def _add_previous_generation(self, transaction: Transaction) -> None:
        """Add exact input prevouts as one non-recursive context generation."""

        for transaction_input in transaction.inputs:
            outpoint = transaction_input.previous_output
            output = self._prevouts.get(transaction.txid, {}).get(outpoint)
            if output is None:
                continue

            transaction_id = _transaction_node_id(outpoint.txid)
            output_id = _output_node_id(outpoint)
            needs_transaction = transaction_id not in self._nodes
            needs_output = output_id not in self._nodes
            if needs_transaction:
                transaction_count = sum(
                    node.kind is TraceNodeKind.TRANSACTION
                    for node in self._nodes.values()
                )
                if transaction_count >= self._limits.max_transactions:
                    self._truncate(
                        "Maximum transaction count reached; previous-generation "
                        "context is partial."
                    )
                    return
            if needs_output:
                output_count = sum(
                    node.kind is TraceNodeKind.OUTPUT
                    for node in self._nodes.values()
                )
                if output_count >= self._limits.max_outputs:
                    self._truncate(
                        "Maximum output count reached; previous-generation "
                        "context is partial."
                    )
                    return

            if needs_transaction:
                self._nodes[transaction_id] = TraceNode(
                    id=transaction_id,
                    kind=TraceNodeKind.TRANSACTION,
                    txid=outpoint.txid,
                    output_index=None,
                    value_sats=None,
                    script_type=None,
                    transaction_kind=TransactionKind.UNKNOWN.value,
                    pool=None,
                    role="previous_generation",
                    status=None,
                    confidence=Confidence.LOW,
                )

            if needs_output:
                self._nodes[output_id] = TraceNode(
                    id=output_id,
                    kind=TraceNodeKind.OUTPUT,
                    txid=outpoint.txid,
                    output_index=outpoint.index,
                    value_sats=output.value_sats,
                    script_type=output.script_type.value,
                    transaction_kind=None,
                    pool=None,
                    role="previous_generation",
                    status="spent",
                    confidence=Confidence.HIGH,
                )
            else:
                self._mark_output_status(outpoint, "spent")

            self._add_edge(
                source=transaction_id,
                target=output_id,
                kind=TraceEdgeKind.CREATES,
                confidence=Confidence.HIGH,
                explanation="The previous transaction creates this input.",
            )
            self._add_edge(
                source=output_id,
                target=_transaction_node_id(transaction.txid),
                kind=TraceEdgeKind.SPENDS,
                confidence=Confidence.HIGH,
                explanation="This resolved previous output is spent here.",
            )

    def _enqueue_roles(
        self,
        frontier: deque[_FrontierItem],
        transaction: Transaction,
        detection: WhirlpoolDetection,
        roles: dict[OutputRole, _Ancestry],
        *,
        depth: int,
        confidence_cap: Confidence | None = None,
    ) -> None:
        for classification in detection.outputs:
            ancestry = roles.get(classification.role)
            if ancestry is None:
                continue
            outpoint = OutPoint(transaction.txid, classification.index)
            if _output_node_id(outpoint) not in self._nodes:
                continue
            confidence = classification.confidence
            if confidence_cap is not None:
                confidence = _lower_confidence(confidence, confidence_cap)
            self._ancestry.setdefault(outpoint, set()).add(ancestry)
            self._mark_output_role(
                outpoint,
                classification.role.value,
                confidence,
            )
            frontier.append(
                _FrontierItem(
                    outpoint=outpoint,
                    output=transaction.outputs[classification.index],
                    ancestry=ancestry,
                    confidence=confidence,
                    depth=depth,
                    allow_recursive=True,
                )
            )

    def _spending_transaction(
        self,
        item: _FrontierItem,
    ) -> Transaction | None | object:
        cached = self._spend_cache.get(item.outpoint, _NOT_CACHED)
        if cached is not _NOT_CACHED:
            return cached
        if (
            len(self._looked_up_outpoints)
            >= self._limits.max_history_lookups
        ):
            self._truncate(
                "Maximum history lookup count reached; the report is partial."
            )
            return _LIMIT_REACHED
        self._looked_up_outpoints.add(item.outpoint)
        spending = self._resolver.spending_transaction(
            item.outpoint,
            item.output,
        )
        self._spend_cache[item.outpoint] = spending
        return spending

    def _follow_round(
        self,
        frontier: deque[_FrontierItem],
        source_item: _FrontierItem,
        transaction: Transaction,
        detection: WhirlpoolDetection,
        depth: int,
    ) -> None:
        self._add_finding(
            TraceFinding(
                kind=TraceFindingKind.WHIRLPOOL_ENTRY,
                confidence=detection.confidence,
                txid=transaction.txid,
                outpoints=(source_item.outpoint,),
                explanation="A tracked premix or possible postmix output "
                "enters this candidate Whirlpool round.",
            )
        )
        next_confidence = _coinjoin_confidence(source_item.confidence)
        for classification in detection.outputs:
            if classification.role is not OutputRole.COINJOIN:
                continue
            outpoint = OutPoint(transaction.txid, classification.index)
            if _output_node_id(outpoint) not in self._nodes:
                continue
            self._add_edge(
                source=_output_node_id(source_item.outpoint),
                target=_output_node_id(outpoint),
                kind=TraceEdgeKind.POSSIBLE_COINJOIN_LINK,
                confidence=next_confidence,
                explanation="Any equal output may follow the tracked input; "
                "the coinjoin removes a deterministic link.",
            )
            self._ancestry.setdefault(outpoint, set()).add(_Ancestry.POSTMIX)
            self._mark_output_role(
                outpoint,
                OutputRole.COINJOIN.value,
                next_confidence,
            )
            frontier.append(
                _FrontierItem(
                    outpoint=outpoint,
                    output=transaction.outputs[classification.index],
                    ancestry=_Ancestry.POSTMIX,
                    confidence=next_confidence,
                    depth=depth,
                    allow_recursive=True,
                )
            )

    def _follow_ordinary_spend(
        self,
        frontier: deque[_FrontierItem],
        transaction: Transaction,
        detection: WhirlpoolDetection,
        depth: int,
    ) -> None:
        tracked_postmix_inputs = tuple(
            sorted(
                (
                    transaction_input.previous_output
                    for transaction_input in transaction.inputs
                    if _Ancestry.POSTMIX
                    in self._ancestry.get(
                        transaction_input.previous_output,
                        set(),
                    )
                ),
                key=lambda outpoint: (outpoint.txid, outpoint.index),
            )
        )
        if len(tracked_postmix_inputs) >= 2:
            self._add_finding(
                TraceFinding(
                    kind=TraceFindingKind.POSTMIX_CONSOLIDATION,
                    confidence=Confidence.HIGH,
                    txid=transaction.txid,
                    outpoints=tracked_postmix_inputs,
                    explanation="This transaction co-spends multiple possible "
                    "postmix descendants. The co-spend is observed; common "
                    "control remains a heuristic.",
                )
            )
        spendable_outputs = tuple(
            output
            for output in transaction.outputs
            if (
                output.value_sats > 0
                and output.script_type is not ScriptType.OP_RETURN
            )
        )
        if (
            len(tracked_postmix_inputs) >= 3
            and len(spendable_outputs) == 1
        ):
            self._add_finding(
                TraceFinding(
                    kind=(
                        TraceFindingKind.POSTMIX_PAYMENT_CONSOLIDATION
                    ),
                    confidence=Confidence.MEDIUM,
                    txid=transaction.txid,
                    outpoints=tracked_postmix_inputs,
                    explanation=(
                        "Three or more possible postmix descendants are "
                        "directly co-spent into one spendable output, a shape "
                        "consistent with a Tx0 to Whirlpool to payment "
                        "consolidation. Coinjoin ancestry and common control "
                        "remain heuristic."
                    ),
                )
            )

        protected_output_indices: set[int] = set()
        ricochet_output_indices: set[int] = set()
        stonewall = detect_stonewall(
            transaction,
            self._prevouts[transaction.txid],
            tracked_postmix_inputs=tracked_postmix_inputs,
        )
        if stonewall is not None:
            repeated_indices = {
                index
                for group in stonewall.repeated_output_indices
                for index in group
            }
            protected_output_indices.update(repeated_indices)
            for index in sorted(repeated_indices):
                self._mark_output_role(
                    OutPoint(transaction.txid, index),
                    "stonewall_equal_output",
                    stonewall.confidence,
                )
            self._add_finding(
                TraceFinding(
                    kind=TraceFindingKind.STONEWALL,
                    confidence=stonewall.confidence,
                    txid=transaction.txid,
                    outpoints=stonewall.tracked_postmix_inputs,
                    explanation=(
                        "This postmix spend has four outputs with repeated "
                        "amounts, a shape consistent with Stonewall or "
                        "StonewallX2. Those two forms are indistinguishable "
                        "on-chain, and unrelated transactions can share the "
                        "same shape."
                    ),
                    repeated_output_values_sats=(
                        stonewall.repeated_output_values_sats
                    ),
                )
            )

        payjoin = detect_payjoin_fingerprints(
            transaction,
            self._prevouts[transaction.txid],
            tracked_postmix_inputs=tracked_postmix_inputs,
        )
        if payjoin is not None:
            self._add_finding(
                TraceFinding(
                    kind=(
                        TraceFindingKind.POSTMIX_PAYJOIN_FINGERPRINT
                    ),
                    confidence=payjoin.confidence,
                    txid=transaction.txid,
                    outpoints=payjoin.tracked_postmix_inputs,
                    explanation=(
                        "This postmix spend has public unnecessary-input or "
                        "input-fingerprint differences consistent with "
                        "Payjoin/Cahoots, but the shape is not proof. Other "
                        "inputs are observed, their ownership is unknown, "
                        "and observable input groups are not proven owners."
                    ),
                    payjoin_unnecessary_input_heuristic=(
                        payjoin.unnecessary_input_heuristic
                    ),
                    payjoin_fingerprint_signals=(
                        payjoin.fingerprint_signals
                    ),
                    payjoin_input_clusters=payjoin.input_clusters,
                )
            )

        ricochet_entry = detect_ricochet_entry(
            transaction,
            tracked_postmix_inputs=tracked_postmix_inputs,
        )
        if ricochet_entry is not None:
            ricochet_indices = self._follow_ricochet(
                transaction,
                ricochet_entry,
                depth,
            )
            ricochet_output_indices.update(ricochet_indices)

        for output in transaction.outputs:
            if output.value_sats == 0 or output.script_type is ScriptType.OP_RETURN:
                continue
            if output.index in ricochet_output_indices:
                continue
            outpoint = OutPoint(transaction.txid, output.index)
            if _output_node_id(outpoint) not in self._nodes:
                continue
            self._ancestry.setdefault(outpoint, set()).add(
                _Ancestry.POSSIBLE_PAYMENT
            )
            if output.index not in protected_output_indices:
                self._mark_output_role(
                    outpoint,
                    TraceFindingKind.POSSIBLE_PAYMENT.value,
                    Confidence.LOW,
                )
            self._add_finding(
                TraceFinding(
                    kind=TraceFindingKind.POSSIBLE_PAYMENT,
                    confidence=Confidence.LOW,
                    txid=transaction.txid,
                    outpoints=(outpoint,),
                    explanation="This ordinary spend output may be a payment "
                    "or change; public transaction data alone cannot decide.",
                )
            )
            frontier.append(
                _FrontierItem(
                    outpoint=outpoint,
                    output=output,
                    ancestry=_Ancestry.POSSIBLE_PAYMENT,
                    confidence=Confidence.LOW,
                    depth=depth,
                    allow_recursive=False,
                )
            )

    def _follow_ricochet(
        self,
        entry_transaction: Transaction,
        entry: RicochetEntry,
        depth: int,
    ) -> set[int]:
        if depth + 4 > self._limits.max_depth:
            self._truncate(
                "Maximum trace depth reached before a possible Ricochet "
                "chain could be proven."
            )
            return set()

        valid_chains: list[
            tuple[OutPoint, tuple[tuple[Transaction, RicochetHop], ...]]
        ] = []
        for candidate in entry.continuation_candidates:
            chain = self._probe_ricochet_chain(
                entry_transaction,
                candidate,
                depth,
            )
            if chain is _LIMIT_REACHED:
                return set()
            if chain is not None:
                valid_chains.append((candidate, chain))
        if len(valid_chains) != 1:
            return set()

        continuation, chain = valid_chains[0]
        new_transactions = {
            transaction.txid
            for transaction, _ in chain
            if _transaction_node_id(transaction.txid) not in self._nodes
        }
        transaction_count = sum(
            node.kind is TraceNodeKind.TRANSACTION
            for node in self._nodes.values()
        )
        if (
            transaction_count + len(new_transactions)
            > self._limits.max_transactions
        ):
            self._truncate(
                "Maximum transaction count reached before a possible "
                "Ricochet chain could be added."
            )
            return set()
        additional_outputs = sum(
            len(transaction.outputs)
            for transaction, _ in chain
            if _transaction_node_id(transaction.txid) not in self._nodes
        )
        output_count = sum(
            node.kind is TraceNodeKind.OUTPUT for node in self._nodes.values()
        )
        if output_count + additional_outputs > self._limits.max_outputs:
            self._truncate(
                "Maximum output count reached before a possible Ricochet "
                "chain could be added."
            )
            return set()

        self._mark_output_role(
            entry.fee_outpoint,
            "ricochet_fee",
            entry.confidence,
        )
        source_outpoint = continuation
        hop_txids: list[str] = []
        for position, (transaction, hop) in enumerate(chain, start=1):
            detection = self._detection(transaction)
            if not self._add_transaction(transaction, detection):
                return set()
            self._add_previous_generation(transaction)
            self._mark_output_status(source_outpoint, "spent")
            self._mark_output_role(
                source_outpoint,
                "ricochet_hop",
                entry.confidence,
            )
            self._add_edge(
                source=_output_node_id(source_outpoint),
                target=_transaction_node_id(transaction.txid),
                kind=TraceEdgeKind.SPENDS,
                confidence=Confidence.HIGH,
                explanation="This output is directly spent by the next "
                "transaction in the possible Ricochet chain.",
            )
            hop_role = (
                TraceFindingKind.POSSIBLE_PAYMENT.value
                if position == 4
                else "ricochet_hop"
            )
            self._mark_output_role(
                hop.output_outpoint,
                hop_role,
                entry.confidence,
            )
            self._ancestry.setdefault(hop.output_outpoint, set()).add(
                _Ancestry.POSSIBLE_PAYMENT
                if position == 4
                else _Ancestry.POSTMIX
            )
            hop_txids.append(transaction.txid)
            source_outpoint = hop.output_outpoint

        self._add_finding(
            TraceFinding(
                kind=TraceFindingKind.RICOCHET,
                confidence=entry.confidence,
                txid=entry_transaction.txid,
                outpoints=(entry.fee_outpoint,),
                explanation=(
                    "A tracked postmix spend creates the documented "
                    "100,000-sat service-fee output and one unique path of "
                    "four serial native-SegWit hops. This is consistent "
                    "with Ricochet, not proof of wallet ownership."
                ),
                service_fee_sats=entry.fee_output.value_sats,
                service_fee_address=encode_p2wpkh_address(
                    entry.fee_output.script_pubkey
                ),
                hop_txids=tuple(hop_txids),
            )
        )
        return {entry.fee_outpoint.index, continuation.index}

    def _probe_ricochet_chain(
        self,
        entry_transaction: Transaction,
        continuation: OutPoint,
        depth: int,
    ) -> tuple[tuple[Transaction, RicochetHop], ...] | None | object:
        previous_outpoint = continuation
        previous_output = entry_transaction.outputs[continuation.index]
        seen_transactions = {entry_transaction.txid}
        chain: list[tuple[Transaction, RicochetHop]] = []
        for hop_position in range(4):
            item = _FrontierItem(
                outpoint=previous_outpoint,
                output=previous_output,
                ancestry=_Ancestry.POSTMIX,
                confidence=Confidence.MEDIUM,
                depth=depth + hop_position,
                allow_recursive=True,
            )
            spending = self._spending_transaction(item)
            if spending is _LIMIT_REACHED:
                return _LIMIT_REACHED
            if spending is None or spending.txid in seen_transactions:
                return None
            hop = detect_ricochet_hop(
                spending,
                expected_input=previous_outpoint,
                previous_output=previous_output,
            )
            if hop is None:
                return None
            chain.append((spending, hop))
            seen_transactions.add(spending.txid)
            previous_outpoint = hop.output_outpoint
            previous_output = hop.output
        return tuple(chain)

    def _add_edge(
        self,
        *,
        source: str,
        target: str,
        kind: TraceEdgeKind,
        confidence: Confidence,
        explanation: str,
    ) -> None:
        if source not in self._nodes or target not in self._nodes:
            return
        edge_id = f"edge:{kind.value}:{source}->{target}"
        self._edges.setdefault(
            edge_id,
            TraceEdge(
                id=edge_id,
                source=source,
                target=target,
                kind=kind,
                confidence=confidence,
                explanation=explanation,
            ),
        )

    def _add_finding(self, finding: TraceFinding) -> None:
        key = (
            finding.kind.value,
            finding.txid,
            tuple(
                (outpoint.txid, outpoint.index)
                for outpoint in finding.outpoints
            ),
        )
        self._findings.setdefault(key, finding)

    def _mark_output_status(self, outpoint: OutPoint, status: str) -> None:
        node_id = _output_node_id(outpoint)
        node = self._nodes.get(node_id)
        if node is not None:
            self._nodes[node_id] = replace(node, status=status)

    def _mark_output_role(
        self,
        outpoint: OutPoint,
        role: str,
        confidence: Confidence,
    ) -> None:
        node_id = _output_node_id(outpoint)
        node = self._nodes.get(node_id)
        if node is not None:
            self._nodes[node_id] = replace(
                node,
                role=role,
                confidence=confidence,
            )

    def _truncate(self, warning: str) -> None:
        self._truncated = True
        self._warnings.add(warning)

    def _report(self, root_txid: str) -> TraceReport:
        self._add_address_reuse_findings()
        nodes = tuple(sorted(self._nodes.values(), key=lambda node: node.id))
        edges = tuple(sorted(self._edges.values(), key=lambda edge: edge.id))
        findings = tuple(
            sorted(
                self._findings.values(),
                key=lambda finding: (
                    finding.kind.value,
                    finding.txid,
                    tuple(
                        (outpoint.txid, outpoint.index)
                        for outpoint in finding.outpoints
                    ),
                ),
            )
        )
        unspent_findings = [
            finding
            for finding in findings
            if finding.kind is TraceFindingKind.UNSPENT
        ]
        unspent_outpoints = {
            finding.outpoints[0] for finding in unspent_findings
        }
        unspent_sats = sum(
            node.value_sats or 0
            for node in nodes
            if node.kind is TraceNodeKind.OUTPUT
            and OutPoint(node.txid, node.output_index or 0) in unspent_outpoints
        )
        summary = TraceSummary(
            transactions_examined=len(self._transactions),
            outputs_examined=sum(
                node.kind is TraceNodeKind.OUTPUT
                and node.txid in self._transactions
                for node in nodes
            ),
            whirlpool_rounds=sum(
                node.kind is TraceNodeKind.TRANSACTION
                and node.transaction_kind
                == TransactionKind.WHIRLPOOL_ROUND.value
                for node in nodes
            ),
            later_tx0s=sum(
                finding.kind is TraceFindingKind.LATER_TX0
                for finding in findings
            ),
            postmix_consolidations=sum(
                finding.kind is TraceFindingKind.POSTMIX_CONSOLIDATION
                for finding in findings
            ),
            stonewall_spends=sum(
                finding.kind is TraceFindingKind.STONEWALL
                for finding in findings
            ),
            ricochet_spends=sum(
                finding.kind is TraceFindingKind.RICOCHET
                for finding in findings
            ),
            postmix_payment_consolidations=sum(
                finding.kind
                is TraceFindingKind.POSTMIX_PAYMENT_CONSOLIDATION
                for finding in findings
            ),
            address_reuse_findings=sum(
                finding.kind is TraceFindingKind.ADDRESS_REUSE
                for finding in findings
            ),
            whirlpool_cpfp_findings=sum(
                finding.kind is TraceFindingKind.WHIRLPOOL_CPFP
                for finding in findings
            ),
            postmix_payjoin_fingerprint_candidates=sum(
                finding.kind
                is TraceFindingKind.POSTMIX_PAYJOIN_FINGERPRINT
                for finding in findings
            ),
            possible_payments=sum(
                finding.kind is TraceFindingKind.POSSIBLE_PAYMENT
                for finding in findings
            ),
            unspent_output_count=len(unspent_outpoints),
            unspent_sats=unspent_sats,
        )
        later_tx0_sources = {
            finding.outpoints[0].txid
            for finding in findings
            if finding.kind is TraceFindingKind.LATER_TX0
            and finding.outpoints
        }
        transactions = tuple(
            _trace_transaction(
                transaction,
                self._detections[txid],
                doxxic_change_enters_later_tx0=txid in later_tx0_sources,
            )
            for txid, transaction in sorted(self._transactions.items())
        )
        return TraceReport(
            root_txid=root_txid,
            nodes=nodes,
            edges=edges,
            findings=findings,
            summary=summary,
            warnings=tuple(sorted(self._warnings)),
            truncated=self._truncated,
            transactions=transactions,
        )

    def _add_address_reuse_findings(self) -> None:
        role_labels = {
            OutputRole.COORDINATOR_FEE.value: "coordinator_fee",
            OutputRole.PREMIX.value: "tx0_premix",
            OutputRole.COINJOIN.value: "whirlpool_coinjoin_output",
            "stonewall_equal_output": "stonewall_equal_output",
        }
        grouped: dict[bytes, list[tuple[OutPoint, str]]] = {}
        for node in self._nodes.values():
            if (
                node.kind is not TraceNodeKind.OUTPUT
                or node.output_index is None
                or node.role not in role_labels
            ):
                continue
            transaction = self._transactions.get(node.txid)
            if transaction is None:
                continue
            output = transaction.outputs[node.output_index]
            if (
                output.value_sats <= 0
                or output.script_type is not ScriptType.P2WPKH
            ):
                continue
            grouped.setdefault(output.script_pubkey, []).append(
                (
                    OutPoint(node.txid, node.output_index),
                    role_labels[node.role],
                )
            )

        for script_pubkey, matches in sorted(
            grouped.items(),
            key=lambda item: item[0],
        ):
            roles = tuple(sorted({role for _, role in matches}))
            if len(roles) < 2:
                continue
            outpoints = tuple(
                sorted(
                    {outpoint for outpoint, _ in matches},
                    key=lambda item: (item.txid, item.index),
                )
            )
            self._add_finding(
                TraceFinding(
                    kind=TraceFindingKind.ADDRESS_REUSE,
                    confidence=Confidence.MEDIUM,
                    txid=outpoints[0].txid,
                    outpoints=outpoints,
                    explanation=(
                        "The exact same native-SegWit address appears across "
                        "multiple classified Whirlpool roles in this bounded "
                        "trace. Address reuse is observed, while the role "
                        "labels are heuristic and common ownership is not "
                        "proven."
                    ),
                    reused_address=encode_p2wpkh_address(script_pubkey),
                    reused_roles=roles,
                )
            )

    def _add_whirlpool_cpfp_finding(
        self,
        source_item: _FrontierItem,
        child: Transaction,
    ) -> None:
        parent = self._transactions.get(source_item.outpoint.txid)
        parent_detection = self._detections.get(source_item.outpoint.txid)
        if (
            parent is None
            or parent_detection is None
            or parent_detection.kind is not TransactionKind.WHIRLPOOL_ROUND
        ):
            return

        tracked_parent_outpoints = tuple(
            sorted(
                {
                    transaction_input.previous_output
                    for transaction_input in child.inputs
                    if transaction_input.previous_output.txid == parent.txid
                    and _Ancestry.POSTMIX
                    in self._ancestry.get(
                        transaction_input.previous_output,
                        set(),
                    )
                },
                key=lambda outpoint: (outpoint.txid, outpoint.index),
            )
        )
        detection = detect_whirlpool_cpfp(
            parent,
            self._prevouts[parent.txid],
            child,
            self._prevouts[child.txid],
            tracked_parent_outpoints=tracked_parent_outpoints,
            parent_height=self._resolver.transaction_height(parent.txid),
            child_height=self._resolver.transaction_height(child.txid),
            parent_is_whirlpool_round=True,
        )
        if detection is None:
            return
        self._add_finding(
            TraceFinding(
                kind=TraceFindingKind.WHIRLPOOL_CPFP,
                confidence=detection.confidence,
                txid=detection.child_txid,
                outpoints=detection.tracked_parent_outpoints,
                explanation=(
                    "A same-block child directly spends a possible Whirlpool "
                    "output at a higher fee rate and raises the combined "
                    "package fee rate, a shape consistent with CPFP. Fee "
                    "acceleration intent, participant identity, and coinjoin "
                    "input-to-output ownership are not proven."
                ),
                cpfp_parent_txid=detection.parent_txid,
                cpfp_block_height=detection.block_height,
                cpfp_parent_fee_sats=detection.parent_fee_sats,
                cpfp_parent_vsize=detection.parent_vsize,
                cpfp_child_fee_sats=detection.child_fee_sats,
                cpfp_child_vsize=detection.child_vsize,
                cpfp_parent_fee_rate=detection.parent_fee_rate,
                cpfp_child_fee_rate=detection.child_fee_rate,
                cpfp_package_fee_rate=detection.package_fee_rate,
            )
        )


_NOT_CACHED = object()
_LIMIT_REACHED = object()


def _transaction_node_id(txid: str) -> str:
    return f"tx:{txid}"


def _output_node_id(outpoint: OutPoint) -> str:
    return f"out:{outpoint.txid}:{outpoint.index}"


def _confidence_rank(confidence: Confidence) -> int:
    return {
        Confidence.LOW: 0,
        Confidence.MEDIUM: 1,
        Confidence.HIGH: 2,
    }[confidence]


def _lower_confidence(
    confidence: Confidence,
    cap: Confidence,
) -> Confidence:
    return confidence if _confidence_rank(confidence) <= _confidence_rank(cap) else cap


def _coinjoin_confidence(confidence: Confidence) -> Confidence:
    if confidence is Confidence.HIGH:
        return Confidence.MEDIUM
    return Confidence.LOW


def _trace_transaction(
    transaction: Transaction,
    detection: WhirlpoolDetection,
    *,
    doxxic_change_enters_later_tx0: bool,
) -> TraceTransaction:
    round_size = detection.round_size
    ratio_size = (
        round_size if detection.input_count is not None else None
    )
    return TraceTransaction(
        txid=transaction.txid,
        kind=detection.kind,
        confidence=detection.confidence,
        pool=(
            detection.pool.identifier
            if detection.pool is not None
            else None
        ),
        input_count=detection.input_count,
        input_value_sats=detection.input_value_sats,
        miner_fee_sats=detection.miner_fee_sats,
        coordinator_fee_sats=detection.coordinator_fee_sats,
        premix_output_count=detection.premix_output_count,
        entered_pool_sats=detection.entered_pool_sats,
        total_fee_cost_sats=detection.total_fee_cost_sats,
        fee_cost_percent=detection.fee_cost_percent,
        round_size=round_size,
        premix_input_count=detection.premix_input_count,
        remix_input_count=detection.remix_input_count,
        new_entrant_ratio=_round_percentage(
            detection.premix_input_count,
            ratio_size,
        ),
        remixer_ratio=_round_percentage(
            detection.remix_input_count,
            ratio_size,
        ),
        doxxic_change_enters_later_tx0=doxxic_change_enters_later_tx0,
    )


def _round_percentage(count: int, round_size: int | None) -> str | None:
    if round_size is None or round_size <= 0:
        return None
    value = (
        Decimal(count) * Decimal(100) / Decimal(round_size)
    ).quantize(Decimal("0.0001"), rounding=ROUND_HALF_UP)
    return format(value, ".4f")
