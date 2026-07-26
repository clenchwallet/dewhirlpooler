"""Resolve parsed transactions and direct prevouts through Fulcrum."""

from __future__ import annotations

from collections.abc import Mapping

from .bitcoin import (
    OutPoint,
    Transaction,
    TransactionParseError,
    TxOutput,
    parse_transaction_hex,
)
from .electrum import ElectrumClient


class TransactionResolutionError(RuntimeError):
    """Fulcrum data could not be safely resolved into a transaction."""


class TransactionResolver:
    """Fetch, verify, and cache transactions for one analysis."""

    def __init__(self, client: ElectrumClient) -> None:
        self._client = client
        self._transactions: dict[str, Transaction] = {}
        self._spending_transactions: dict[OutPoint, Transaction | None] = {}
        self._transaction_heights: dict[str, int | None] = {}

    def transaction(self, txid: str) -> Transaction:
        normalized_txid = txid.lower()
        cached = self._transactions.get(normalized_txid)
        if cached is not None:
            return cached

        raw_hex = self._client.transaction_hex(txid)
        try:
            transaction = parse_transaction_hex(raw_hex)
        except TransactionParseError as exc:
            raise TransactionResolutionError(
                "Fulcrum returned invalid transaction data."
            ) from exc
        if transaction.txid != normalized_txid:
            raise TransactionResolutionError(
                "Fulcrum returned transaction data that did not match "
                "the requested ID."
            )
        self._transactions[normalized_txid] = transaction
        return transaction

    def prevouts(
        self,
        transaction: Transaction,
    ) -> Mapping[OutPoint, TxOutput]:
        resolved: dict[OutPoint, TxOutput] = {}
        for transaction_input in transaction.inputs:
            outpoint = transaction_input.previous_output
            if outpoint.txid == "0" * 64 and outpoint.index == 0xFFFFFFFF:
                continue
            previous_transaction = self.transaction(outpoint.txid)
            if outpoint.index >= len(previous_transaction.outputs):
                raise TransactionResolutionError(
                    "A referenced previous output was not available."
                )
            resolved[outpoint] = previous_transaction.outputs[outpoint.index]
        return resolved

    def spending_transaction(
        self,
        outpoint: OutPoint,
        output: TxOutput,
    ) -> Transaction | None:
        if outpoint in self._spending_transactions:
            return self._spending_transactions[outpoint]

        history = self._client.script_history(output.script_pubkey)
        if len(history) > 100:
            raise TransactionResolutionError(
                "Output history is too large for bounded spend resolution."
            )
        for entry in history:
            self._remember_height(entry.txid, entry.height)

        spending_transactions: list[Transaction] = []
        for entry in history:
            if entry.txid == outpoint.txid:
                continue
            candidate = self.transaction(entry.txid)
            if any(
                transaction_input.previous_output == outpoint
                for transaction_input in candidate.inputs
            ):
                spending_transactions.append(candidate)

        if len(spending_transactions) > 1:
            raise TransactionResolutionError(
                "More than one spending transaction was returned for an output."
            )
        resolved = spending_transactions[0] if spending_transactions else None
        self._spending_transactions[outpoint] = resolved
        return resolved

    def transaction_height(self, txid: str) -> int | None:
        """Return a positive height observed during a bounded history lookup."""

        return self._transaction_heights.get(txid.lower())

    def _remember_height(self, txid: str, height: int) -> None:
        normalized_txid = txid.lower()
        observed = height if type(height) is int and height > 0 else None
        current = self._transaction_heights.get(
            normalized_txid,
            _HEIGHT_NOT_OBSERVED,
        )
        if (
            current is not _HEIGHT_NOT_OBSERVED
            and current is not None
            and observed is not None
            and current != observed
        ):
            raise TransactionResolutionError(
                "Conflicting transaction confirmation heights were returned."
            )
        if current is _HEIGHT_NOT_OBSERVED or (
            current is None and observed is not None
        ):
            self._transaction_heights[normalized_txid] = observed


_HEIGHT_NOT_OBSERVED = object()
