from __future__ import annotations

from pathlib import Path

import pytest

from dewhirlpooler.bitcoin import (
    OutPoint,
    Transaction,
    TxInput,
    parse_transaction_hex,
)
from dewhirlpooler.electrum import HistoryEntry
from dewhirlpooler.resolver import (
    TransactionResolutionError,
    TransactionResolver,
)

FIXTURES = Path(__file__).parent / "fixtures"
TX0_TXID = "18c999772ed82bf7753bdce9021cfa68b505de36344ce81f77d0c436b7135892"


def _fixture(name: str) -> str:
    return (FIXTURES / name).read_text().strip()


class FakeClient:
    def __init__(
        self,
        responses: dict[str, str],
        histories: dict[bytes, tuple[HistoryEntry, ...]] | None = None,
    ) -> None:
        self.responses = responses
        self.histories = histories or {}
        self.calls: list[str] = []
        self.history_calls: list[bytes] = []

    def transaction_hex(self, txid: str) -> str:
        self.calls.append(txid)
        return self.responses[txid]

    def script_history(
        self,
        script_pubkey: bytes,
    ) -> tuple[HistoryEntry, ...]:
        self.history_calls.append(script_pubkey)
        return self.histories.get(script_pubkey, ())


def test_transaction_verifies_txid_and_caches() -> None:
    client = FakeClient({TX0_TXID: _fixture("ashigaru-tx0-0.025.hex")})
    resolver = TransactionResolver(client)  # type: ignore[arg-type]

    first = resolver.transaction(TX0_TXID)
    second = resolver.transaction(TX0_TXID.upper())

    assert first is second
    assert client.calls == [TX0_TXID]


def test_transaction_rejects_mismatched_txid() -> None:
    requested = "a" * 64
    client = FakeClient({requested: _fixture("ashigaru-tx0-0.025.hex")})
    resolver = TransactionResolver(client)  # type: ignore[arg-type]

    with pytest.raises(TransactionResolutionError, match="did not match"):
        resolver.transaction(requested)


def test_transaction_wraps_invalid_raw_data() -> None:
    requested = "b" * 64
    client = FakeClient({requested: "not-hex"})
    resolver = TransactionResolver(client)  # type: ignore[arg-type]

    with pytest.raises(TransactionResolutionError, match="invalid transaction"):
        resolver.transaction(requested)


def test_prevouts_resolves_referenced_output() -> None:
    previous = parse_transaction_hex(_fixture("ashigaru-tx0-0.025.hex"))
    outpoint = OutPoint(previous.txid, 3)
    child = _child_with_outpoint(outpoint)
    client = FakeClient({previous.txid: _fixture("ashigaru-tx0-0.025.hex")})
    resolver = TransactionResolver(client)  # type: ignore[arg-type]

    resolved = resolver.prevouts(child)

    assert resolved[outpoint] == previous.outputs[3]
    assert client.calls == [previous.txid]


def test_prevouts_rejects_missing_index() -> None:
    previous = parse_transaction_hex(_fixture("ashigaru-tx0-0.025.hex"))
    outpoint = OutPoint(previous.txid, 999)
    child = _child_with_outpoint(outpoint)
    client = FakeClient({previous.txid: _fixture("ashigaru-tx0-0.025.hex")})
    resolver = TransactionResolver(client)  # type: ignore[arg-type]

    with pytest.raises(TransactionResolutionError, match="not available"):
        resolver.prevouts(child)


def test_spending_transaction_finds_and_caches_real_public_spend() -> None:
    funding = parse_transaction_hex(_fixture("ashigaru-tx0-0.025.hex"))
    spending = parse_transaction_hex(_fixture("ashigaru-round-0.025.hex"))
    outpoint = OutPoint(funding.txid, 10)
    output = funding.outputs[10]
    history = (
        HistoryEntry(funding.txid, 959_000),
        HistoryEntry(spending.txid, 959_313),
    )
    client = FakeClient(
        {
            funding.txid: _fixture("ashigaru-tx0-0.025.hex"),
            spending.txid: _fixture("ashigaru-round-0.025.hex"),
        },
        {output.script_pubkey: history},
    )
    resolver = TransactionResolver(client)  # type: ignore[arg-type]

    first = resolver.spending_transaction(outpoint, output)
    second = resolver.spending_transaction(outpoint, output)

    assert first == spending
    assert second is first
    assert client.history_calls == [output.script_pubkey]
    assert resolver.transaction_height(funding.txid) == 959_000
    assert resolver.transaction_height(spending.txid) == 959_313
    assert resolver.transaction_height("f" * 64) is None


def test_spending_transaction_returns_and_caches_none() -> None:
    funding = parse_transaction_hex(_fixture("ashigaru-tx0-0.025.hex"))
    outpoint = OutPoint(funding.txid, 3)
    output = funding.outputs[3]
    client = FakeClient(
        {funding.txid: _fixture("ashigaru-tx0-0.025.hex")},
        {
            output.script_pubkey: (
                HistoryEntry(funding.txid, 959_000),
            )
        },
    )
    resolver = TransactionResolver(client)  # type: ignore[arg-type]

    assert resolver.spending_transaction(outpoint, output) is None
    assert resolver.spending_transaction(outpoint, output) is None
    assert client.history_calls == [output.script_pubkey]


def test_spending_transaction_does_not_expose_unconfirmed_height() -> None:
    funding = parse_transaction_hex(_fixture("ashigaru-tx0-0.025.hex"))
    outpoint = OutPoint(funding.txid, 3)
    output = funding.outputs[3]
    client = FakeClient(
        {funding.txid: _fixture("ashigaru-tx0-0.025.hex")},
        {
            output.script_pubkey: (
                HistoryEntry(funding.txid, 0),
            )
        },
    )
    resolver = TransactionResolver(client)  # type: ignore[arg-type]

    assert resolver.spending_transaction(outpoint, output) is None
    assert resolver.transaction_height(funding.txid) is None


def test_spending_transaction_rejects_conflicting_positive_heights() -> None:
    funding = parse_transaction_hex(_fixture("ashigaru-tx0-0.025.hex"))
    first = funding.outputs[3]
    second = funding.outputs[4]
    assert first.script_pubkey != second.script_pubkey
    client = FakeClient(
        {funding.txid: _fixture("ashigaru-tx0-0.025.hex")},
        {
            first.script_pubkey: (HistoryEntry(funding.txid, 959_000),),
            second.script_pubkey: (HistoryEntry(funding.txid, 959_001),),
        },
    )
    resolver = TransactionResolver(client)  # type: ignore[arg-type]

    assert (
        resolver.spending_transaction(
            OutPoint(funding.txid, first.index),
            first,
        )
        is None
    )
    with pytest.raises(
        TransactionResolutionError,
        match="Conflicting transaction confirmation heights",
    ):
        resolver.spending_transaction(
            OutPoint(funding.txid, second.index),
            second,
        )


def test_spending_transaction_rejects_conflicting_spends() -> None:
    funding = parse_transaction_hex(_fixture("ashigaru-tx0-0.025.hex"))
    outpoint = OutPoint(funding.txid, 3)
    output = funding.outputs[3]
    first_raw = _spending_raw(outpoint, 1_000)
    second_raw = _spending_raw(outpoint, 2_000)
    first = parse_transaction_hex(first_raw)
    second = parse_transaction_hex(second_raw)
    client = FakeClient(
        {
            funding.txid: _fixture("ashigaru-tx0-0.025.hex"),
            first.txid: first_raw,
            second.txid: second_raw,
        },
        {
            output.script_pubkey: (
                HistoryEntry(funding.txid, 1),
                HistoryEntry(first.txid, 2),
                HistoryEntry(second.txid, 3),
            )
        },
    )
    resolver = TransactionResolver(client)  # type: ignore[arg-type]

    with pytest.raises(TransactionResolutionError, match="More than one"):
        resolver.spending_transaction(outpoint, output)


def _child_with_outpoint(outpoint: OutPoint) -> Transaction:
    template = parse_transaction_hex(_fixture("ashigaru-tx0-0.025.hex"))
    return Transaction(
        version=template.version,
        inputs=(
            TxInput(
                previous_output=outpoint,
                script_sig=b"",
                sequence=0xFFFFFFFF,
                witness=(b"signature",),
            ),
        ),
        outputs=template.outputs[:1],
        lock_time=0,
        has_witness=True,
        txid="c" * 64,
        wtxid="d" * 64,
        size=1,
        weight=1,
        vsize=1,
    )


def _spending_raw(outpoint: OutPoint, value_sats: int) -> str:
    transaction = bytearray((1).to_bytes(4, "little", signed=True))
    transaction.extend(b"\x01")
    transaction.extend(bytes.fromhex(outpoint.txid)[::-1])
    transaction.extend(outpoint.index.to_bytes(4, "little"))
    transaction.extend(b"\x00")
    transaction.extend((0xFFFFFFFF).to_bytes(4, "little"))
    transaction.extend(b"\x01")
    transaction.extend(value_sats.to_bytes(8, "little"))
    script_pubkey = b"\x00\x14" + b"\x33" * 20
    transaction.extend(bytes((len(script_pubkey),)))
    transaction.extend(script_pubkey)
    transaction.extend(b"\x00" * 4)
    return transaction.hex()
