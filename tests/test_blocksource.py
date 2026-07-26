from __future__ import annotations

import copy
from decimal import Decimal
from pathlib import Path

import pytest

from dewhirlpooler.bitcoin import (
    OutPoint,
    TransactionParseError,
    parse_transaction_hex,
)
from dewhirlpooler.blocksource import (
    CoreBlockError,
    CoreBlockSource,
    _btc_to_sats,
)

FIXTURES = Path(__file__).parent / "fixtures"
BLOCK_HASH = "a" * 64
PREVIOUS_BLOCK_HASH = "b" * 64


class FakeCoreClient:
    def __init__(
        self,
        block: dict[str, object],
        *,
        height: int = 123,
    ) -> None:
        self.block = block
        self.height = height
        self.calls: list[tuple[str, object]] = []

    def block_count(self) -> int:
        self.calls.append(("getblockcount", None))
        return self.height

    def block_hash(self, height: int) -> str:
        self.calls.append(("getblockhash", height))
        return BLOCK_HASH

    def block_verbose(self, block_hash: str) -> dict[str, object]:
        self.calls.append(("getblock", block_hash))
        return self.block


def _fixture_hex(name: str) -> str:
    return (FIXTURES / name).read_text().strip()


def _segwit_block() -> tuple[dict[str, object], object, object]:
    entry = parse_transaction_hex(_fixture_hex("ricochet-testnet-entry.hex"))
    hop = parse_transaction_hex(_fixture_hex("ricochet-testnet-hop-1.hex"))
    previous = entry.outputs[2]
    block = {
        "hash": BLOCK_HASH,
        "height": 123,
        "previousblockhash": PREVIOUS_BLOCK_HASH,
        "time": 1_700_000_000,
        "tx": [
            {
                "txid": hop.txid,
                "hex": _fixture_hex("ricochet-testnet-hop-1.hex"),
                "vin": [
                    {
                        "txid": hop.inputs[0].previous_output.txid,
                        "vout": hop.inputs[0].previous_output.index,
                        "prevout": {
                            "value": (
                                Decimal(previous.value_sats)
                                / Decimal(100_000_000)
                            ),
                            "scriptPubKey": {
                                "hex": previous.script_pubkey.hex()
                            },
                        },
                    }
                ],
            }
        ],
    }
    return block, hop, previous


def _coinbase_hex() -> str:
    return (
        "01000000"
        "01"
        + "00" * 32
        + "ffffffff"
        "01"
        "00"
        "ffffffff"
        "01"
        "0100000000000000"
        "00"
        "00000000"
    )


def _legacy_transaction_hex(
    input_txids: tuple[str, ...],
    output_values: tuple[int, ...] = (1,),
) -> str:
    content = bytearray((1).to_bytes(4, "little"))
    content.append(len(input_txids))
    for txid in input_txids:
        content.extend(bytes.fromhex(txid)[::-1])
        content.extend((0).to_bytes(4, "little"))
        content.append(0)
        content.extend((0xFFFFFFFF).to_bytes(4, "little"))
    content.append(len(output_values))
    for value in output_values:
        content.extend(value.to_bytes(8, "little"))
        content.append(0)
    content.extend((0).to_bytes(4, "little"))
    return content.hex()


def _legacy_rpc_block(
    raw_hex: str,
    input_values: tuple[Decimal, ...],
) -> dict[str, object]:
    try:
        transaction = parse_transaction_hex(raw_hex)
    except TransactionParseError:
        return {
            "hash": BLOCK_HASH,
            "height": 123,
            "previousblockhash": PREVIOUS_BLOCK_HASH,
            "time": 1_700_000_000,
            "tx": [{"txid": "c" * 64, "hex": raw_hex, "vin": []}],
        }
    return {
        "hash": BLOCK_HASH,
        "height": 123,
        "previousblockhash": PREVIOUS_BLOCK_HASH,
        "time": 1_700_000_000,
        "tx": [
            {
                "txid": transaction.txid,
                "hex": raw_hex,
                "vin": [
                    {
                        "txid": transaction_input.previous_output.txid,
                        "vout": transaction_input.previous_output.index,
                        "prevout": {
                            "value": value,
                            "scriptPubKey": {"hex": ""},
                        },
                    }
                    for transaction_input, value in zip(
                        transaction.inputs,
                        input_values,
                        strict=True,
                    )
                ],
            }
        ],
    }


def test_reads_exact_block_and_direct_prevouts() -> None:
    block_content, hop, previous = _segwit_block()
    client = FakeCoreClient(block_content)
    source = CoreBlockSource(client)  # type: ignore[arg-type]

    assert source.chain_height() == 123
    block = source.block_at_height(123)

    assert block.height == 123
    assert block.block_hash == BLOCK_HASH
    assert block.previous_block_hash == PREVIOUS_BLOCK_HASH
    assert block.block_time == 1_700_000_000
    assert len(block.transactions) == 1
    resolved = block.transactions[0]
    assert resolved.transaction == hop
    assert resolved.prevouts[hop.inputs[0].previous_output] == previous
    assert client.calls == [
        ("getblockcount", None),
        ("getblockhash", 123),
        ("getblock", BLOCK_HASH),
    ]
    with pytest.raises(TypeError):
        resolved.prevouts[OutPoint("f" * 64, 0)] = previous  # type: ignore[index]


def test_reads_block_hash_without_verbose_block() -> None:
    block_content, _, _ = _segwit_block()
    client = FakeCoreClient(block_content)
    source = CoreBlockSource(client)  # type: ignore[arg-type]

    assert source.block_hash_at_height(123) == BLOCK_HASH
    assert client.calls == [("getblockhash", 123)]


def test_accepts_genesis_coinbase_without_prevout() -> None:
    raw_hex = _coinbase_hex()
    transaction = parse_transaction_hex(raw_hex)
    block_content = {
        "hash": BLOCK_HASH,
        "height": 0,
        "time": 1231006505,
        "tx": [
            {
                "txid": transaction.txid,
                "hex": raw_hex,
                "vin": [{"coinbase": "00"}],
            }
        ],
    }

    block = CoreBlockSource(  # type: ignore[arg-type]
        FakeCoreClient(block_content, height=0)
    ).block_at_height(0)

    assert block.previous_block_hash is None
    assert block.transactions[0].prevouts == {}


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (Decimal("0"), 0),
        (Decimal("0.00000001"), 1),
        (Decimal("21000000"), 2_100_000_000_000_000),
        (1, 100_000_000),
    ],
)
def test_converts_btc_to_exact_satoshis(
    value: object,
    expected: int,
) -> None:
    assert _btc_to_sats(value) == expected


@pytest.mark.parametrize(
    "value",
    [
        Decimal("-0.00000001"),
        Decimal("0.000000001"),
        Decimal("21000000.00000001"),
        Decimal("NaN"),
        0.1,
        True,
        "1",
        None,
    ],
)
def test_rejects_invalid_btc_values(value: object) -> None:
    with pytest.raises(CoreBlockError, match="prevout value"):
        _btc_to_sats(value)


@pytest.mark.parametrize(
    ("change", "message"),
    [
        ({"hash": "c" * 64}, "hash"),
        ({"height": 124}, "height"),
        ({"time": -1}, "time"),
        ({"previousblockhash": None}, "previous hash"),
        ({"tx": []}, "no transactions"),
    ],
)
def test_rejects_invalid_block_envelope(
    change: dict[str, object],
    message: str,
) -> None:
    block, _, _ = _segwit_block()
    block.update(change)

    with pytest.raises(CoreBlockError, match=message):
        CoreBlockSource(  # type: ignore[arg-type]
            FakeCoreClient(block)
        ).block_at_height(123)


@pytest.mark.parametrize(
    ("mutate", "message"),
    [
        (lambda tx: tx.update({"hex": "00"}), "hex"),
        (lambda tx: tx.update({"txid": "c" * 64}), "ID"),
        (lambda tx: tx.update({"vin": []}), "inputs"),
        (
            lambda tx: tx["vin"][0].update({"txid": "c" * 64}),
            "outpoint",
        ),
        (
            lambda tx: tx["vin"][0].pop("prevout"),
            "prevout",
        ),
        (
            lambda tx: tx["vin"][0]["prevout"]["scriptPubKey"].update(
                {"hex": "0G"}
            ),
            "script",
        ),
        (
            lambda tx: tx["vin"][0]["prevout"].update(
                {"value": Decimal("0.00000001")}
            ),
            "totals",
        ),
    ],
)
def test_rejects_malformed_transaction_or_prevout(
    mutate: object,
    message: str,
) -> None:
    block, _, _ = _segwit_block()
    changed = copy.deepcopy(block)
    transaction = changed["tx"][0]  # type: ignore[index]
    mutate(transaction)  # type: ignore[operator]

    with pytest.raises(CoreBlockError, match=message):
        CoreBlockSource(  # type: ignore[arg-type]
            FakeCoreClient(changed)
        ).block_at_height(123)


def test_rejects_duplicate_input_outpoints() -> None:
    raw_hex = _legacy_transaction_hex(("1" * 64, "1" * 64))
    block = _legacy_rpc_block(
        raw_hex,
        (Decimal("1"), Decimal("1")),
    )

    with pytest.raises(CoreBlockError, match="repeated an input"):
        CoreBlockSource(  # type: ignore[arg-type]
            FakeCoreClient(block)
        ).block_at_height(123)


@pytest.mark.parametrize(
    ("raw_hex", "input_values", "message"),
    [
        (
            _legacy_transaction_hex(
                ("1" * 64,),
                (2_100_000_000_000_000, 1),
            ),
            (Decimal("21000000"),),
            "transaction hex",
        ),
        (
            _legacy_transaction_hex(("1" * 64, "2" * 64)),
            (Decimal("21000000"), Decimal("21000000")),
            "input total",
        ),
    ],
)
def test_rejects_input_or_output_total_overflow(
    raw_hex: str,
    input_values: tuple[Decimal, ...],
    message: str,
) -> None:
    block = _legacy_rpc_block(raw_hex, input_values)

    with pytest.raises(CoreBlockError, match=message):
        CoreBlockSource(  # type: ignore[arg-type]
            FakeCoreClient(block)
        ).block_at_height(123)


@pytest.mark.parametrize("height", [-1, True, 1.5, "1"])
def test_rejects_invalid_requested_height(height: object) -> None:
    block, _, _ = _segwit_block()

    with pytest.raises(ValueError, match="nonnegative integer"):
        CoreBlockSource(  # type: ignore[arg-type]
            FakeCoreClient(block)
        ).block_at_height(height)  # type: ignore[arg-type]
