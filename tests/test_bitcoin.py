from __future__ import annotations

from pathlib import Path

import pytest

from dewhirlpooler.bitcoin import (
    MAX_MONEY_SATS,
    ScriptType,
    TransactionParseError,
    classify_script,
    encode_p2wpkh_address,
    parse_transaction_hex,
)

FIXTURES = Path(__file__).parent / "fixtures"


def _fixture(name: str) -> str:
    return (FIXTURES / name).read_text().strip()


def _legacy_transaction(*, value_sats: int = 1, output_count: int = 1) -> str:
    transaction = bytearray((1).to_bytes(4, "little", signed=True))
    transaction.extend(b"\x01")
    transaction.extend(b"\x00" * 32)
    transaction.extend((0xFFFFFFFF).to_bytes(4, "little"))
    transaction.extend(b"\x01\x00")
    transaction.extend((0xFFFFFFFF).to_bytes(4, "little"))
    transaction.extend(bytes((output_count,)))
    for _ in range(output_count):
        transaction.extend(value_sats.to_bytes(8, "little"))
        transaction.extend(b"\x01\x51")
    transaction.extend(b"\x00" * 4)
    return transaction.hex()


def test_parses_public_ashigaru_tx0() -> None:
    transaction = parse_transaction_hex(_fixture("ashigaru-tx0-0.025.hex"))

    assert transaction.txid == (
        "18c999772ed82bf7753bdce9021cfa68"
        "b505de36344ce81f77d0c436b7135892"
    )
    assert transaction.has_witness is True
    assert transaction.wtxid != transaction.txid
    assert len(transaction.inputs) == 1
    assert len(transaction.outputs) == 12
    assert transaction.size == 576
    assert transaction.weight == 1977
    assert transaction.vsize == 495
    assert transaction.outputs[0].script_type is ScriptType.OP_RETURN
    assert transaction.outputs[1].script_type is ScriptType.P2WPKH


def test_parses_public_ashigaru_round() -> None:
    transaction = parse_transaction_hex(_fixture("ashigaru-round-0.025.hex"))

    assert transaction.txid == (
        "1394d9a5cc423dc71dc576e6b2f3e963"
        "9ae3096689d38f77857f809ef277816f"
    )
    assert len(transaction.inputs) == 5
    assert len(transaction.outputs) == 5
    assert {output.value_sats for output in transaction.outputs} == {2_500_000}
    assert transaction.weight == 2020
    assert transaction.vsize == 505


def test_parses_legacy_serialization() -> None:
    raw_hex = _legacy_transaction(value_sats=50_000)

    transaction = parse_transaction_hex(raw_hex)

    assert transaction.has_witness is False
    assert transaction.wtxid == transaction.txid
    assert transaction.size * 4 == transaction.weight
    assert transaction.vsize == transaction.size
    assert transaction.inputs[0].witness == ()
    assert transaction.outputs[0].value_sats == 50_000
    assert transaction.outputs[0].script_type is ScriptType.UNKNOWN


@pytest.mark.parametrize(
    ("script_hex", "expected"),
    [
        ("76a914" + "11" * 20 + "88ac", ScriptType.P2PKH),
        ("a914" + "11" * 20 + "87", ScriptType.P2SH),
        ("0014" + "11" * 20, ScriptType.P2WPKH),
        ("0020" + "11" * 32, ScriptType.P2WSH),
        ("5120" + "11" * 32, ScriptType.P2TR),
        ("6a01ff", ScriptType.OP_RETURN),
        ("51", ScriptType.UNKNOWN),
    ],
)
def test_classifies_standard_scripts(
    script_hex: str,
    expected: ScriptType,
) -> None:
    assert classify_script(bytes.fromhex(script_hex)) is expected


@pytest.mark.parametrize(
    ("network", "script_hex", "expected"),
    [
        (
            "mainnet",
            "00145787996036eaf0e8b0ce96a208e429d37d5fd5fb",
            "bc1q27rejcpkatcw3vxwj63q3epf6d74l40mmtug0j",
        ),
        (
            "testnet",
            "0014f55e49b95291e28ed9e089ecb4dbfaa59d6eafaf",
            "tb1q740ynw2jj83gak0q38ktfkl65kwkata0jqlsj6",
        ),
        (
            "regtest",
            "0014f55e49b95291e28ed9e089ecb4dbfaa59d6eafaf",
            "bcrt1q740ynw2jj83gak0q38ktfkl65kwkata0sfxa9n",
        ),
    ],
)
def test_encodes_native_p2wpkh_address(
    network: str,
    script_hex: str,
    expected: str,
) -> None:
    assert (
        encode_p2wpkh_address(bytes.fromhex(script_hex), network=network)
        == expected
    )


@pytest.mark.parametrize(
    ("script", "network"),
    [
        (b"", "mainnet"),
        (b"\x00\x20" + b"\x11" * 32, "mainnet"),
        (b"\x51\x20" + b"\x11" * 32, "mainnet"),
        (b"\x00\x14" + b"\x11" * 20, "signet"),
        (bytearray(b"\x00\x14" + b"\x11" * 20), "mainnet"),
    ],
)
def test_rejects_unsupported_address_inputs(
    script: bytes,
    network: str,
) -> None:
    with pytest.raises(ValueError):
        encode_p2wpkh_address(script, network=network)


@pytest.mark.parametrize(
    ("raw_hex", "message"),
    [
        ("", "empty"),
        ("0", "even"),
        ("zz", "non-hexadecimal"),
        ("00 00", "non-hexadecimal"),
        ("0100", "truncated"),
        ("01000000fd0100", "non-canonical"),
        ("010000000002", "unsupported witness"),
        ("0100000000", "at least one input"),
    ],
)
def test_rejects_malformed_transaction(raw_hex: str, message: str) -> None:
    with pytest.raises(TransactionParseError, match=message):
        parse_transaction_hex(raw_hex)


def test_rejects_trailing_data() -> None:
    with pytest.raises(TransactionParseError, match="trailing"):
        parse_transaction_hex(_legacy_transaction() + "00")


def test_rejects_output_above_max_money() -> None:
    with pytest.raises(TransactionParseError, match="MAX_MONEY"):
        parse_transaction_hex(
            _legacy_transaction(value_sats=MAX_MONEY_SATS + 1)
        )


def test_rejects_total_above_max_money() -> None:
    with pytest.raises(TransactionParseError, match="total"):
        parse_transaction_hex(
            _legacy_transaction(
                value_sats=MAX_MONEY_SATS // 2 + 1,
                output_count=2,
            )
        )


def test_rejects_zero_outputs() -> None:
    raw_hex = _legacy_transaction()
    one_output_offset = 4 + 1 + 32 + 4 + 1 + 1 + 4
    without_output = (
        bytes.fromhex(raw_hex)[:one_output_offset]
        + b"\x00"
        + b"\x00" * 4
    )

    with pytest.raises(TransactionParseError, match="at least one output"):
        parse_transaction_hex(without_output.hex())
