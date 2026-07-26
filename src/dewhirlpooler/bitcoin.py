"""Strict, dependency-free Bitcoin transaction parsing."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from enum import StrEnum

MAX_MONEY_SATS = 21_000_000 * 100_000_000
MAX_TRANSACTION_BYTES = 4 * 1024 * 1024
_BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
_BECH32_NETWORK_HRPS = {
    "mainnet": "bc",
    "testnet": "tb",
    "regtest": "bcrt",
}


class TransactionParseError(ValueError):
    """Raw bytes did not encode one supported, canonical Bitcoin transaction."""


class ScriptType(StrEnum):
    """Standard output script templates needed by the analyzer."""

    P2PKH = "p2pkh"
    P2SH = "p2sh"
    P2WPKH = "p2wpkh"
    P2WSH = "p2wsh"
    P2TR = "p2tr"
    OP_RETURN = "op_return"
    UNKNOWN = "unknown"


@dataclass(frozen=True, slots=True)
class OutPoint:
    """A reference to one output of an earlier transaction."""

    txid: str
    index: int


@dataclass(frozen=True, slots=True)
class TxInput:
    """One transaction input, including any SegWit stack."""

    previous_output: OutPoint
    script_sig: bytes
    sequence: int
    witness: tuple[bytes, ...]


@dataclass(frozen=True, slots=True)
class TxOutput:
    """One indexed transaction output."""

    index: int
    value_sats: int
    script_pubkey: bytes
    script_type: ScriptType


@dataclass(frozen=True, slots=True)
class Transaction:
    """Stable parsed form of a legacy or SegWit Bitcoin transaction."""

    version: int
    inputs: tuple[TxInput, ...]
    outputs: tuple[TxOutput, ...]
    lock_time: int
    has_witness: bool
    txid: str
    wtxid: str
    size: int
    weight: int
    vsize: int


class _Reader:
    def __init__(self, content: bytes) -> None:
        self.content = content
        self.position = 0

    @property
    def remaining(self) -> int:
        return len(self.content) - self.position

    def read(self, length: int) -> bytes:
        if length < 0 or length > self.remaining:
            raise TransactionParseError("Transaction data is truncated.")
        start = self.position
        self.position += length
        return self.content[start : self.position]

    def read_uint32(self) -> int:
        return int.from_bytes(self.read(4), "little")

    def read_uint64(self) -> int:
        return int.from_bytes(self.read(8), "little")

    def read_compact_size(self) -> int:
        prefix = self.read(1)[0]
        if prefix < 0xFD:
            return prefix
        if prefix == 0xFD:
            value = int.from_bytes(self.read(2), "little")
            minimum = 0xFD
        elif prefix == 0xFE:
            value = int.from_bytes(self.read(4), "little")
            minimum = 0x10000
        else:
            value = int.from_bytes(self.read(8), "little")
            minimum = 0x100000000
        if value < minimum:
            raise TransactionParseError(
                "Transaction uses a non-canonical compact-size integer."
            )
        return value

    def read_vector(self) -> bytes:
        length = self.read_compact_size()
        return self.read(length)


def parse_transaction_hex(raw_hex: str) -> Transaction:
    """Parse exactly one canonical legacy or SegWit transaction."""

    if not isinstance(raw_hex, str):
        raise TransactionParseError("Raw transaction must be hexadecimal text.")
    normalized = raw_hex.strip()
    if not normalized:
        raise TransactionParseError("Raw transaction must not be empty.")
    if re.fullmatch(r"[0-9a-fA-F]+", normalized) is None:
        raise TransactionParseError(
            "Raw transaction contains non-hexadecimal characters."
        )
    if len(normalized) % 2:
        raise TransactionParseError(
            "Raw transaction must contain an even number of hexadecimal characters."
        )
    content = bytes.fromhex(normalized)
    if len(content) > MAX_TRANSACTION_BYTES:
        raise TransactionParseError("Raw transaction exceeds the 4 MiB limit.")

    reader = _Reader(content)
    version_bytes = reader.read(4)
    version = int.from_bytes(version_bytes, "little", signed=True)
    has_witness = False

    if reader.remaining >= 2 and reader.content[reader.position] == 0:
        reader.read(1)
        witness_flag = reader.read(1)[0]
        if witness_flag != 1:
            raise TransactionParseError(
                "Transaction uses unsupported witness serialization flags."
            )
        has_witness = True

    input_count = reader.read_compact_size()
    if input_count == 0:
        raise TransactionParseError("Transaction must contain at least one input.")
    if input_count > reader.remaining // 41:
        raise TransactionParseError("Transaction input count exceeds its data.")

    inputs: list[TxInput] = []
    for _ in range(input_count):
        previous_txid = reader.read(32)[::-1].hex()
        previous_index = reader.read_uint32()
        script_sig = reader.read_vector()
        sequence = reader.read_uint32()
        inputs.append(
            TxInput(
                previous_output=OutPoint(previous_txid, previous_index),
                script_sig=script_sig,
                sequence=sequence,
                witness=(),
            )
        )

    output_count = reader.read_compact_size()
    if output_count == 0:
        raise TransactionParseError("Transaction must contain at least one output.")
    if output_count > reader.remaining // 9:
        raise TransactionParseError("Transaction output count exceeds its data.")

    outputs: list[TxOutput] = []
    total_output_sats = 0
    for index in range(output_count):
        value_sats = reader.read_uint64()
        if value_sats > MAX_MONEY_SATS:
            raise TransactionParseError("Transaction output value exceeds MAX_MONEY.")
        total_output_sats += value_sats
        if total_output_sats > MAX_MONEY_SATS:
            raise TransactionParseError("Transaction output total exceeds MAX_MONEY.")
        script_pubkey = reader.read_vector()
        outputs.append(
            TxOutput(
                index=index,
                value_sats=value_sats,
                script_pubkey=script_pubkey,
                script_type=classify_script(script_pubkey),
            )
        )

    if has_witness:
        witnessed_inputs: list[TxInput] = []
        any_witness_item = False
        for transaction_input in inputs:
            item_count = reader.read_compact_size()
            if item_count > reader.remaining:
                raise TransactionParseError(
                    "Transaction witness item count exceeds its data."
                )
            witness_items = tuple(
                reader.read_vector() for _ in range(item_count)
            )
            any_witness_item = any_witness_item or bool(witness_items)
            witnessed_inputs.append(
                TxInput(
                    previous_output=transaction_input.previous_output,
                    script_sig=transaction_input.script_sig,
                    sequence=transaction_input.sequence,
                    witness=witness_items,
                )
            )
        if not any_witness_item:
            raise TransactionParseError(
                "Transaction uses witness serialization without witness data."
            )
        inputs = witnessed_inputs

    lock_time = reader.read_uint32()
    if reader.remaining:
        raise TransactionParseError("Transaction contains trailing data.")

    input_tuple = tuple(inputs)
    output_tuple = tuple(outputs)
    base_serialization = _serialize_transaction(
        version=version,
        inputs=input_tuple,
        outputs=output_tuple,
        lock_time=lock_time,
        include_witness=False,
    )
    txid = _display_hash(base_serialization)
    wtxid = _display_hash(content) if has_witness else txid
    base_size = len(base_serialization)
    size = len(content)
    weight = base_size * 4 + (size - base_size)

    return Transaction(
        version=version,
        inputs=input_tuple,
        outputs=output_tuple,
        lock_time=lock_time,
        has_witness=has_witness,
        txid=txid,
        wtxid=wtxid,
        size=size,
        weight=weight,
        vsize=(weight + 3) // 4,
    )


def classify_script(script_pubkey: bytes) -> ScriptType:
    """Identify standard script templates without deriving an address."""

    if (
        len(script_pubkey) == 25
        and script_pubkey[:3] == b"\x76\xa9\x14"
        and script_pubkey[-2:] == b"\x88\xac"
    ):
        return ScriptType.P2PKH
    if (
        len(script_pubkey) == 23
        and script_pubkey[:2] == b"\xa9\x14"
        and script_pubkey[-1:] == b"\x87"
    ):
        return ScriptType.P2SH
    if len(script_pubkey) == 22 and script_pubkey[:2] == b"\x00\x14":
        return ScriptType.P2WPKH
    if len(script_pubkey) == 34 and script_pubkey[:2] == b"\x00\x20":
        return ScriptType.P2WSH
    if len(script_pubkey) == 34 and script_pubkey[:2] == b"\x51\x20":
        return ScriptType.P2TR
    if script_pubkey[:1] == b"\x6a":
        return ScriptType.OP_RETURN
    return ScriptType.UNKNOWN


def encode_p2wpkh_address(
    script_pubkey: bytes,
    *,
    network: str = "mainnet",
) -> str:
    """Encode one native P2WPKH output as a canonical BIP173 address."""

    if (
        not isinstance(script_pubkey, bytes)
        or len(script_pubkey) != 22
        or script_pubkey[:2] != b"\x00\x14"
    ):
        raise ValueError("Output script must be native P2WPKH.")
    try:
        hrp = _BECH32_NETWORK_HRPS[network]
    except (KeyError, TypeError):
        raise ValueError("Bitcoin network is not supported.") from None

    data = (0, *_convert_bits(script_pubkey[2:], 8, 5, pad=True))
    checksum = _bech32_checksum(hrp, data)
    return f"{hrp}1{''.join(_BECH32_CHARSET[value] for value in data + checksum)}"


def is_tx0_marker(output: TxOutput) -> bool:
    """Return whether an output has the observed 64-byte Tx0 marker shape."""

    return (
        output.value_sats == 0
        and output.script_type is ScriptType.OP_RETURN
        and len(output.script_pubkey) == 66
        and output.script_pubkey[:2] == b"\x6a\x40"
    )


def _serialize_transaction(
    *,
    version: int,
    inputs: tuple[TxInput, ...],
    outputs: tuple[TxOutput, ...],
    lock_time: int,
    include_witness: bool,
) -> bytes:
    serialized = bytearray(version.to_bytes(4, "little", signed=True))
    if include_witness:
        serialized.extend(b"\x00\x01")
    serialized.extend(_encode_compact_size(len(inputs)))
    for transaction_input in inputs:
        serialized.extend(bytes.fromhex(transaction_input.previous_output.txid)[::-1])
        serialized.extend(transaction_input.previous_output.index.to_bytes(4, "little"))
        serialized.extend(_encode_compact_size(len(transaction_input.script_sig)))
        serialized.extend(transaction_input.script_sig)
        serialized.extend(transaction_input.sequence.to_bytes(4, "little"))
    serialized.extend(_encode_compact_size(len(outputs)))
    for output in outputs:
        serialized.extend(output.value_sats.to_bytes(8, "little"))
        serialized.extend(_encode_compact_size(len(output.script_pubkey)))
        serialized.extend(output.script_pubkey)
    if include_witness:
        for transaction_input in inputs:
            serialized.extend(_encode_compact_size(len(transaction_input.witness)))
            for witness_item in transaction_input.witness:
                serialized.extend(_encode_compact_size(len(witness_item)))
                serialized.extend(witness_item)
    serialized.extend(lock_time.to_bytes(4, "little"))
    return bytes(serialized)


def _encode_compact_size(value: int) -> bytes:
    if value < 0:
        raise ValueError("Compact-size value must not be negative.")
    if value < 0xFD:
        return bytes((value,))
    if value <= 0xFFFF:
        return b"\xfd" + value.to_bytes(2, "little")
    if value <= 0xFFFFFFFF:
        return b"\xfe" + value.to_bytes(4, "little")
    if value <= 0xFFFFFFFFFFFFFFFF:
        return b"\xff" + value.to_bytes(8, "little")
    raise ValueError("Compact-size value exceeds uint64.")


def _display_hash(content: bytes) -> str:
    return hashlib.sha256(hashlib.sha256(content).digest()).digest()[::-1].hex()


def _bech32_checksum(hrp: str, data: tuple[int, ...]) -> tuple[int, ...]:
    values = _bech32_hrp_expand(hrp) + data + (0, 0, 0, 0, 0, 0)
    polymod = _bech32_polymod(values) ^ 1
    return tuple((polymod >> (5 * (5 - position))) & 31 for position in range(6))


def _bech32_hrp_expand(hrp: str) -> tuple[int, ...]:
    return (
        *(ord(character) >> 5 for character in hrp),
        0,
        *(ord(character) & 31 for character in hrp),
    )


def _bech32_polymod(values: tuple[int, ...]) -> int:
    generators = (
        0x3B6A57B2,
        0x26508E6D,
        0x1EA119FA,
        0x3D4233DD,
        0x2A1462B3,
    )
    checksum = 1
    for value in values:
        top = checksum >> 25
        checksum = ((checksum & 0x1FFFFFF) << 5) ^ value
        for position, generator in enumerate(generators):
            if (top >> position) & 1:
                checksum ^= generator
    return checksum


def _convert_bits(
    content: bytes,
    from_bits: int,
    to_bits: int,
    *,
    pad: bool,
) -> tuple[int, ...]:
    accumulator = 0
    bit_count = 0
    result: list[int] = []
    maximum_result = (1 << to_bits) - 1
    maximum_accumulator = (1 << (from_bits + to_bits - 1)) - 1
    for value in content:
        if value >> from_bits:
            raise ValueError("Witness program contains an invalid value.")
        accumulator = (
            (accumulator << from_bits) | value
        ) & maximum_accumulator
        bit_count += from_bits
        while bit_count >= to_bits:
            bit_count -= to_bits
            result.append((accumulator >> bit_count) & maximum_result)
    if pad and bit_count:
        result.append((accumulator << (to_bits - bit_count)) & maximum_result)
    elif bit_count >= from_bits or (
        (accumulator << (to_bits - bit_count)) & maximum_result
    ):
        raise ValueError("Witness program cannot be converted canonically.")
    return tuple(result)
