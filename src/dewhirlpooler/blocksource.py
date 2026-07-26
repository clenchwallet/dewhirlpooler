"""Strict conversion of Bitcoin Core verbosity-3 blocks."""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
from types import MappingProxyType

from .bitcoin import (
    MAX_MONEY_SATS,
    OutPoint,
    Transaction,
    TransactionParseError,
    TxOutput,
    classify_script,
    parse_transaction_hex,
)
from .core import CoreClient

_HASH_PATTERN = re.compile(r"^[0-9a-f]{64}$")
_HEX_PATTERN = re.compile(r"^(?:[0-9a-f]{2})*$")
_SATOSHIS_PER_BTC = Decimal(100_000_000)
_COINBASE_OUTPOINT = OutPoint("0" * 64, 0xFFFFFFFF)


class CoreBlockError(ValueError):
    """Safe failure for incomplete or malformed verbosity-3 block data."""


@dataclass(frozen=True, slots=True)
class BlockTransaction:
    transaction: Transaction
    prevouts: Mapping[OutPoint, TxOutput]


@dataclass(frozen=True, slots=True)
class CoreBlock:
    height: int
    block_hash: str
    previous_block_hash: str | None
    block_time: int
    transactions: tuple[BlockTransaction, ...]


class CoreBlockSource:
    """Fetch and validate complete main-chain blocks from Bitcoin Core."""

    def __init__(self, client: CoreClient) -> None:
        self._client = client

    def chain_height(self) -> int:
        return self._client.block_count()

    def block_hash_at_height(self, height: int) -> str:
        if type(height) is not int or height < 0:
            raise ValueError("Block height must be a nonnegative integer.")
        return self._client.block_hash(height)

    def block_at_height(self, height: int) -> CoreBlock:
        if type(height) is not int or height < 0:
            raise ValueError("Block height must be a nonnegative integer.")
        requested_hash = self._client.block_hash(height)
        block = self._client.block_verbose(requested_hash)
        return _convert_block(block, height, requested_hash)


def _convert_block(
    content: Mapping[str, object],
    requested_height: int,
    requested_hash: str,
) -> CoreBlock:
    block_hash = content.get("hash")
    height = content.get("height")
    block_time = content.get("time")
    if block_hash != requested_hash or not _is_hash(block_hash):
        raise CoreBlockError("Bitcoin Core block hash did not match.")
    if type(height) is not int or height != requested_height:
        raise CoreBlockError("Bitcoin Core block height did not match.")
    if type(block_time) is not int or block_time < 0:
        raise CoreBlockError("Bitcoin Core block time was invalid.")

    previous = content.get("previousblockhash")
    if height == 0:
        if previous is not None:
            raise CoreBlockError(
                "Bitcoin Core genesis block had a previous hash."
            )
    elif not _is_hash(previous):
        raise CoreBlockError(
            "Bitcoin Core block previous hash was unavailable."
        )

    rpc_transactions = content.get("tx")
    if not isinstance(rpc_transactions, list) or not rpc_transactions:
        raise CoreBlockError("Bitcoin Core block had no transactions.")
    transactions = tuple(
        _convert_transaction(item) for item in rpc_transactions
    )
    return CoreBlock(
        height=height,
        block_hash=block_hash,
        previous_block_hash=previous,
        block_time=block_time,
        transactions=transactions,
    )


def _convert_transaction(content: object) -> BlockTransaction:
    if not isinstance(content, dict):
        raise CoreBlockError("Bitcoin Core transaction data was invalid.")
    raw_hex = content.get("hex")
    expected_txid = content.get("txid")
    rpc_inputs = content.get("vin")
    if (
        not isinstance(raw_hex, str)
        or not _is_hash(expected_txid)
        or not isinstance(rpc_inputs, list)
    ):
        raise CoreBlockError("Bitcoin Core transaction data was incomplete.")
    try:
        transaction = parse_transaction_hex(raw_hex)
    except TransactionParseError:
        raise CoreBlockError(
            "Bitcoin Core transaction hex was invalid."
        ) from None
    if transaction.txid != expected_txid:
        raise CoreBlockError("Bitcoin Core transaction ID did not match.")
    if len(rpc_inputs) != len(transaction.inputs):
        raise CoreBlockError("Bitcoin Core transaction inputs did not match.")

    prevouts: dict[OutPoint, TxOutput] = {}
    seen: set[OutPoint] = set()
    for parsed_input, rpc_input in zip(
        transaction.inputs,
        rpc_inputs,
        strict=True,
    ):
        if not isinstance(rpc_input, dict):
            raise CoreBlockError("Bitcoin Core transaction input was invalid.")
        outpoint = parsed_input.previous_output
        if outpoint in seen:
            raise CoreBlockError("Bitcoin Core transaction repeated an input.")
        seen.add(outpoint)
        if outpoint == _COINBASE_OUTPOINT:
            if not isinstance(rpc_input.get("coinbase"), str):
                raise CoreBlockError(
                    "Bitcoin Core coinbase input was invalid."
                )
            if rpc_input.get("prevout") is not None:
                raise CoreBlockError(
                    "Bitcoin Core coinbase unexpectedly had a prevout."
                )
            continue
        if (
            rpc_input.get("txid") != outpoint.txid
            or rpc_input.get("vout") != outpoint.index
        ):
            raise CoreBlockError(
                "Bitcoin Core input outpoint did not match transaction hex."
            )
        prevouts[outpoint] = _convert_prevout(
            rpc_input.get("prevout"),
            outpoint,
        )

    _validate_totals(transaction, prevouts)
    return BlockTransaction(
        transaction=transaction,
        prevouts=MappingProxyType(prevouts),
    )


def _convert_prevout(content: object, outpoint: OutPoint) -> TxOutput:
    if not isinstance(content, dict):
        raise CoreBlockError("Bitcoin Core direct prevout was unavailable.")
    script_pub_key = content.get("scriptPubKey")
    if not isinstance(script_pub_key, dict):
        raise CoreBlockError("Bitcoin Core prevout script was unavailable.")
    script_hex = script_pub_key.get("hex")
    if (
        not isinstance(script_hex, str)
        or _HEX_PATTERN.fullmatch(script_hex) is None
    ):
        raise CoreBlockError("Bitcoin Core prevout script was invalid.")
    value_sats = _btc_to_sats(content.get("value"))
    script = bytes.fromhex(script_hex)
    return TxOutput(
        index=outpoint.index,
        value_sats=value_sats,
        script_pubkey=script,
        script_type=classify_script(script),
    )


def _btc_to_sats(value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, (int, Decimal)):
        raise CoreBlockError("Bitcoin Core prevout value was invalid.")
    try:
        btc = Decimal(value)
        sats = btc * _SATOSHIS_PER_BTC
    except (InvalidOperation, ValueError):
        raise CoreBlockError(
            "Bitcoin Core prevout value was invalid."
        ) from None
    if (
        not btc.is_finite()
        or btc < 0
        or sats != sats.to_integral_value()
    ):
        raise CoreBlockError("Bitcoin Core prevout value was invalid.")
    value_sats = int(sats)
    if value_sats > MAX_MONEY_SATS:
        raise CoreBlockError("Bitcoin Core prevout value was invalid.")
    return value_sats


def _validate_totals(
    transaction: Transaction,
    prevouts: Mapping[OutPoint, TxOutput],
) -> None:
    output_total = 0
    for output in transaction.outputs:
        if output.value_sats > MAX_MONEY_SATS:
            raise CoreBlockError("Bitcoin Core output total was invalid.")
        output_total += output.value_sats
        if output_total > MAX_MONEY_SATS:
            raise CoreBlockError("Bitcoin Core output total was invalid.")

    non_coinbase = tuple(
        transaction_input.previous_output
        for transaction_input in transaction.inputs
        if transaction_input.previous_output != _COINBASE_OUTPOINT
    )
    if set(non_coinbase) != set(prevouts):
        raise CoreBlockError("Bitcoin Core direct prevouts were incomplete.")
    input_total = 0
    for outpoint in non_coinbase:
        input_total += prevouts[outpoint].value_sats
        if input_total > MAX_MONEY_SATS:
            raise CoreBlockError("Bitcoin Core input total was invalid.")
    if non_coinbase and input_total < output_total:
        raise CoreBlockError("Bitcoin Core transaction totals were invalid.")


def _is_hash(value: object) -> bool:
    return isinstance(value, str) and _HASH_PATTERN.fullmatch(value) is not None
