"""Minimal newline-delimited Electrum 1.4 client."""

from __future__ import annotations

import hashlib
import itertools
import json
import re
import socket
import ssl
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any

from .config import FulcrumSettings

_MAX_RESPONSE_BYTES = 16 * 1024 * 1024
_TXID_PATTERN = re.compile(r"[0-9a-fA-F]{64}\Z")
_HEX_PATTERN = re.compile(r"[0-9a-fA-F]+\Z")


class ElectrumError(RuntimeError):
    """Base class for safe, user-presentable Fulcrum failures."""


class ElectrumConnectionError(ElectrumError):
    """The Fulcrum server could not be reached or read."""


class ElectrumProtocolError(ElectrumError):
    """The Fulcrum server reply did not satisfy the expected contract."""


@dataclass(frozen=True, slots=True)
class ChainTip:
    """The current chain height and raw block header."""

    height: int
    header_hex: str


@dataclass(frozen=True, slots=True)
class HistoryEntry:
    """One transaction returned for an Electrum script history."""

    txid: str
    height: int


class ElectrumClient:
    """Small synchronous client that isolates every request on a connection."""

    def __init__(self, settings: FulcrumSettings) -> None:
        self._settings = settings
        self._request_ids = itertools.count(1)

    def request(self, method: str, params: Sequence[object]) -> object:
        """Issue one JSON-RPC request over one TCP or TLS connection."""

        if not isinstance(method, str) or not method.strip():
            raise ElectrumProtocolError("Fulcrum request method must not be blank.")

        request_id = next(self._request_ids)
        try:
            request_bytes = (
                json.dumps(
                    {
                        "jsonrpc": "2.0",
                        "id": request_id,
                        "method": method,
                        "params": list(params),
                    },
                    separators=(",", ":"),
                ).encode("utf-8")
                + b"\n"
            )
        except (TypeError, ValueError) as exc:
            raise ElectrumProtocolError(
                "The Fulcrum request could not be prepared."
            ) from exc

        try:
            response_bytes = self._exchange(request_bytes)
        except ElectrumProtocolError:
            raise
        except (OSError, TimeoutError) as exc:
            raise ElectrumConnectionError(
                "Unable to communicate with the Fulcrum server."
            ) from exc

        try:
            response = json.loads(response_bytes.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ElectrumProtocolError(
                "The Fulcrum server sent an unreadable reply."
            ) from exc

        if not isinstance(response, dict):
            raise ElectrumProtocolError(
                "The Fulcrum server sent an unexpected reply."
            )

        response_id = response.get("id")
        if type(response_id) is not int or response_id != request_id:
            raise ElectrumProtocolError(
                "The Fulcrum server sent an unexpected reply."
            )
        if response.get("error") is not None:
            raise ElectrumProtocolError(
                "The Fulcrum server rejected the request."
            )
        if "result" not in response:
            raise ElectrumProtocolError(
                "The Fulcrum server reply did not include the requested data."
            )
        return response["result"]

    def server_version(
        self,
        client_name: str = "dewhirlpooler",
        protocol_version: str = "1.4",
    ) -> tuple[str, str]:
        """Return the Fulcrum software and negotiated protocol versions."""

        result = self.request(
            "server.version",
            [client_name, protocol_version],
        )
        if (
            not isinstance(result, (list, tuple))
            or len(result) != 2
            or not all(isinstance(value, str) and value for value in result)
        ):
            raise ElectrumProtocolError(
                "The Fulcrum server returned invalid version details."
            )
        return result[0], result[1]

    def chain_tip(self) -> ChainTip:
        """Return the height and header reported by Fulcrum."""

        result = self.request("blockchain.headers.subscribe", [])
        if not isinstance(result, dict):
            raise ElectrumProtocolError(
                "The Fulcrum server returned invalid chain details."
            )

        height = result.get("height")
        header_hex = result.get("hex")
        if (
            type(height) is not int
            or height < 0
            or not _is_even_hex(header_hex)
        ):
            raise ElectrumProtocolError(
                "The Fulcrum server returned invalid chain details."
            )
        return ChainTip(height=height, header_hex=header_hex)

    def transaction_hex(self, txid: str) -> str:
        """Fetch and validate raw historical transaction hex."""

        if not isinstance(txid, str) or _TXID_PATTERN.fullmatch(txid) is None:
            raise ElectrumProtocolError(
                "Transaction ID must be exactly 64 hexadecimal characters."
            )

        result = self.request("blockchain.transaction.get", [txid, False])
        if not _is_even_hex(result):
            raise ElectrumProtocolError(
                "The Fulcrum server returned invalid transaction data."
            )
        return result

    def script_history(
        self,
        script_pubkey: bytes,
    ) -> tuple[HistoryEntry, ...]:
        """Return validated history for one serialized output script."""

        if not isinstance(script_pubkey, bytes):
            raise ElectrumProtocolError(
                "Output script must be bytes."
            )
        script_hash = hashlib.sha256(script_pubkey).digest()[::-1].hex()
        result = self.request(
            "blockchain.scripthash.get_history",
            [script_hash],
        )
        if not isinstance(result, list) or len(result) > 10_000:
            raise ElectrumProtocolError(
                "The Fulcrum server returned invalid script history."
            )

        entries: list[HistoryEntry] = []
        seen_txids: set[str] = set()
        for item in result:
            if not isinstance(item, dict):
                raise ElectrumProtocolError(
                    "The Fulcrum server returned invalid script history."
                )
            txid = item.get("tx_hash")
            height = item.get("height")
            if (
                not isinstance(txid, str)
                or _TXID_PATTERN.fullmatch(txid) is None
                or type(height) is not int
                or txid.lower() in seen_txids
            ):
                raise ElectrumProtocolError(
                    "The Fulcrum server returned invalid script history."
                )
            normalized_txid = txid.lower()
            seen_txids.add(normalized_txid)
            entries.append(HistoryEntry(normalized_txid, height))
        return tuple(entries)

    def _exchange(self, request_bytes: bytes) -> bytes:
        settings = self._settings
        with socket.create_connection(
            (settings.host, settings.port),
            timeout=settings.timeout_seconds,
        ) as raw_socket:
            raw_socket.settimeout(settings.timeout_seconds)
            if settings.use_tls:
                context = ssl.create_default_context()
                with context.wrap_socket(
                    raw_socket,
                    server_hostname=settings.host,
                ) as tls_socket:
                    tls_socket.settimeout(settings.timeout_seconds)
                    return _send_and_read(tls_socket, request_bytes)
            return _send_and_read(raw_socket, request_bytes)


def _send_and_read(connection: Any, request_bytes: bytes) -> bytes:
    connection.sendall(request_bytes)
    response = bytearray()

    while True:
        remaining = _MAX_RESPONSE_BYTES + 1 - len(response)
        chunk = connection.recv(min(64 * 1024, remaining))
        if not chunk:
            raise ElectrumProtocolError(
                "The Fulcrum server reply was incomplete."
            )

        newline_index = chunk.find(b"\n")
        if newline_index >= 0:
            if len(response) + newline_index > _MAX_RESPONSE_BYTES:
                raise ElectrumProtocolError(
                    "The Fulcrum server reply was too large."
                )
            response.extend(chunk[:newline_index])
            return bytes(response)

        response.extend(chunk)
        if len(response) > _MAX_RESPONSE_BYTES:
            raise ElectrumProtocolError(
                "The Fulcrum server reply was too large."
            )


def _is_even_hex(value: object) -> bool:
    return (
        isinstance(value, str)
        and bool(value)
        and len(value) % 2 == 0
        and _HEX_PATTERN.fullmatch(value) is not None
    )
