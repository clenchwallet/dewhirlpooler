from __future__ import annotations

import hashlib
import json
import socket
import threading
from collections.abc import Callable
from typing import Any

import pytest

from dewhirlpooler import electrum
from dewhirlpooler.config import FulcrumSettings
from dewhirlpooler.electrum import (
    ChainTip,
    ElectrumClient,
    ElectrumProtocolError,
)

ResponseFactory = Callable[[dict[str, Any]], bytes | dict[str, Any]]


class StubServer:
    def __init__(self, responses: list[ResponseFactory]) -> None:
        self._responses = responses
        self._socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._socket.bind(("localhost", 0))
        self._socket.listen()
        self._socket.settimeout(2)
        self.port = self._socket.getsockname()[1]
        self.requests: list[dict[str, Any]] = []
        self.error: BaseException | None = None
        self._thread = threading.Thread(target=self._serve, daemon=True)

    def __enter__(self) -> StubServer:
        self._thread.start()
        return self

    def __exit__(self, *args: object) -> None:
        self._thread.join(timeout=3)
        self._socket.close()
        if self._thread.is_alive():
            raise AssertionError("stub server did not stop")
        if self.error is not None:
            raise self.error

    def _serve(self) -> None:
        try:
            for response_factory in self._responses:
                connection, _ = self._socket.accept()
                with connection:
                    request_bytes = _read_line(connection)
                    request = json.loads(request_bytes)
                    self.requests.append(request)
                    response = response_factory(request)
                    if isinstance(response, dict):
                        response = json.dumps(response).encode() + b"\n"
                    connection.sendall(response)
        except BaseException as exc:
            self.error = exc


def _read_line(connection: socket.socket) -> bytes:
    content = bytearray()
    while not content.endswith(b"\n"):
        chunk = connection.recv(4096)
        if not chunk:
            break
        content.extend(chunk)
    return bytes(content)


def _result(value: object) -> ResponseFactory:
    return lambda request: {"id": request["id"], "result": value}


def _settings(port: int, *, use_tls: bool = False) -> FulcrumSettings:
    return FulcrumSettings(
        host="localhost",
        port=port,
        use_tls=use_tls,
        timeout_seconds=1,
    )


def test_successful_server_version_chain_tip_and_transaction() -> None:
    txid = "a" * 64
    responses = [
        _result(["Fulcrum 2.0", "1.4"]),
        _result({"height": 850_000, "hex": "ab" * 80}),
        _result("01000000"),
    ]

    with StubServer(responses) as server:
        client = ElectrumClient(_settings(server.port))

        assert client.server_version() == ("Fulcrum 2.0", "1.4")
        assert client.chain_tip() == ChainTip(850_000, "ab" * 80)
        assert client.transaction_hex(txid) == "01000000"

    assert [request["id"] for request in server.requests] == [1, 2, 3]
    assert [request["method"] for request in server.requests] == [
        "server.version",
        "blockchain.headers.subscribe",
        "blockchain.transaction.get",
    ]
    assert server.requests[2]["params"] == [txid, False]


def test_remote_error_becomes_protocol_error() -> None:
    def remote_error(request: dict[str, Any]) -> dict[str, Any]:
        return {
            "id": request["id"],
            "error": {"code": 1, "message": "unavailable"},
        }

    with StubServer([remote_error]) as server:
        client = ElectrumClient(_settings(server.port))
        with pytest.raises(ElectrumProtocolError, match="rejected"):
            client.request("server.ping", [])


def test_malformed_json_becomes_protocol_error() -> None:
    with StubServer([lambda request: b"{not-json}\n"]) as server:
        client = ElectrumClient(_settings(server.port))
        with pytest.raises(ElectrumProtocolError, match="unreadable"):
            client.request("server.ping", [])


def test_mismatched_response_id_becomes_protocol_error() -> None:
    with StubServer([lambda request: {"id": 999, "result": None}]) as server:
        client = ElectrumClient(_settings(server.port))
        with pytest.raises(ElectrumProtocolError, match="unexpected"):
            client.request("server.ping", [])


@pytest.mark.parametrize(
    ("response", "message"),
    [
        (b"{}", "incomplete"),
        (b"x" * 33, "too large"),
    ],
)
def test_no_newline_and_oversized_responses(
    monkeypatch: pytest.MonkeyPatch,
    response: bytes,
    message: str,
) -> None:
    monkeypatch.setattr(electrum, "_MAX_RESPONSE_BYTES", 32)

    with StubServer([lambda request: response]) as server:
        client = ElectrumClient(_settings(server.port))
        with pytest.raises(ElectrumProtocolError, match=message):
            client.request("server.ping", [])


def test_invalid_txid_is_rejected_before_network_access(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    contacted = False

    def fail_if_contacted(*args: object, **kwargs: object) -> None:
        nonlocal contacted
        contacted = True
        raise AssertionError("network access was attempted")

    monkeypatch.setattr(electrum.socket, "create_connection", fail_if_contacted)
    client = ElectrumClient(_settings(50001))

    with pytest.raises(ElectrumProtocolError, match="64 hexadecimal"):
        client.transaction_hex("not-a-txid")

    assert contacted is False


def test_script_history_uses_electrum_script_hash() -> None:
    script_pubkey = bytes.fromhex("0014" + "11" * 20)
    txid = "a" * 64
    history = [{"tx_hash": txid, "height": 850_000}]

    with StubServer([_result(history)]) as server:
        client = ElectrumClient(_settings(server.port))

        assert client.script_history(script_pubkey) == (
            electrum.HistoryEntry(txid=txid, height=850_000),
        )

    expected_hash = hashlib.sha256(script_pubkey).digest()[::-1].hex()
    assert server.requests[0]["method"] == "blockchain.scripthash.get_history"
    assert server.requests[0]["params"] == [expected_hash]


def test_script_history_supports_empty_output_script() -> None:
    with StubServer([_result([])]) as server:
        client = ElectrumClient(_settings(server.port))

        assert client.script_history(b"") == ()

    expected_hash = hashlib.sha256(b"").digest()[::-1].hex()
    assert server.requests[0]["params"] == [expected_hash]


@pytest.mark.parametrize(
    "history",
    [
        {},
        [{"tx_hash": "not-a-txid", "height": 1}],
        [{"tx_hash": "a" * 64, "height": True}],
        [
            {"tx_hash": "a" * 64, "height": 1},
            {"tx_hash": "A" * 64, "height": 2},
        ],
        [{"tx_hash": f"{index:064x}", "height": 1} for index in range(10_001)],
    ],
)
def test_invalid_script_history_becomes_protocol_error(
    history: object,
) -> None:
    with StubServer([_result(history)]) as server:
        client = ElectrumClient(_settings(server.port))
        with pytest.raises(ElectrumProtocolError, match="script history"):
            client.script_history(b"\x51")


def test_nonbytes_script_is_rejected_before_network_access(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    contacted = False

    def fail_if_contacted(*args: object, **kwargs: object) -> None:
        nonlocal contacted
        contacted = True
        raise AssertionError("network access was attempted")

    monkeypatch.setattr(electrum.socket, "create_connection", fail_if_contacted)
    client = ElectrumClient(_settings(50001))

    with pytest.raises(ElectrumProtocolError, match="must be bytes"):
        client.script_history(bytearray())

    assert contacted is False


def test_tls_wraps_the_connection(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    raw_socket = FakeSocket([])
    wrapped_socket = FakeSocket(
        [b'{"jsonrpc":"2.0","id":1,"result":["Fulcrum TLS","1.4"]}\n']
    )
    wrapper = FakeTlsContext(wrapped_socket)

    monkeypatch.setattr(
        electrum.socket,
        "create_connection",
        lambda address, timeout: raw_socket,
    )
    monkeypatch.setattr(electrum.ssl, "create_default_context", lambda: wrapper)

    client = ElectrumClient(_settings(50002, use_tls=True))

    assert client.server_version() == ("Fulcrum TLS", "1.4")
    assert wrapper.server_hostname == "localhost"
    assert wrapper.raw_socket is raw_socket
    assert wrapped_socket.sent.endswith(b"\n")
    assert wrapped_socket.timeout == 1


class FakeSocket:
    def __init__(self, responses: list[bytes]) -> None:
        self._responses = iter(responses)
        self.sent = b""
        self.timeout: float | None = None

    def __enter__(self) -> FakeSocket:
        return self

    def __exit__(self, *args: object) -> None:
        return None

    def settimeout(self, timeout: float) -> None:
        self.timeout = timeout

    def sendall(self, content: bytes) -> None:
        self.sent += content

    def recv(self, size: int) -> bytes:
        return next(self._responses, b"")


class FakeTlsContext:
    def __init__(self, wrapped_socket: FakeSocket) -> None:
        self._wrapped_socket = wrapped_socket
        self.raw_socket: FakeSocket | None = None
        self.server_hostname: str | None = None

    def wrap_socket(
        self,
        raw_socket: FakeSocket,
        *,
        server_hostname: str,
    ) -> FakeSocket:
        self.raw_socket = raw_socket
        self.server_hostname = server_hostname
        return self._wrapped_socket
