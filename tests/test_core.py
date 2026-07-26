from __future__ import annotations

import json
import threading
import urllib.error
from contextlib import contextmanager
from decimal import Decimal
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

import pytest

from dewhirlpooler.core import (
    CoreClient,
    CoreRpcError,
    CoreSettings,
)


def _environment(**overrides: str) -> dict[str, str]:
    values = {
        "DEWHIRLPOOLER_CORE_HOST": "127.0.0.1",
        "DEWHIRLPOOLER_CORE_USER": "reader",
        "DEWHIRLPOOLER_CORE_PASSWORD": "synthetic-secret",
    }
    values.update(overrides)
    return values


@contextmanager
def _rpc_server() -> Any:
    records: list[dict[str, object]] = []

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:  # noqa: N802
            length = int(self.headers["Content-Length"])
            request = json.loads(self.rfile.read(length))
            records.append(
                {
                    "request": request,
                    "authorization": self.headers.get("Authorization"),
                    "content_type": self.headers.get("Content-Type"),
                }
            )
            method = request["method"]
            if method == "getblockcount":
                result: object = 959_575
            elif method == "getblockhash":
                result = "a" * 64
            else:
                result = {
                    "hash": "a" * 64,
                    "height": 959_575,
                    "time": 1_700_000_000,
                    "tx": [],
                    "one_sat": 0.00000001,
                }
            content = json.dumps(
                {
                    "jsonrpc": "2.0",
                    "id": request["id"],
                    "result": result,
                    "error": None,
                }
            ).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(content)))
            self.end_headers()
            self.wfile.write(content)

        def log_message(self, format: str, *args: object) -> None:
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server.server_port, records
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def test_settings_defaults_and_secret_safe_repr() -> None:
    settings = CoreSettings.from_env(_environment())

    assert settings.port == 8332
    assert settings.use_tls is False
    assert settings.timeout_seconds == 30
    assert settings.username == "reader"
    assert settings.password == "synthetic-secret"
    assert "synthetic-secret" not in repr(settings)


@pytest.mark.parametrize(
    ("overrides", "message"),
    [
        ({"DEWHIRLPOOLER_CORE_HOST": ""}, "CORE_HOST"),
        ({"DEWHIRLPOOLER_CORE_HOST": "http://node"}, "CORE_HOST"),
        ({"DEWHIRLPOOLER_CORE_HOST": "user@node"}, "CORE_HOST"),
        ({"DEWHIRLPOOLER_CORE_PORT": "0"}, "CORE_PORT"),
        ({"DEWHIRLPOOLER_CORE_PORT": "abc"}, "CORE_PORT"),
        ({"DEWHIRLPOOLER_CORE_USER": ""}, "CORE_USER"),
        ({"DEWHIRLPOOLER_CORE_USER": "a:b"}, "CORE_USER"),
        ({"DEWHIRLPOOLER_CORE_PASSWORD": ""}, "CORE_PASSWORD"),
        ({"DEWHIRLPOOLER_CORE_TIMEOUT": "0"}, "CORE_TIMEOUT"),
        ({"DEWHIRLPOOLER_CORE_TIMEOUT": "nan"}, "CORE_TIMEOUT"),
        ({"DEWHIRLPOOLER_CORE_TLS": "perhaps"}, "CORE_TLS"),
    ],
)
def test_settings_reject_invalid_values_without_leaking(
    overrides: dict[str, str],
    message: str,
) -> None:
    values = _environment(**overrides)

    with pytest.raises(ValueError, match=message) as error:
        CoreSettings.from_env(values)

    assert "synthetic-secret" not in str(error.value)
    assert "127.0.0.1" not in str(error.value)


def test_client_sends_exact_read_only_calls_and_decimal_values() -> None:
    with _rpc_server() as (port, records):
        settings = CoreSettings.from_env(
            _environment(DEWHIRLPOOLER_CORE_PORT=str(port))
        )
        client = CoreClient(settings)

        assert client.block_count() == 959_575
        assert client.block_hash(959_575) == "a" * 64
        block = client.block_verbose("a" * 64)

    assert block["one_sat"] == Decimal("0.00000001")
    requests = [record["request"] for record in records]
    assert [request["id"] for request in requests] == [1, 2, 3]
    assert [request["method"] for request in requests] == [
        "getblockcount",
        "getblockhash",
        "getblock",
    ]
    assert [request["params"] for request in requests] == [
        [],
        [959_575],
        ["a" * 64, 3],
    ]
    assert all(
        isinstance(record["authorization"], str)
        and record["authorization"].startswith("Basic ")
        for record in records
    )
    assert all(
        record["content_type"] == "application/json"
        for record in records
    )


@pytest.mark.parametrize("height", [-1, True, 1.5, "1"])
def test_block_hash_rejects_invalid_height(height: object) -> None:
    client = CoreClient(CoreSettings.from_env(_environment()))

    with pytest.raises(ValueError, match="nonnegative integer"):
        client.block_hash(height)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "block_hash",
    ["", "A" * 64, "g" * 64, "a" * 63, 1],
)
def test_block_verbose_rejects_invalid_hash(block_hash: object) -> None:
    client = CoreClient(CoreSettings.from_env(_environment()))

    with pytest.raises(ValueError, match="lowercase hex"):
        client.block_verbose(block_hash)  # type: ignore[arg-type]


class _Response:
    def __init__(self, content: bytes) -> None:
        self.content = content

    def __enter__(self) -> _Response:
        return self

    def __exit__(self, *args: object) -> None:
        pass

    def read(self, limit: int) -> bytes:
        return self.content[:limit]


@pytest.mark.parametrize(
    ("content", "message"),
    [
        (b"not json", "invalid JSON"),
        (b"[]", "invalid RPC"),
        (b'{"id":2,"error":null,"result":1}', "mismatched"),
        (b'{"id":1,"error":{"code":-1}}', "rejected"),
        (b'{"id":1,"error":null}', "invalid RPC"),
    ],
)
def test_client_rejects_malformed_envelopes_safely(
    monkeypatch: pytest.MonkeyPatch,
    content: bytes,
    message: str,
) -> None:
    monkeypatch.setattr(
        "dewhirlpooler.core.urllib.request.urlopen",
        lambda *args, **kwargs: _Response(content),
    )
    client = CoreClient(CoreSettings.from_env(_environment()))

    with pytest.raises(CoreRpcError, match=message) as error:
        client.block_count()

    assert "synthetic-secret" not in str(error.value)
    assert "127.0.0.1" not in str(error.value)
    assert content.decode(errors="ignore") not in str(error.value)


def test_client_rejects_transport_failure_safely(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fail(*args: object, **kwargs: object) -> object:
        raise urllib.error.URLError("private endpoint detail")

    monkeypatch.setattr(
        "dewhirlpooler.core.urllib.request.urlopen",
        fail,
    )
    client = CoreClient(CoreSettings.from_env(_environment()))

    with pytest.raises(CoreRpcError) as error:
        client.block_count()

    assert str(error.value) == "Bitcoin Core RPC request failed."
    assert "private endpoint detail" not in str(error.value)


def test_client_rejects_oversized_response(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("dewhirlpooler.core._MAX_RESPONSE_BYTES", 8)
    monkeypatch.setattr(
        "dewhirlpooler.core.urllib.request.urlopen",
        lambda *args, **kwargs: _Response(b"123456789"),
    )
    client = CoreClient(CoreSettings.from_env(_environment()))

    with pytest.raises(CoreRpcError, match="too large"):
        client.block_count()


@pytest.mark.parametrize(
    ("content", "method", "message"),
    [
        (
            b'{"id":1,"error":null,"result":true}',
            "block_count",
            "block count",
        ),
        (
            b'{"id":1,"error":null,"result":"A"}',
            "block_hash",
            "block hash",
        ),
        (
            b'{"id":1,"error":null,"result":[]}',
            "block_verbose",
            "block data",
        ),
    ],
)
def test_client_rejects_wrong_result_types(
    monkeypatch: pytest.MonkeyPatch,
    content: bytes,
    method: str,
    message: str,
) -> None:
    monkeypatch.setattr(
        "dewhirlpooler.core.urllib.request.urlopen",
        lambda *args, **kwargs: _Response(content),
    )
    client = CoreClient(CoreSettings.from_env(_environment()))

    with pytest.raises(CoreRpcError, match=message):
        if method == "block_count":
            client.block_count()
        elif method == "block_hash":
            client.block_hash(1)
        else:
            client.block_verbose("a" * 64)
