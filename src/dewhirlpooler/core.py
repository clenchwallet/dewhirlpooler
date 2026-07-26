"""Secret-safe, read-only Bitcoin Core JSON-RPC client."""

from __future__ import annotations

import base64
import json
import math
import re
import ssl
import threading
import urllib.error
import urllib.request
from collections.abc import Mapping
from dataclasses import dataclass, field
from decimal import Decimal

_MAX_RESPONSE_BYTES = 64 * 1024 * 1024
_HASH_PATTERN = re.compile(r"^[0-9a-f]{64}$")
_TRUE_VALUES = frozenset({"1", "true", "yes", "on"})
_FALSE_VALUES = frozenset({"0", "false", "no", "off"})


class CoreRpcError(RuntimeError):
    """Safe public error that never contains endpoint or response data."""


@dataclass(frozen=True, slots=True)
class CoreSettings:
    """Explicit Bitcoin Core RPC connection settings."""

    host: str
    port: int
    username: str
    password: str = field(repr=False)
    use_tls: bool = False
    timeout_seconds: float = 30.0

    @classmethod
    def from_env(
        cls,
        env: Mapping[str, str] | None = None,
    ) -> CoreSettings:
        """Build settings without including configured values in errors."""

        import os

        values = os.environ if env is None else env
        host = values.get("DEWHIRLPOOLER_CORE_HOST", "").strip()
        if not host or any(
            marker in host for marker in ("://", "/", "@")
        ) or any(
            character.isspace() for character in host
        ):
            raise ValueError(
                "DEWHIRLPOOLER_CORE_HOST is required and must be a hostname"
            )

        port_text = values.get("DEWHIRLPOOLER_CORE_PORT", "8332")
        try:
            port = int(port_text)
        except (TypeError, ValueError):
            raise ValueError(
                "DEWHIRLPOOLER_CORE_PORT must be a valid port"
            ) from None
        if not 1 <= port <= 65535:
            raise ValueError(
                "DEWHIRLPOOLER_CORE_PORT must be a valid port"
            )

        username = values.get("DEWHIRLPOOLER_CORE_USER", "").strip()
        password = values.get("DEWHIRLPOOLER_CORE_PASSWORD", "")
        if not username:
            raise ValueError("DEWHIRLPOOLER_CORE_USER is required")
        if not password:
            raise ValueError("DEWHIRLPOOLER_CORE_PASSWORD is required")
        if any(character in username for character in ("\r", "\n", ":")):
            raise ValueError("DEWHIRLPOOLER_CORE_USER is invalid")

        timeout_text = values.get("DEWHIRLPOOLER_CORE_TIMEOUT", "30")
        try:
            timeout_seconds = float(timeout_text)
        except (TypeError, ValueError):
            raise ValueError(
                "DEWHIRLPOOLER_CORE_TIMEOUT must be a positive number"
            ) from None
        if not math.isfinite(timeout_seconds) or timeout_seconds <= 0:
            raise ValueError(
                "DEWHIRLPOOLER_CORE_TIMEOUT must be a positive number"
            )

        use_tls = _parse_boolean(
            values.get("DEWHIRLPOOLER_CORE_TLS", "false")
        )
        return cls(
            host=host,
            port=port,
            username=username,
            password=password,
            use_tls=use_tls,
            timeout_seconds=timeout_seconds,
        )


class CoreClient:
    """Minimal read-only client for block enumeration RPCs."""

    def __init__(self, settings: CoreSettings) -> None:
        self._settings = settings
        scheme = "https" if settings.use_tls else "http"
        self._endpoint = f"{scheme}://{settings.host}:{settings.port}/"
        credentials = f"{settings.username}:{settings.password}".encode()
        self._authorization = (
            "Basic " + base64.b64encode(credentials).decode("ascii")
        )
        self._next_request_id = 1
        self._request_id_lock = threading.Lock()

    def block_count(self) -> int:
        result = self._call("getblockcount", ())
        if type(result) is not int or result < 0:
            raise CoreRpcError(
                "Bitcoin Core returned an invalid block count."
            )
        return result

    def block_hash(self, height: int) -> str:
        if type(height) is not int or height < 0:
            raise ValueError("Block height must be a nonnegative integer.")
        result = self._call("getblockhash", (height,))
        if not _is_hash(result):
            raise CoreRpcError("Bitcoin Core returned an invalid block hash.")
        return result

    def block_verbose(self, block_hash: str) -> Mapping[str, object]:
        if not _is_hash(block_hash):
            raise ValueError("Block hash must be 64 lowercase hex characters.")
        result = self._call("getblock", (block_hash, 3))
        if not isinstance(result, dict):
            raise CoreRpcError("Bitcoin Core returned invalid block data.")
        return result

    def _call(self, method: str, params: tuple[object, ...]) -> object:
        with self._request_id_lock:
            request_id = self._next_request_id
            self._next_request_id += 1
        payload = json.dumps(
            {
                "jsonrpc": "2.0",
                "id": request_id,
                "method": method,
                "params": params,
            },
            separators=(",", ":"),
        ).encode("utf-8")
        request = urllib.request.Request(
            self._endpoint,
            data=payload,
            method="POST",
            headers={
                "Authorization": self._authorization,
                "Content-Type": "application/json",
            },
        )
        try:
            with urllib.request.urlopen(
                request,
                timeout=self._settings.timeout_seconds,
            ) as response:
                content = response.read(_MAX_RESPONSE_BYTES + 1)
        except (
            TimeoutError,
            OSError,
            ssl.SSLError,
            urllib.error.HTTPError,
            urllib.error.URLError,
        ):
            raise CoreRpcError("Bitcoin Core RPC request failed.") from None

        if len(content) > _MAX_RESPONSE_BYTES:
            raise CoreRpcError("Bitcoin Core RPC response was too large.")
        try:
            envelope = json.loads(
                content.decode("utf-8"),
                parse_float=Decimal,
            )
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise CoreRpcError(
                "Bitcoin Core returned an invalid JSON response."
            ) from None
        if not isinstance(envelope, dict):
            raise CoreRpcError(
                "Bitcoin Core returned an invalid RPC response."
            )
        if envelope.get("id") != request_id:
            raise CoreRpcError(
                "Bitcoin Core returned a mismatched RPC response."
            )
        if envelope.get("error") is not None:
            raise CoreRpcError("Bitcoin Core rejected the RPC request.")
        if "result" not in envelope:
            raise CoreRpcError(
                "Bitcoin Core returned an invalid RPC response."
            )
        return envelope["result"]


def _parse_boolean(value: object) -> bool:
    if not isinstance(value, str):
        raise ValueError("DEWHIRLPOOLER_CORE_TLS must be true or false")
    normalized = value.strip().lower()
    if normalized in _TRUE_VALUES:
        return True
    if normalized in _FALSE_VALUES:
        return False
    raise ValueError("DEWHIRLPOOLER_CORE_TLS must be true or false")


def _is_hash(value: object) -> bool:
    return isinstance(value, str) and _HASH_PATTERN.fullmatch(value) is not None
