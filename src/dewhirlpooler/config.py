"""Environment-backed configuration for a Fulcrum server."""

from __future__ import annotations

import math
import os
from collections.abc import Mapping
from dataclasses import dataclass

_HOST_VARIABLE = "DEWHIRLPOOLER_FULCRUM_HOST"
_PORT_VARIABLE = "DEWHIRLPOOLER_FULCRUM_PORT"
_TLS_VARIABLE = "DEWHIRLPOOLER_FULCRUM_TLS"
_TIMEOUT_VARIABLE = "DEWHIRLPOOLER_FULCRUM_TIMEOUT"

_TRUE_VALUES = frozenset({"1", "true", "yes", "on"})
_FALSE_VALUES = frozenset({"0", "false", "no", "off"})


@dataclass(frozen=True, slots=True)
class FulcrumSettings:
    """Connection settings loaded from explicitly named environment values."""

    host: str
    port: int
    use_tls: bool
    timeout_seconds: float

    @classmethod
    def from_env(
        cls,
        env: Mapping[str, str] | None = None,
    ) -> FulcrumSettings:
        """Build settings without ever including secret values in errors."""

        values = os.environ if env is None else env

        host = values.get(_HOST_VARIABLE, "").strip()
        if not host:
            raise ValueError(f"{_HOST_VARIABLE} is required and must not be blank")

        use_tls = _parse_boolean(values.get(_TLS_VARIABLE, "false"))

        default_port = 50002 if use_tls else 50001
        port_text = values.get(_PORT_VARIABLE)
        if port_text is None:
            port = default_port
        else:
            try:
                port = int(port_text)
            except (TypeError, ValueError):
                raise ValueError(
                    f"{_PORT_VARIABLE} must be a valid port"
                ) from None
            if not 1 <= port <= 65535:
                raise ValueError(f"{_PORT_VARIABLE} must be a valid port")

        timeout_text = values.get(_TIMEOUT_VARIABLE, "10")
        try:
            timeout_seconds = float(timeout_text)
        except (TypeError, ValueError):
            raise ValueError(
                f"{_TIMEOUT_VARIABLE} must be a positive number"
            ) from None
        if not math.isfinite(timeout_seconds) or timeout_seconds <= 0:
            raise ValueError(f"{_TIMEOUT_VARIABLE} must be a positive number")

        return cls(
            host=host,
            port=port,
            use_tls=use_tls,
            timeout_seconds=timeout_seconds,
        )


def _parse_boolean(value: str) -> bool:
    try:
        normalized = value.strip().lower()
    except AttributeError:
        raise ValueError(
            f"{_TLS_VARIABLE} must be true or false"
        ) from None

    if normalized in _TRUE_VALUES:
        return True
    if normalized in _FALSE_VALUES:
        return False
    raise ValueError(f"{_TLS_VARIABLE} must be true or false")
