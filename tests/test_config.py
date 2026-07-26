from __future__ import annotations

import pytest

from dewhirlpooler.config import FulcrumSettings

HOST_VARIABLE = "DEWHIRLPOOLER_FULCRUM_HOST"
PORT_VARIABLE = "DEWHIRLPOOLER_FULCRUM_PORT"
TLS_VARIABLE = "DEWHIRLPOOLER_FULCRUM_TLS"
TIMEOUT_VARIABLE = "DEWHIRLPOOLER_FULCRUM_TIMEOUT"


def test_defaults_without_tls() -> None:
    settings = FulcrumSettings.from_env({HOST_VARIABLE: "fulcrum.example"})

    assert settings == FulcrumSettings(
        host="fulcrum.example",
        port=50001,
        use_tls=False,
        timeout_seconds=10.0,
    )


def test_defaults_with_tls() -> None:
    settings = FulcrumSettings.from_env(
        {
            HOST_VARIABLE: "fulcrum.example",
            TLS_VARIABLE: "yes",
        }
    )

    assert settings.port == 50002
    assert settings.use_tls is True


def test_explicit_overrides() -> None:
    settings = FulcrumSettings.from_env(
        {
            HOST_VARIABLE: " fulcrum.example ",
            PORT_VARIABLE: "61002",
            TLS_VARIABLE: "ON",
            TIMEOUT_VARIABLE: "2.5",
        }
    )

    assert settings == FulcrumSettings(
        host="fulcrum.example",
        port=61002,
        use_tls=True,
        timeout_seconds=2.5,
    )


@pytest.mark.parametrize("host", [None, "", "   "])
def test_host_is_required_and_nonblank(host: str | None) -> None:
    env = {} if host is None else {HOST_VARIABLE: host}

    with pytest.raises(ValueError, match=HOST_VARIABLE):
        FulcrumSettings.from_env(env)


@pytest.mark.parametrize("port", ["not-a-port", "0", "65536"])
def test_invalid_port_names_variable_without_echoing_value(port: str) -> None:
    with pytest.raises(ValueError) as caught:
        FulcrumSettings.from_env(
            {
                HOST_VARIABLE: "fulcrum.example",
                PORT_VARIABLE: port,
            }
        )

    assert PORT_VARIABLE in str(caught.value)
    assert port not in str(caught.value)


@pytest.mark.parametrize("timeout", ["not-a-timeout", "0", "-1", "nan", "inf"])
def test_invalid_timeout_names_variable_without_echoing_value(
    timeout: str,
) -> None:
    with pytest.raises(ValueError) as caught:
        FulcrumSettings.from_env(
            {
                HOST_VARIABLE: "fulcrum.example",
                TIMEOUT_VARIABLE: timeout,
            }
        )

    assert TIMEOUT_VARIABLE in str(caught.value)
    assert timeout not in str(caught.value)


@pytest.mark.parametrize("value", ["1", "true", "TRUE", "yes", "On"])
def test_boolean_true_values(value: str) -> None:
    settings = FulcrumSettings.from_env(
        {
            HOST_VARIABLE: "fulcrum.example",
            TLS_VARIABLE: value,
        }
    )

    assert settings.use_tls is True


@pytest.mark.parametrize("value", ["0", "false", "FALSE", "no", "Off"])
def test_boolean_false_values(value: str) -> None:
    settings = FulcrumSettings.from_env(
        {
            HOST_VARIABLE: "fulcrum.example",
            TLS_VARIABLE: value,
        }
    )

    assert settings.use_tls is False


def test_invalid_boolean_names_variable_without_echoing_value() -> None:
    invalid_value = "perhaps"

    with pytest.raises(ValueError) as caught:
        FulcrumSettings.from_env(
            {
                HOST_VARIABLE: "fulcrum.example",
                TLS_VARIABLE: invalid_value,
            }
        )

    assert TLS_VARIABLE in str(caught.value)
    assert invalid_value not in str(caught.value)
