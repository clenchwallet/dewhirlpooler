from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def read(relative_path: str) -> str:
    return (ROOT / relative_path).read_text(encoding="utf-8")


def test_all_packaging_files_exist() -> None:
    expected = {
        ".dockerignore",
        ".env.example",
        ".github/workflows/ci.yml",
        "Dockerfile",
        "LICENSE",
        "compose.yaml",
        "docs/assets/dewhirlpooler-trace.png",
        "docs/deployment.md",
        "docs/public-example.md",
        "docs/sources.md",
    }

    assert all((ROOT / path).is_file() for path in expected)


def test_readme_links_the_reproducible_public_example() -> None:
    readme = read("README.md")
    public_example = read("docs/public-example.md")

    assert (
        "[![DeWhirlpooler public trace showing the exposure summary, root "
        "transaction accounting, and interactive transaction graph]"
        "(docs/assets/dewhirlpooler-trace.png)](docs/public-example.md)"
    ) in readme
    assert "18c999772ed82bf7753bdce9021cfa68b505de36344ce81f77d0c436b7135892" in (
        public_example
    )
    assert "Trace depth: `2`" in public_example
    assert "observed public-chain data" in public_example
    assert "releases/download/v0.1.0" not in readme


def test_project_uses_the_owner_selected_mit_license() -> None:
    license_text = read("LICENSE")

    assert license_text.startswith(
        "MIT License\n\nCopyright (c) 2026 Clench Wallet Contributors\n"
    )
    assert "Permission is hereby granted, free of charge" in license_text
    assert 'THE SOFTWARE IS PROVIDED "AS IS"' in license_text
    assert "[MIT License](LICENSE)" in read("README.md")


def test_dockerfile_is_hardened_multistage_build() -> None:
    dockerfile = read("Dockerfile")

    assert dockerfile.count("FROM python:3.12-slim-bookworm") == 2
    assert " AS builder" in dockerfile
    assert " AS runtime" in dockerfile
    assert "python -m pip wheel" in dockerfile
    assert "--no-index --find-links=/wheels" in dockerfile
    assert "COPY pyproject.toml README.md ./" in dockerfile
    assert "COPY src ./src" in dockerfile
    assert "groupadd --gid 10001 dewhirlpooler" in dockerfile
    assert "useradd --uid 10001 --gid 10001" in dockerfile
    assert "USER 10001:10001" in dockerfile
    assert "DEWHIRLPOOLER_CACHE_PATH=/data/reports.sqlite3" in dockerfile
    assert "HEALTHCHECK --interval=30s --timeout=5s" in dockerfile
    assert "--start-period=10s --retries=3 CMD [" in dockerfile
    assert "http://127.0.0.1:8000/health" in dockerfile
    assert (
        'CMD ["uvicorn", "dewhirlpooler.web:create_app", "--factory", '
        '"--host", "0.0.0.0", "--port", "8000"]'
    ) in dockerfile


def test_docker_runtime_stage_has_no_forbidden_content() -> None:
    runtime = read("Dockerfile").split(
        "FROM python:3.12-slim-bookworm AS runtime",
        maxsplit=1,
    )[1].lower()

    forbidden = (
        "apt-get",
        "apt ",
        "apk ",
        "curl",
        " git",
        "sudo",
        "copy tests",
        "192.168.",
        "10.0.",
        "172.16.",
    )
    assert not any(item in runtime for item in forbidden)


def test_dockerignore_excludes_sensitive_and_local_content() -> None:
    rules = {
        line.strip()
        for line in read(".dockerignore").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    }
    expected = {
        ".git",
        ".github",
        ".venv",
        "__pycache__",
        "*.py[cod]",
        ".pytest_cache",
        ".ruff_cache",
        "*.egg-info",
        "build",
        "dist",
        ".env",
        ".env.*",
        "!.env.example",
        "*.sqlite3",
        "*.sqlite3-shm",
        "*.sqlite3-wal",
        ".dewhirlpooler-data",
        "*.local.md",
        ".notes",
        "tests",
    }

    assert expected <= rules
    assert "pyproject.toml" not in rules
    assert "README.md" not in rules
    assert "src" not in rules


def test_compose_has_required_security_boundaries() -> None:
    compose = read("compose.yaml")

    assert "clenchwallet/dewhirlpooler:local" in compose
    assert "init: true" in compose
    assert "restart: unless-stopped" in compose
    assert (
        "${DEWHIRLPOOLER_BIND_ADDRESS:-127.0.0.1}:"
        "${DEWHIRLPOOLER_BIND_PORT:-8000}:8000"
    ) in compose
    assert "${DEWHIRLPOOLER_FULCRUM_HOST:?" in compose
    assert "DEWHIRLPOOLER_CACHE_PATH: /data/reports.sqlite3" in compose
    assert "dewhirlpooler-data:/data" in compose
    assert "read_only: true" in compose
    assert "/tmp:size=16m,mode=1777,noexec,nosuid,nodev" in compose
    assert "cap_drop:" in compose
    assert "- ALL" in compose
    assert "no-new-privileges:true" in compose
    assert "pids_limit: 128" in compose
    assert "stop_grace_period: 10s" in compose

    lowered = compose.lower()
    forbidden = (
        "privileged:",
        "network_mode:",
        "host_network",
        "/var/run/docker.sock",
        "devices:",
        "extra_hosts:",
    )
    assert not any(item in lowered for item in forbidden)


def test_compose_passes_only_approved_application_variables() -> None:
    compose = read("compose.yaml")
    variables = set(
        re.findall(r"^      (DEWHIRLPOOLER_[A-Z_]+):", compose, re.MULTILINE)
    )

    assert variables == {
        "DEWHIRLPOOLER_FULCRUM_HOST",
        "DEWHIRLPOOLER_FULCRUM_PORT",
        "DEWHIRLPOOLER_FULCRUM_TLS",
        "DEWHIRLPOOLER_FULCRUM_TIMEOUT",
        "DEWHIRLPOOLER_CACHE_PATH",
        "DEWHIRLPOOLER_CACHE_TTL_SECONDS",
        "DEWHIRLPOOLER_CACHE_MAX_ENTRIES",
    }


def test_example_environment_has_only_placeholders_and_defaults() -> None:
    entries = dict(
        line.split("=", maxsplit=1)
        for line in read(".env.example").splitlines()
        if line
    )

    assert entries == {
        "DEWHIRLPOOLER_FULCRUM_HOST": "your-fulcrum-host",
        "DEWHIRLPOOLER_FULCRUM_PORT": "50001",
        "DEWHIRLPOOLER_FULCRUM_TLS": "false",
        "DEWHIRLPOOLER_FULCRUM_TIMEOUT": "10",
        "DEWHIRLPOOLER_CACHE_TTL_SECONDS": "900",
        "DEWHIRLPOOLER_CACHE_MAX_ENTRIES": "256",
        "DEWHIRLPOOLER_CHAIN_PREFETCH_WORKERS": "8",
        "DEWHIRLPOOLER_BIND_ADDRESS": "127.0.0.1",
        "DEWHIRLPOOLER_BIND_PORT": "8000",
    }
    assert not re.search(
        r"(?i)(password|token|cookie|credential|secret)=",
        read(".env.example"),
    )
    assert "://" not in entries["DEWHIRLPOOLER_FULCRUM_HOST"]
    assert "@" not in entries["DEWHIRLPOOLER_FULCRUM_HOST"]


def test_workflow_uses_read_only_permissions_and_official_actions() -> None:
    workflow = read(".github/workflows/ci.yml")
    actions = re.findall(r"^\s*uses:\s*(\S+)", workflow, re.MULTILINE)

    assert "permissions:\n  contents: read" in workflow
    assert set(actions) == {"actions/checkout@v4", "actions/setup-python@v5"}
    assert "pull_request:" in workflow
    assert "branches:\n      - main" in workflow
    assert "python-version: \"3.12\"" in workflow
    assert "python -m pytest -q" in workflow
    assert "python -m compileall -q src tests" in workflow
    assert "ruff check --select E,F,I,UP src tests" in workflow
    assert "python -m pip check" in workflow
    assert "git diff --check" in workflow
    assert "docker compose config" in workflow
    assert "10001:10001" in workflow
    assert "if: always()" in workflow

    lowered = workflow.lower()
    forbidden = (
        "${{ secrets.",
        "docker push",
        "upload-artifact",
        "release create",
        "gh release",
    )
    assert not any(item in lowered for item in forbidden)


def test_deployment_docs_cover_runtime_and_lifecycle() -> None:
    docs = read("docs/deployment.md").lower()

    assert "docker engine 24" in docs
    assert "docker compose v2" in docs
    assert "cp .env.example .env" in docs
    assert "docker compose up --detach --build" in docs
    assert "http://127.0.0.1:8000" in docs
    assert "docker compose down" in docs
    assert "git pull" in docs
    assert "docker compose down --volumes" in docs
    assert "has no authentication" in docs
    assert "read-only root filesystem" in docs
    assert "getblockcount" in docs
    assert "getblockhash" in docs
    assert "getblock" in docs
    assert "dewhirlpooler_chain_db=/data/chain.sqlite3" in docs
    assert "10001:10001" in docs
    assert "`bypass`" in docs
    assert "unhealthy" in docs


def test_packaging_configuration_contains_no_private_material() -> None:
    paths = (
        ".dockerignore",
        ".env.example",
        ".github/workflows/ci.yml",
        "Dockerfile",
        "compose.yaml",
    )
    content = "\n".join(read(path) for path in paths)

    private_ip = re.compile(
        r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}"
        r"|192\.168\.\d{1,3}\.\d{1,3}"
        r"|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})\b"
    )
    sensitive_assignment = re.compile(
        r"(?im)^\s*(?:password|token|cookie|credential|secret)\s*[:=]\s*\S+"
    )
    extended_public_key = re.compile(r"\bxpub[1-9A-HJ-NP-Za-km-z]{20,}\b")

    assert private_ip.search(content) is None
    assert sensitive_assignment.search(content) is None
    assert extended_public_key.search(content) is None
