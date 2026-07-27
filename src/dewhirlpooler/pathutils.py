"""Portable expansion for user-configured filesystem paths."""

from __future__ import annotations

import os
from pathlib import Path


def expand_user_path(path_text: str) -> Path:
    """Expand a leading ``~`` while honoring ``HOME`` on every platform."""

    if path_text == "~" or path_text.startswith(("~/", "~\\")):
        home = os.environ.get("HOME")
        if home:
            suffix = path_text[2:] if len(path_text) > 1 else ""
            return Path(home) / suffix
    return Path(path_text).expanduser()
