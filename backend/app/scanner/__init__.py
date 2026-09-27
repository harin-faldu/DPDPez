"""Scanner package.

Submodules are imported lazily rather than eagerly. Importing them here created
a cycle: app.policy.discovery needs trackers, importing any scanner submodule
runs this file, this file imported web_scanner, and web_scanner imports
app.policy.discovery, which was still half built. It only showed up when
discovery happened to be imported first, so it survived a long time before a
test picked that order and broke.

Attribute access still works, so `from app.scanner import web_scanner` and
`app.scanner.web_scanner` both behave as before.
"""

import importlib
from typing import TYPE_CHECKING

__all__ = [
    "certin_scanner",
    "cname",
    "code_scanner",
    "payload_pii",
    "trackers",
    "url_guard",
    "web_scanner",
]

if TYPE_CHECKING:  # pragma: no cover - import time only
    from app.scanner import (
        certin_scanner,
        cname,
        code_scanner,
        payload_pii,
        trackers,
        url_guard,
        web_scanner,
    )


def __getattr__(name: str):
    if name in __all__:
        return importlib.import_module(f"{__name__}.{name}")
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


def __dir__() -> list[str]:
    return sorted(__all__)
