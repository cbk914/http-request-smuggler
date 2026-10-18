"""Shared helpers for the cbk914/http-request-smuggler tests.

Both scripts in this repository have dashes in their filenames, so they cannot
be imported with a plain ``import`` statement. These helpers load them by path.
"""

import importlib.util
import sys
import types
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent


def _ensure_termcolor():
    """Provide a no-op termcolor when the optional dependency is absent."""
    try:
        import termcolor  # noqa: F401
    except ImportError:
        stub = types.ModuleType("termcolor")
        stub.colored = lambda text, color=None, *args, **kwargs: text
        sys.modules["termcolor"] = stub


def load_script(filename, module_name):
    """Import a sibling script by filename, caching it across tests."""
    _ensure_termcolor()
    if module_name in sys.modules:
        return sys.modules[module_name]

    path = REPO_ROOT / filename
    spec = importlib.util.spec_from_file_location(module_name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def run_all():
    return load_script("run-all.py", "hrs_run_all")


@pytest.fixture
def scanner():
    return load_script("http-request-smuggler.py", "hrs_scanner")