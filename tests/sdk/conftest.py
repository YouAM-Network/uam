"""Shared fixtures for UAM SDK tests."""

from __future__ import annotations

import os

import pytest
from fastapi.testclient import TestClient

from uam.relay.app import create_app
from uam.sdk.config import SDKConfig


@pytest.fixture()
def relay_app(tmp_path):
    """Create a relay app backed by a temporary database.

    NOTE: This yields the raw app object WITHOUT triggering lifespan.
    Tests that need the database initialized should use ``relay_client``
    instead, which wraps the app in a TestClient context manager.
    """
    os.environ["UAM_DB_PATH"] = str(tmp_path / "relay.db")
    os.environ["UAM_RELAY_DOMAIN"] = "test.local"
    os.environ["UAM_RELAY_HTTP_URL"] = "http://testserver"
    os.environ["UAM_RELAY_WS_URL"] = "ws://testserver/ws"
    app = create_app()
    # Enter TestClient to trigger lifespan (database init, etc.)
    # This is the single lifespan context for all tests using this app.
    with TestClient(app):
        yield app
    os.environ.pop("UAM_DB_PATH", None)
    os.environ.pop("UAM_RELAY_DOMAIN", None)
    os.environ.pop("UAM_RELAY_HTTP_URL", None)
    os.environ.pop("UAM_RELAY_WS_URL", None)


@pytest.fixture()
def relay_client(tmp_path):
    """TestClient with lifespan management -- independent instance.

    Use this when you need a sync TestClient for direct REST calls.
    """
    os.environ["UAM_DB_PATH"] = str(tmp_path / "relay.db")
    os.environ["UAM_RELAY_DOMAIN"] = "test.local"
    os.environ["UAM_RELAY_HTTP_URL"] = "http://testserver"
    os.environ["UAM_RELAY_WS_URL"] = "ws://testserver/ws"
    app = create_app()
    with TestClient(app) as c:
        yield c
    os.environ.pop("UAM_DB_PATH", None)
    os.environ.pop("UAM_RELAY_DOMAIN", None)
    os.environ.pop("UAM_RELAY_HTTP_URL", None)
    os.environ.pop("UAM_RELAY_WS_URL", None)


@pytest.fixture()
def key_dir(tmp_path):
    """Temporary key directory for SDK tests."""
    d = tmp_path / ".uam" / "keys"
    d.mkdir(parents=True)
    return d


@pytest.fixture()
def data_dir(tmp_path):
    """Temporary data directory for SDK tests."""
    d = tmp_path / ".uam"
    d.mkdir(parents=True, exist_ok=True)
    return d


@pytest.fixture()
def sdk_config(key_dir, data_dir):
    """SDKConfig for tests, pointed at tmp directories."""
    return SDKConfig(
        name="testbot",
        relay_url="http://testserver",
        key_dir=key_dir,
        data_dir=data_dir,
    )
