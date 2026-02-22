"""Tests for SDKConfig defaults and overrides."""

from __future__ import annotations

from pathlib import Path

from uam.sdk.config import SDKConfig


class TestSDKConfig:
    """SDKConfig default values and derivation."""

    def test_default_config(self):
        c = SDKConfig(name="test")
        assert "relay.youam.network" in c.relay_url
        assert c.key_dir == Path.home() / ".uam" / "keys"
        assert c.transport_type == "websocket"
        assert c.trust_policy == "auto-accept"
        assert c.display_name == "test"

    def test_custom_relay_url(self):
        c = SDKConfig(name="test", relay_url="http://localhost:8000")
        assert c.relay_url == "http://localhost:8000"
        assert c.relay_ws_url == "ws://localhost:8000/ws"

    def test_https_to_wss(self):
        c = SDKConfig(name="test", relay_url="https://relay.example.com")
        assert c.relay_ws_url == "wss://relay.example.com/ws"

    def test_env_var_override(self, monkeypatch):
        monkeypatch.setenv("UAM_RELAY_URL", "http://env-relay:9000")
        c = SDKConfig(name="test")
        assert c.relay_url == "http://env-relay:9000"
        assert c.relay_ws_url == "ws://env-relay:9000/ws"

    def test_explicit_overrides_env_var(self, monkeypatch):
        monkeypatch.setenv("UAM_RELAY_URL", "http://env-relay:9000")
        c = SDKConfig(name="test", relay_url="http://explicit:5000")
        assert c.relay_url == "http://explicit:5000"

    def test_relay_domain_extraction(self):
        c = SDKConfig(name="test", relay_url="https://relay.youam.network")
        assert c.relay_domain == "relay.youam.network"

    def test_custom_key_dir(self, tmp_path):
        c = SDKConfig(name="test", key_dir=tmp_path / "mykeys")
        assert c.key_dir == tmp_path / "mykeys"

    def test_custom_data_dir(self, tmp_path):
        c = SDKConfig(name="test", data_dir=tmp_path / "mydata")
        assert c.data_dir == tmp_path / "mydata"
