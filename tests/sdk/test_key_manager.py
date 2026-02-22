"""Tests for KeyManager: key generation, storage, loading, permissions."""

from __future__ import annotations

import os
import platform
import stat

import pytest

from uam.protocol import serialize_verify_key
from uam.sdk.key_manager import KeyManager


@pytest.fixture()
def key_dir(tmp_path):
    d = tmp_path / ".uam" / "keys"
    d.mkdir(parents=True)
    return d


class TestKeyManager:
    """Key generation and persistence tests."""

    def test_generate_new_keypair(self, key_dir):
        km = KeyManager(key_dir)
        km.load_or_generate("alice")

        # Key files exist on disk
        assert (key_dir / "alice.key").exists()
        assert (key_dir / "alice.pub").exists()

        # Properties work
        assert km.signing_key is not None
        assert km.verify_key is not None

    def test_load_existing_keypair(self, key_dir):
        # First run: generate
        km1 = KeyManager(key_dir)
        km1.load_or_generate("alice")
        pk1 = serialize_verify_key(km1.verify_key)

        # Second run: load from disk
        km2 = KeyManager(key_dir)
        km2.load_or_generate("alice")
        pk2 = serialize_verify_key(km2.verify_key)

        # Same key
        assert pk1 == pk2

    @pytest.mark.skipif(platform.system() == "Windows", reason="Unix-only permissions")
    def test_key_file_permissions_unix(self, key_dir):
        km = KeyManager(key_dir)
        km.load_or_generate("alice")

        key_path = key_dir / "alice.key"
        mode = key_path.stat().st_mode & 0o777
        assert mode == 0o600

    @pytest.mark.skipif(platform.system() == "Windows", reason="Unix-only permissions")
    def test_permission_warning(self, key_dir):
        km = KeyManager(key_dir)
        km.load_or_generate("alice")

        # Make permissions too open
        key_path = key_dir / "alice.key"
        os.chmod(key_path, 0o644)

        # Loading again should warn
        km2 = KeyManager(key_dir)
        with pytest.warns(UserWarning, match="permissions"):
            km2.load_or_generate("alice")

    def test_signing_key_not_loaded_raises(self):
        km = KeyManager()
        with pytest.raises(RuntimeError, match="No keypair loaded"):
            _ = km.signing_key

    def test_verify_key_not_loaded_raises(self):
        km = KeyManager()
        with pytest.raises(RuntimeError, match="No keypair loaded"):
            _ = km.verify_key


class TestTokenPersistence:
    """Token storage and retrieval tests."""

    def test_save_and_load_token(self, key_dir):
        km = KeyManager(key_dir)
        km.save_token("alice", "test-token-abc123")

        loaded = km.load_token("alice")
        assert loaded == "test-token-abc123"

    def test_load_token_not_found(self, key_dir):
        km = KeyManager(key_dir)
        assert km.load_token("nonexistent") is None

    @pytest.mark.skipif(platform.system() == "Windows", reason="Unix-only permissions")
    def test_token_file_permissions_unix(self, key_dir):
        km = KeyManager(key_dir)
        km.save_token("alice", "test-token")

        token_path = key_dir / "alice.token"
        mode = token_path.stat().st_mode & 0o777
        assert mode == 0o600
