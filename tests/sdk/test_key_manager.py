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


class TestEnvVarSupport:
    """Environment variable support for ephemeral deployments."""

    def test_signing_key_from_env(self, key_dir, monkeypatch):
        """UAM_SIGNING_KEY env var loads the key without touching disk."""
        from uam.protocol import generate_keypair, serialize_signing_key, serialize_verify_key

        sk, vk = generate_keypair()
        serialized = serialize_signing_key(sk)
        monkeypatch.setenv("UAM_SIGNING_KEY", serialized)

        km = KeyManager(key_dir)
        km.load_or_generate("ephemeral")

        # Key loaded correctly
        assert serialize_verify_key(km.verify_key) == serialize_verify_key(vk)

        # No files written to disk
        assert not (key_dir / "ephemeral.key").exists()
        assert not (key_dir / "ephemeral.pub").exists()

    def test_signing_key_env_takes_precedence(self, key_dir, monkeypatch):
        """Env var overrides file-based key even if file exists."""
        from uam.protocol import generate_keypair, serialize_signing_key, serialize_verify_key

        # Generate file-based key first
        km1 = KeyManager(key_dir)
        km1.load_or_generate("alice")
        file_pk = serialize_verify_key(km1.verify_key)

        # Set a different key via env var
        sk2, vk2 = generate_keypair()
        monkeypatch.setenv("UAM_SIGNING_KEY", serialize_signing_key(sk2))

        km2 = KeyManager(key_dir)
        km2.load_or_generate("alice")
        env_pk = serialize_verify_key(km2.verify_key)

        # Env var key wins
        assert env_pk == serialize_verify_key(vk2)
        assert env_pk != file_pk

    def test_token_from_env(self, key_dir, monkeypatch):
        """UAM_TOKEN env var returns the token without touching disk."""
        monkeypatch.setenv("UAM_TOKEN", "env-token-xyz")

        km = KeyManager(key_dir)
        loaded = km.load_token("ephemeral")
        assert loaded == "env-token-xyz"

    def test_token_env_takes_precedence(self, key_dir, monkeypatch):
        """Env var overrides file-based token."""
        km = KeyManager(key_dir)
        km.save_token("alice", "file-token")

        monkeypatch.setenv("UAM_TOKEN", "env-token")

        loaded = km.load_token("alice")
        assert loaded == "env-token"

    def test_token_env_strips_whitespace(self, key_dir, monkeypatch):
        """Env var values are stripped of trailing whitespace/newlines."""
        monkeypatch.setenv("UAM_TOKEN", "  my-token  \n")

        km = KeyManager(key_dir)
        assert km.load_token("alice") == "my-token"

    def test_no_env_falls_through_to_file(self, key_dir):
        """Without env vars set, file-based storage works as before."""
        km = KeyManager(key_dir)
        km.load_or_generate("alice")

        assert (key_dir / "alice.key").exists()
        assert (key_dir / "alice.pub").exists()

    def test_legacy_api_key_still_works(self, key_dir):
        """Legacy .api_key files still load when no env var or .token file."""
        legacy_path = key_dir / "alice.api_key"
        legacy_path.write_text("legacy-key-123")

        km = KeyManager(key_dir)
        assert km.load_token("alice") == "legacy-key-123"
