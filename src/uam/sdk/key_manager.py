"""Ed25519 key generation, storage, loading, and token persistence (SDK-06)."""

from __future__ import annotations

import os
import platform
import stat
import warnings
from pathlib import Path

from nacl.signing import SigningKey, VerifyKey

from uam.protocol import (
    generate_keypair,
    serialize_signing_key,
    deserialize_signing_key,
    serialize_verify_key,
)


_DEFAULT_KEY_DIR = Path.home() / ".uam" / "keys"


class KeyManager:
    """Manages Ed25519 keypair storage at ~/.uam/keys/ (SDK-06).

    First-run: generates keypair, writes to disk, sets 600 permissions.
    Returning user: loads from disk, warns if permissions too permissive.
    """

    def __init__(self, key_dir: Path | str | None = None) -> None:
        self._key_dir = Path(key_dir) if key_dir else _DEFAULT_KEY_DIR
        self._signing_key: SigningKey | None = None
        self._verify_key: VerifyKey | None = None

    @property
    def signing_key(self) -> SigningKey:
        """Access the Ed25519 signing key.  Raises if not loaded."""
        if self._signing_key is None:
            raise RuntimeError("No keypair loaded. Call load_or_generate() first.")
        return self._signing_key

    @property
    def verify_key(self) -> VerifyKey:
        """Access the Ed25519 verify key.  Raises if not loaded."""
        if self._verify_key is None:
            raise RuntimeError("No keypair loaded. Call load_or_generate() first.")
        return self._verify_key

    def load_or_generate(self, name: str) -> None:
        """Load existing keypair or generate a new one.

        First-run: generates keypair, writes ``{name}.key`` and ``{name}.pub``
        files, sets 600 permissions on the private key.

        Returning user: loads from disk, warns if permissions too permissive.
        """
        self._key_dir.mkdir(parents=True, exist_ok=True)
        key_path = self._key_dir / f"{name}.key"
        pub_path = self._key_dir / f"{name}.pub"

        if key_path.exists():
            # Returning user: load existing keys
            self._check_permissions(key_path)
            self._signing_key = deserialize_signing_key(key_path.read_text().strip())
            self._verify_key = self._signing_key.verify_key
        else:
            # First-run: generate new keypair
            self._signing_key, self._verify_key = generate_keypair()
            key_path.write_text(serialize_signing_key(self._signing_key))
            pub_path.write_text(serialize_verify_key(self._verify_key))
            self._set_permissions(key_path)

    def _set_permissions(self, path: Path) -> None:
        """Set file permissions to 600 (owner read/write only)."""
        if platform.system() != "Windows":
            os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)

    def _check_permissions(self, path: Path) -> None:
        """Warn if key file permissions are too permissive (SDK-06)."""
        if platform.system() == "Windows":
            return  # Cannot reliably check on Windows
        mode = path.stat().st_mode & 0o777
        if mode != 0o600:
            warnings.warn(
                f"Key file {path} has permissions {oct(mode)} (expected 0o600). "
                f"Run: chmod 600 {path}",
                stacklevel=2,
            )

    def save_token(self, name: str, token: str) -> None:
        """Store the relay token alongside the keypair."""
        token_path = self._key_dir / f"{name}.token"
        token_path.write_text(token)
        self._set_permissions(token_path)

    def load_token(self, name: str) -> str | None:
        """Load a previously saved token, or return None.

        Also checks for legacy ``.api_key`` files for backward compatibility.
        """
        token_path = self._key_dir / f"{name}.token"
        if token_path.exists():
            return token_path.read_text().strip()
        # Backward compatibility: check for legacy .api_key file
        legacy_path = self._key_dir / f"{name}.api_key"
        if legacy_path.exists():
            return legacy_path.read_text().strip()
        return None
