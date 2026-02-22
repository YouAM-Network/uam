"""Fixtures for cross-language tests."""
import json
from pathlib import Path

import pytest

FIXTURES_DIR = Path(__file__).parent.parent.parent / "ts-sdk" / "tests" / "cross-language" / "fixtures"


@pytest.fixture
def ts_fixtures():
    """Load TypeScript-generated fixtures."""
    return {
        "envelope": json.loads((FIXTURES_DIR / "ts-envelope.json").read_text()),
        "contact_card": json.loads((FIXTURES_DIR / "ts-contact-card.json").read_text()),
        "box_payload": json.loads((FIXTURES_DIR / "ts-box-payload.json").read_text()),
        "sealedbox_payload": json.loads((FIXTURES_DIR / "ts-sealedbox-payload.json").read_text()),
        "keys": json.loads((FIXTURES_DIR / "python-keys.json").read_text()),
    }
