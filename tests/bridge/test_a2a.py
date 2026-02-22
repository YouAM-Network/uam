"""Unit tests for A2A bridge conversion functions."""

from __future__ import annotations

import pytest

from uam.bridge.a2a import (
    A2ABridgeMetadata,
    bridge_metadata_from_dict,
    bridge_metadata_to_dict,
    contact_from_a2a,
    contact_to_a2a,
)
from uam.protocol.contact import ContactCard, create_contact_card
from uam.protocol.errors import InvalidContactCardError
from uam.protocol.types import UAM_VERSION


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

SAMPLE_A2A_CARD = {
    "name": "Weather Agent",
    "description": "Provides weather forecasts",
    "url": "https://weather.example.com/a2a",
    "version": "0.1",
    "provider": {"organization": "WeatherCorp", "url": "https://weathercorp.com"},
    "capabilities": {"streaming": True, "pushNotifications": False},
    "skills": [
        {
            "id": "forecast",
            "name": "Weather Forecast",
            "description": "Get weather forecasts for any location",
            "tags": ["weather", "forecast"],
            "examples": ["What's the weather in Paris?"],
        }
    ],
    "defaultInputModes": ["text/plain", "application/json"],
    "defaultOutputModes": ["text/plain", "application/json"],
    "securitySchemes": {"apiKey": {"type": "apiKey", "in": "header", "name": "X-API-Key"}},
    "authentication": {"schemes": ["apiKey"]},
}


@pytest.fixture
def sample_a2a_card() -> dict:
    """Full A2A Agent Card with all optional fields."""
    return dict(SAMPLE_A2A_CARD)


@pytest.fixture
def minimal_a2a_card() -> dict:
    """Minimal A2A Agent Card with only name + url."""
    return {"name": "Simple Agent", "url": "https://simple.example.com/a2a"}


@pytest.fixture
def sample_uam_card() -> ContactCard:
    """A UAM ContactCard for testing contact_to_a2a."""
    return ContactCard(
        version=UAM_VERSION,
        address="alice::youam.network",
        display_name="Alice Agent",
        description="A helpful agent",
        system=None,
        connection_endpoint="https://alice.youam.network",
        relay="wss://relay.youam.network",
        public_key="fakepubkey123",
        signature="fakesig456",
    )


# ---------------------------------------------------------------------------
# contact_from_a2a tests
# ---------------------------------------------------------------------------


def test_contact_from_a2a_basic(minimal_a2a_card: dict):
    """Minimal A2A card converts to ContactCard with correct fields."""
    card, meta = contact_from_a2a(minimal_a2a_card)

    assert card.display_name == "Simple Agent"
    assert card.address == "Simple Agent::simple.example.com"
    assert card.system == "a2a"
    assert card.relay == "bridge://a2a"
    assert card.connection_endpoint == "https://simple.example.com/a2a"
    assert card.version == UAM_VERSION
    assert card.public_key == ""
    assert card.signature == ""
    assert meta.source_protocol == "a2a"


def test_contact_from_a2a_full(sample_a2a_card: dict):
    """Full A2A card maps all fields correctly to ContactCard + metadata."""
    card, meta = contact_from_a2a(sample_a2a_card)

    # ContactCard fields
    assert card.display_name == "Weather Agent"
    assert card.description == "Provides weather forecasts"
    assert card.connection_endpoint == "https://weather.example.com/a2a"
    assert card.address == "Weather Agent::weather.example.com"
    assert card.system == "a2a"
    assert card.relay == "bridge://a2a"

    # bridge_metadata captures A2A-specific fields
    assert "skills" in meta.a2a_fields
    assert "capabilities" in meta.a2a_fields
    assert "provider" in meta.a2a_fields
    assert "defaultInputModes" in meta.a2a_fields
    assert "defaultOutputModes" in meta.a2a_fields
    assert "securitySchemes" in meta.a2a_fields
    assert "authentication" in meta.a2a_fields
    assert "version" in meta.a2a_fields


def test_contact_from_a2a_missing_name_raises():
    """A2A card without 'name' raises InvalidContactCardError."""
    bad_card = {"url": "https://example.com", "description": "No name"}
    with pytest.raises(InvalidContactCardError, match="missing required 'name'"):
        contact_from_a2a(bad_card)


def test_contact_from_a2a_no_url():
    """A2A card with name but no url uses fallback address."""
    card, _ = contact_from_a2a({"name": "Lonely Agent"})
    assert card.address == "Lonely Agent::a2a.bridge"
    assert card.connection_endpoint is None


def test_contact_from_a2a_bridge_metadata_records_skills(sample_a2a_card: dict):
    """Skills array from A2A card appears in metadata.a2a_fields."""
    _, meta = contact_from_a2a(sample_a2a_card)
    skills = meta.a2a_fields["skills"]
    assert len(skills) == 1
    assert skills[0]["id"] == "forecast"
    assert skills[0]["name"] == "Weather Forecast"


def test_contact_from_a2a_source_url_recorded():
    """source_url kwarg is recorded in metadata."""
    card_data = {"name": "Test Agent", "url": "https://test.example.com"}
    _, meta = contact_from_a2a(card_data, source_url="https://test.example.com/.well-known/agent.json")
    assert meta.source_url == "https://test.example.com/.well-known/agent.json"


# ---------------------------------------------------------------------------
# contact_to_a2a tests
# ---------------------------------------------------------------------------


def test_contact_to_a2a_basic(sample_uam_card: ContactCard):
    """UAM ContactCard converts to A2A dict with required fields."""
    result = contact_to_a2a(sample_uam_card)

    assert result["name"] == "Alice Agent"
    assert result["url"] == "https://alice.youam.network"
    assert result["version"] == "0.1"
    assert "capabilities" in result
    assert "skills" in result
    assert "defaultInputModes" in result
    assert "defaultOutputModes" in result
    assert result["description"] == "A helpful agent"


def test_contact_to_a2a_has_uam_skill(sample_uam_card: ContactCard):
    """Output skills array contains the uam-messaging skill."""
    result = contact_to_a2a(sample_uam_card)
    skills = result["skills"]
    assert len(skills) == 1
    assert skills[0]["id"] == "uam-messaging"
    assert skills[0]["name"] == "UAM Messaging"
    assert "encrypted" in skills[0]["tags"]


def test_contact_to_a2a_url_from_base_url(sample_uam_card: ContactCard):
    """base_url kwarg overrides derived URL."""
    result = contact_to_a2a(sample_uam_card, base_url="https://custom.example.com/a2a")
    assert result["url"] == "https://custom.example.com/a2a"


def test_contact_to_a2a_url_fallback():
    """When no connection_endpoint and no base_url, URL is derived from address."""
    card = ContactCard(
        version=UAM_VERSION,
        address="bot::mydomain.com",
        display_name="Bot",
        description=None,
        system=None,
        connection_endpoint=None,
        relay="wss://relay.test",
        public_key="key",
        signature="sig",
    )
    result = contact_to_a2a(card)
    assert result["url"] == "https://mydomain.com"
    # description omitted when None
    assert "description" not in result


# ---------------------------------------------------------------------------
# Roundtrip test
# ---------------------------------------------------------------------------


def test_roundtrip_a2a_to_uam_to_a2a(sample_a2a_card: dict):
    """A2A -> UAM -> A2A preserves name and description."""
    card, _ = contact_from_a2a(sample_a2a_card)
    roundtrip = contact_to_a2a(card)

    assert roundtrip["name"] == sample_a2a_card["name"]
    assert roundtrip["description"] == sample_a2a_card["description"]


# ---------------------------------------------------------------------------
# Serialization test
# ---------------------------------------------------------------------------


def test_bridge_metadata_serialization():
    """bridge_metadata_to_dict and bridge_metadata_from_dict roundtrip."""
    original = A2ABridgeMetadata(
        source_protocol="a2a",
        source_url="https://example.com/.well-known/agent.json",
        a2a_fields={
            "skills": [{"id": "test", "name": "Test"}],
            "capabilities": {"streaming": True},
        },
    )

    d = bridge_metadata_to_dict(original)
    restored = bridge_metadata_from_dict(d)

    assert restored.source_protocol == original.source_protocol
    assert restored.source_url == original.source_url
    assert restored.a2a_fields == original.a2a_fields
