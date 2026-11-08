"""Each agent gets its own webhook secret, and can verify what the relay signs.

The relay keeps only a hash of an agent's token, and a receiver cannot compute
that hash, so the signing key has to be a value the agent is actually given.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from uam.db.crud.agents import get_agent_by_address, update_agent
from uam.db.engine import get_engine
from uam.db.session import async_session_factory
from uam.protocol import generate_keypair, serialize_verify_key
from uam.relay.webhook import WebhookDeliveryService, compute_webhook_signature
from uam.sdk.webhook_verify import verify_webhook_signature

URL = "https://hooks.example.com/uam"
OTHER_URL = "https://hooks.example.com/other"


@pytest.fixture(autouse=True)
def _public_dns():
    with patch("uam.relay.webhook_validator.is_public_ip", return_value=True):
        yield


def _auth(agent) -> dict:
    return {"Authorization": f"Bearer {agent['token']}"}


def _put(client, agent, url=URL) -> dict:
    resp = client.put(
        f"/api/v1/agents/{agent['address']}/webhook",
        json={"webhook_url": url},
        headers=_auth(agent),
    )
    assert resp.status_code == 200, resp.text
    return resp.json()


def test_setting_a_webhook_returns_a_secret(client, registered_agent_pair):
    alice, _ = registered_agent_pair
    secret = _put(client, alice)["webhook_secret"]
    assert len(secret) >= 32
    assert secret != alice["token"]


def test_each_agent_has_its_own_secret(client, registered_agent_pair):
    alice, bob = registered_agent_pair
    assert _put(client, alice)["webhook_secret"] != _put(client, bob)["webhook_secret"]


def test_changing_the_url_keeps_the_secret(client, registered_agent_pair):
    alice, _ = registered_agent_pair
    first = _put(client, alice)["webhook_secret"]
    assert _put(client, alice, OTHER_URL)["webhook_secret"] == first


def test_removing_the_webhook_retires_the_secret(client, registered_agent_pair):
    alice, _ = registered_agent_pair
    first = _put(client, alice)["webhook_secret"]
    resp = client.delete(f"/api/v1/agents/{alice['address']}/webhook", headers=_auth(alice))
    assert resp.status_code == 200
    assert _put(client, alice)["webhook_secret"] != first


def test_reading_the_webhook_does_not_show_the_secret(client, registered_agent_pair):
    alice, _ = registered_agent_pair
    _put(client, alice)
    resp = client.get(f"/api/v1/agents/{alice['address']}/webhook", headers=_auth(alice))
    assert resp.status_code == 200
    assert resp.json()["webhook_url"] == URL
    assert resp.json()["webhook_secret"] is None


def test_registering_with_a_webhook_returns_a_secret(client):
    _, vk = generate_keypair()
    resp = client.post(
        "/api/v1/register",
        json={
            "agent_name": "hooked",
            "public_key": serialize_verify_key(vk),
            "webhook_url": URL,
        },
    )
    assert resp.status_code == 200, resp.text
    assert len(resp.json()["webhook_secret"]) >= 32


def test_registering_without_a_webhook_returns_no_secret(client):
    _, vk = generate_keypair()
    resp = client.post(
        "/api/v1/register",
        json={"agent_name": "plain", "public_key": serialize_verify_key(vk)},
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["webhook_secret"] is None


def test_claiming_a_reservation_with_a_webhook_returns_a_secret(client):
    reserved = client.post("/api/v1/reserve", json={"name": "claimed"})
    assert reserved.status_code == 201, reserved.text
    _, vk = generate_keypair()
    resp = client.post(
        "/api/v1/reserve/claim",
        json={
            "claim_token": reserved.json()["claim_token"],
            "public_key": serialize_verify_key(vk),
            "webhook_url": URL,
        },
    )
    assert resp.status_code == 200, resp.text
    assert len(resp.json()["webhook_secret"]) >= 32


def _capture_posts(app) -> list[dict]:
    posts: list[dict] = []

    async def post(url, *, content=None, headers=None):
        posts.append({"url": url, "content": content, "headers": headers})
        return MagicMock(status_code=200)

    service: WebhookDeliveryService = app.state.webhook_service
    service._http_client = AsyncMock()
    service._http_client.post = post
    return posts


def _send_and_wait(client, sender, wire, posts) -> None:
    deadline = datetime.now(timezone.utc) + timedelta(seconds=5)
    with patch(
        "uam.relay.webhook.async_validate_webhook_url",
        new_callable=AsyncMock,
        return_value=(True, ""),
    ):
        resp = client.post("/api/v1/send", json={"envelope": wire}, headers=_auth(sender))
        assert resp.status_code == 200, resp.text
        while not posts and datetime.now(timezone.utc) < deadline:
            client.get("/health")


def test_a_delivered_webhook_verifies_with_the_secret(
    client, app, registered_agent_pair, make_envelope
):
    alice, bob = registered_agent_pair
    secret = _put(client, bob)["webhook_secret"]
    posts = _capture_posts(app)

    _send_and_wait(client, alice, make_envelope(alice, bob), posts)

    [post] = posts
    signature = post["headers"]["X-UAM-Signature"]
    assert verify_webhook_signature(post["content"], signature, secret)
    assert not verify_webhook_signature(post["content"], signature, bob["token"])


def test_a_webhook_without_a_secret_is_not_sent(
    client, app, registered_agent_pair, make_envelope
):
    """The message waits in the inbox rather than going out signed with anything else."""
    alice, bob = registered_agent_pair
    _put(client, bob)
    posts = _capture_posts(app)

    async def clear_secret():
        factory = async_session_factory(get_engine())
        async with factory() as session:
            await update_agent(session, bob["address"], webhook_secret=None)
            agent = await get_agent_by_address(session, bob["address"])
            assert agent.webhook_url == URL

    client.portal.call(clear_secret)

    wire = make_envelope(alice, bob)
    resp = client.post("/api/v1/send", json={"envelope": wire}, headers=_auth(alice))
    assert resp.status_code == 200, resp.text

    assert posts == []
    inbox = client.get(f"/api/v1/inbox/{bob['address']}", headers=_auth(bob))
    assert [m["message_id"] for m in inbox.json()["messages"]] == [wire["message_id"]]


def test_verify_still_takes_the_old_keyword():
    from uam.sdk.webhook_verify import verify_webhook_signature

    signature = compute_webhook_signature(b"body", "a-secret")

    with pytest.warns(DeprecationWarning):
        assert verify_webhook_signature(b"body", signature, token="a-secret")


def test_verify_needs_a_secret():
    from uam.sdk.webhook_verify import verify_webhook_signature

    with pytest.raises(TypeError):
        verify_webhook_signature(b"body", "sha256=00")


def test_a_non_ascii_signature_is_just_wrong():
    from uam.sdk.webhook_verify import verify_webhook_signature

    assert verify_webhook_signature(b"body", "sha256=é", "a-secret") is False
