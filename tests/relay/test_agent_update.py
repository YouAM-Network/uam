"""PATCH /agents/{address}: an agent's token can update its profile, but
not the public key the relay hands out for it."""

from uam.protocol import generate_keypair, serialize_verify_key


def _patch(client, agent, body):
    return client.patch(
        f"/api/v1/agents/{agent['address']}",
        json=body,
        headers={"Authorization": f"Bearer {agent['token']}"},
    )


def _served_key(client, address):
    resp = client.get(f"/api/v1/agents/{address}/public-key")
    assert resp.status_code == 200, resp.text
    return resp.json()["public_key"]


def test_token_cannot_change_public_key(client, registered_agent):
    _, other_vk = generate_keypair()

    resp = _patch(client, registered_agent, {"public_key": serialize_verify_key(other_vk)})

    assert resp.status_code == 403
    assert _served_key(client, registered_agent["address"]) == registered_agent["public_key_str"]


def test_token_can_still_update_display_name(client, registered_agent):
    resp = _patch(client, registered_agent, {"display_name": "Renamed"})

    assert resp.status_code == 200, resp.text
    assert resp.json()["display_name"] == "Renamed"
