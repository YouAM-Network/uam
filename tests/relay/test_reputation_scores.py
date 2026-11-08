"""Score updates, on whichever database the relay's tests run against.

Two-argument MIN and MAX exist only on SQLite, so these matter most in the
Postgres job.
"""

from __future__ import annotations


def test_agent_score_stays_between_0_and_100(client, app, registered_agent):
    manager = app.state.reputation_manager
    address = registered_agent["address"]
    assert client.portal.call(manager.update_score, address, 500) == 100
    assert client.portal.call(manager.update_score, address, -5) == 95
    assert client.portal.call(manager.update_score, address, -500) == 0


def test_relay_score_rises_to_100_and_falls_to_0(client, app):
    manager = app.state.relay_reputation
    domain = "peer.example"
    for _ in range(60):
        client.portal.call(manager.record_success, domain)
    assert manager._cache[domain] == 100
    for _ in range(25):
        client.portal.call(manager.record_failure, domain, "test")
    assert manager._cache[domain] == 0
