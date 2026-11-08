"""/health and the OpenAPI document report the running package version,
so a deploy can be checked from outside."""

import uam


def test_health_reports_package_version(client):
    resp = client.get("/health")

    assert resp.status_code == 200
    assert resp.json()["version"] == uam.__version__


def test_openapi_reports_package_version(client):
    assert client.app.version == uam.__version__
