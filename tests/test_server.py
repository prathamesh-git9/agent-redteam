"""HTTP surface tests. Skipped entirely when the optional server extra is not
installed, so the core CI job (which does not install FastAPI) stays green while
a job that does install it still exercises the endpoints.
"""

from __future__ import annotations

import pytest

pytest.importorskip("fastapi")

from fastapi.testclient import TestClient  # noqa: E402

from agent_redteam.server import create_app  # noqa: E402


@pytest.fixture
def client() -> TestClient:
    return TestClient(create_app())


def test_healthz(client: TestClient):
    assert client.get("/healthz").json() == {"status": "ok"}


def test_attacks_listing(client: TestClient):
    body = client.get("/attacks").json()
    assert len(body) > 0
    assert all("id" in a and "category" in a for a in body)


def test_scan_authorized_fake_target(client: TestClient):
    resp = client.post(
        "/scan",
        json={"target": {"name": "demo", "kind": "fake", "authorized": True},
              "run": {"suite": "smoke"}},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["summary"]["total"] > 0
    # The report is retrievable by the id it was assigned.
    assert client.get(f"/report/{body['id']}").status_code == 200


def test_scan_unauthorized_is_forbidden(client: TestClient):
    # An unauthorized remote target must be refused at the auth gate, surfaced
    # as 403 rather than executed.
    resp = client.post(
        "/scan",
        json={
            "target": {
                "name": "x", "kind": "openai_chat", "authorized": False,
                "options": {"base_url": "https://api.openai.com/v1"},
            },
            "run": {"suite": "smoke"},
        },
    )
    assert resp.status_code == 403


def test_unknown_report_is_404(client: TestClient):
    assert client.get("/report/does-not-exist").status_code == 404
