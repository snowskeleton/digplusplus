"""Tests for app.py: Flask routes and error-to-HTTP-status mapping."""

import pytest

import app as app_module
import dnstools


@pytest.fixture
def client():
    app_module.app.config["TESTING"] = True
    return app_module.app.test_client()


def test_index_serves_html(client):
    resp = client.get("/")
    assert resp.status_code == 200
    assert b"dig++" in resp.data


def test_non_json_body_is_invalid_input(client):
    resp = client.post("/api/dig", data="not json", content_type="text/plain")
    assert resp.status_code == 400
    assert resp.get_json()["code"] == "invalid_input"


def test_missing_domain_is_invalid_input(client):
    resp = client.post("/api/dig", json={})
    assert resp.status_code == 400
    assert resp.get_json()["code"] == "invalid_input"


def test_invalid_type_is_invalid_input(client):
    resp = client.post("/api/dig", json={"domain": "example.com", "type": "BOGUS"})
    assert resp.status_code == 400
    assert resp.get_json()["code"] == "invalid_input"


def test_invalid_server_is_invalid_input(client):
    resp = client.post(
        "/api/dig", json={"domain": "example.com", "server": "not-an-ip"}
    )
    assert resp.status_code == 400
    assert resp.get_json()["code"] == "invalid_input"


def test_dmarc_subdomain_is_accepted(client, monkeypatch):
    monkeypatch.setattr(
        dnstools,
        "lookup",
        lambda *a, **k: {"query": {}, "rcode": "NOERROR", "answers": []},
    )
    resp = client.post("/api/dig", json={"domain": "_dmarc.example.com", "type": "TXT"})
    assert resp.status_code == 200


def test_successful_lookup(client, monkeypatch):
    fake_result = {
        "query": {"domain": "example.com", "type": "A", "server": None},
        "rcode": "NOERROR",
        "flags": "",
        "authoritative": False,
        "query_time_ms": 12.3,
        "answers": [{"name": "example.com.", "ttl": 300, "type": "A", "data": "93.184.216.34"}],
    }
    monkeypatch.setattr(dnstools, "lookup", lambda *a, **k: fake_result)

    resp = client.post("/api/dig", json={"domain": "example.com", "type": "A"})

    assert resp.status_code == 200
    assert resp.get_json() == fake_result


def test_successful_trace(client, monkeypatch):
    fake_result = {
        "query": {"domain": "example.com", "type": "A"},
        "hops": [],
        "final_answer": None,
        "total_time_ms": 5.0,
        "error": None,
    }
    monkeypatch.setattr(dnstools, "trace", lambda *a, **k: fake_result)

    resp = client.post("/api/dig", json={"domain": "example.com", "trace": True})

    assert resp.status_code == 200
    assert resp.get_json() == fake_result


def test_timeout_maps_to_504(client, monkeypatch):
    def raise_timeout(*a, **k):
        raise dnstools.DigError("DNS query timed out.", "timeout")

    monkeypatch.setattr(dnstools, "lookup", raise_timeout)

    resp = client.post("/api/dig", json={"domain": "example.com", "server": "192.0.2.1"})

    assert resp.status_code == 504
    assert resp.get_json()["code"] == "timeout"


def test_no_nameservers_maps_to_502(client, monkeypatch):
    def raise_no_nameservers(*a, **k):
        raise dnstools.DigError("No response from nameserver.", "no_nameservers")

    monkeypatch.setattr(dnstools, "lookup", raise_no_nameservers)

    resp = client.post("/api/dig", json={"domain": "example.com", "server": "192.0.2.1"})

    assert resp.status_code == 502
    assert resp.get_json()["code"] == "no_nameservers"


def test_unexpected_exception_maps_to_500(client, monkeypatch):
    def raise_boom(*a, **k):
        raise RuntimeError("boom")

    monkeypatch.setattr(dnstools, "lookup", raise_boom)

    resp = client.post("/api/dig", json={"domain": "example.com"})

    assert resp.status_code == 500
    assert resp.get_json()["code"] == "internal_error"
