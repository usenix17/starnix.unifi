# -*- coding: utf-8 -*-
# Copyright: (c) 2026, Sasha Karcz <sasha@starnix.net>
# GPL-3.0-or-later (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
"""Unit tests for the starnix.unifi shared module_utils (no network)."""
# pylint: disable=protected-access,too-few-public-methods

import io
import json
from urllib.error import HTTPError

import pytest

from ansible_collections.starnix.unifi.plugins.module_utils import unifi


def make_client():
    """Return a client instance; no connection is opened until a request."""
    return unifi.UniFiClient("host.example", 443, "secret-key")


class FakeResp:
    """Minimal stand-in for a urllib response object."""

    def __init__(self, raw):
        self._raw = raw

    def read(self):
        """Return the canned raw body."""
        return self._raw


# -- URL assembly ---------------------------------------------------------
def test_url_joins_prefix_and_path():
    """Base, prefix, and path concatenate; None query values drop out."""
    client = make_client()
    url = client._url("/v1/sites", query={"limit": 5, "offset": None})
    assert url == ("https://host.example:443/proxy/network/integration"
                   "/v1/sites?limit=5")


# -- request / decode -----------------------------------------------------
def test_request_decodes_json(monkeypatch):
    """A JSON body is decoded and returned."""
    client = make_client()
    monkeypatch.setattr(client._request, "open",
                        lambda m, u, data=None: FakeResp(b'{"a": 1}'))
    assert client.request("GET", "/x") == {"a": 1}


def test_request_empty_body_is_empty_dict(monkeypatch):
    """An empty body yields an empty dict, not an error."""
    client = make_client()
    monkeypatch.setattr(client._request, "open",
                        lambda m, u, data=None: FakeResp(b""))
    assert client.request("GET", "/x") == {}


def test_to_unifi_error_round_trips_envelope(monkeypatch):
    """The error envelope populates status/code/request_path and message."""
    body = json.dumps({
        "statusCode": 404, "statusName": "NOT_FOUND", "message": "no such",
        "code": "NOT_FOUND", "requestId": "req-1", "requestPath": "/v1/p",
    }).encode()
    err = HTTPError("https://x", 404, "Not Found", {}, io.BytesIO(body))
    client = make_client()

    def boom(_method, _url, data=None):
        raise err

    monkeypatch.setattr(client._request, "open", boom)
    with pytest.raises(unifi.UniFiError) as caught:
        client.request("GET", "/v1/p")
    exc = caught.value
    assert exc.status == 404
    assert exc.code == "NOT_FOUND"
    assert exc.request_path == "/v1/p"
    assert "no such" in str(exc)


def test_error_without_message_falls_back(monkeypatch):
    """A body lacking 'message' does not render a '404 : ' blank message."""
    body = json.dumps({"statusCode": 404, "code": "GONE"}).encode()
    err = HTTPError("https://x", 404, "Not Found", {}, io.BytesIO(body))
    client = make_client()

    def boom(_method, _url, data=None):
        raise err

    monkeypatch.setattr(client._request, "open", boom)
    with pytest.raises(unifi.UniFiError) as caught:
        client.request("GET", "/x")
    assert "GONE" in str(caught.value)


# -- pagination -----------------------------------------------------------
def test_paginate_advances_by_returned_count(monkeypatch):
    """Offset advances by items returned, never the requested page size."""
    client = make_client()
    pages = [
        {"data": [1, 2], "count": 2, "totalCount": 3},  # asked 200, got 2
        {"data": [3], "count": 1, "totalCount": 3},
    ]
    seen_offsets = []

    def fake_request(_method, _path, query=None):
        seen_offsets.append(query["offset"])
        return pages[len(seen_offsets) - 1]

    monkeypatch.setattr(client, "request", fake_request)
    assert list(client.paginate("/x")) == [1, 2, 3]
    assert seen_offsets == [0, 2]  # not [0, 200]


def test_paginate_stops_on_empty_page(monkeypatch):
    """A count==0 page terminates the walk without looping."""
    client = make_client()
    monkeypatch.setattr(
        client, "request",
        lambda *a, **k: {"data": [], "count": 0, "totalCount": 0})
    assert not list(client.paginate("/x"))


# -- site resolution ------------------------------------------------------
def test_resolve_site_uuid_passthrough():
    """A UUID is returned unchanged without any API call."""
    client = make_client()
    uuid = "88f7af54-98f8-306a-a1c7-c9349722b1f6"
    assert client.resolve_site(uuid) == uuid


def test_resolve_site_default_single(monkeypatch):
    """'default' resolves to the only site's id on a single-site controller."""
    client = make_client()
    monkeypatch.setattr(client, "paginate", lambda _p: iter([{"id": "s-1"}]))
    assert client.resolve_site("default") == "s-1"


def test_resolve_site_default_multi_fails(monkeypatch):
    """'default' is ambiguous on a multi-site controller."""
    client = make_client()
    monkeypatch.setattr(
        client, "paginate",
        lambda _p: iter([{"id": "a"}, {"id": "b"}]))
    with pytest.raises(unifi.UniFiError):
        client.resolve_site("default")


def test_resolve_site_nonuuid_name_fails():
    """A non-UUID, non-'default' value is rejected."""
    with pytest.raises(unifi.UniFiError):
        make_client().resolve_site("my-site")


# -- diff helpers ---------------------------------------------------------
def test_subset_equal_ignores_server_injected_keys():
    """Server-added keys inside an opaque object do not count as drift."""
    desired = {"name": "p", "action": {"type": "ALLOW"}}
    current = {"name": "p", "id": "1",
               "action": {"type": "ALLOW", "allowReturnTraffic": False}}
    assert unifi.subset_equal(desired, current)


def test_subset_equal_detects_declared_drift():
    """A declared key that differs is drift."""
    assert not unifi.subset_equal({"name": "x"}, {"name": "y"})


def test_needs_update_set_keys_order_insensitive():
    """Set-typed fields compare by membership, not order."""
    changed, _ = unifi.needs_update(
        {"networkIds": ["a", "b"]}, {"networkIds": ["b", "a"]},
        set_keys={"networkIds"})
    assert changed is False


def test_needs_update_reports_change_and_diff():
    """A real change is reported with a focused before/after diff."""
    changed, diff = unifi.needs_update({"enabled": True}, {"enabled": False})
    assert changed
    assert diff["before"] == {"enabled": False}
    assert diff["after"] == {"enabled": True}


def test_prune_drops_none_recursively():
    """None values are removed at every depth."""
    assert unifi.prune({"a": 1, "b": None, "c": {"d": None, "e": 2}}) == \
        {"a": 1, "c": {"e": 2}}
