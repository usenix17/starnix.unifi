# -*- coding: utf-8 -*-
# Copyright: (c) 2026, Sasha Karcz <sasha@starnix.net>
# GPL-3.0-or-later (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
"""Unit tests for the unifi_firewall_zone module (no network)."""
# pylint: disable=too-few-public-methods

import pytest

from ansible_collections.starnix.unifi.plugins.module_utils import unifi
from ansible_collections.starnix.unifi.plugins.modules import (
    unifi_firewall_zone as zone,
)


class _Exit(Exception):
    """Raised by the fake exit_json to halt like the real SystemExit."""


class _Fail(Exception):
    """Raised by the fake fail_json to halt like the real SystemExit."""


class FakeModule:
    """Capture exit_json/fail_json and stop flow, like AnsibleModule."""

    def __init__(self, params, check_mode=False):
        self.params = params
        self.check_mode = check_mode
        self.result = None
        self.fail_msg = None

    def exit_json(self, **kwargs):
        """Record the result and halt."""
        self.result = kwargs
        raise _Exit()

    def fail_json(self, msg=None, **_kwargs):
        """Record the failure and halt."""
        self.fail_msg = msg
        raise _Fail()


class FakeClient:
    """Record calls and return canned zone objects."""

    def __init__(self, listing=None, get_obj=None):
        self.listing = listing or []
        self.get_obj = get_obj
        self.calls = []

    def paginate(self, path):
        """Return the canned collection."""
        self.calls.append(("paginate", path))
        return iter(self.listing)

    def get(self, path):
        """Return the canned object, or raise a 404 UniFiError."""
        self.calls.append(("get", path))
        if self.get_obj is not None:
            return self.get_obj
        raise unifi.UniFiError("not found", status=404)

    def post(self, path, body=None):
        """Echo the body with a server-assigned id."""
        self.calls.append(("post", path, body))
        return {**body, "id": "new-id"}

    def put(self, path, body=None):
        """Echo the body, preserving the existing id."""
        self.calls.append(("put", path, body))
        return {**body, "id": "existing-id"}

    def delete(self, path):
        """Record a delete."""
        self.calls.append(("delete", path))
        return {}


class FakeUM:
    """Minimal UniFiModule stand-in."""

    def __init__(self, module, client):
        self.module = module
        self.client = client
        self.site_id = "site-1"

    def fail(self, msg, **kwargs):
        """Delegate to the fake module."""
        self.module.fail_json(msg=msg, **kwargs)


def _params(**over):
    """Return a params dict with sensible defaults, overridable."""
    base = {"state": "present", "name": "Aux", "id": None,
            "network_ids": ["net-a"]}
    base.update(over)
    return base


def _existing(**over):
    """Return a live zone object."""
    base = {"id": "existing-id", "name": "Aux", "networkIds": ["net-a"],
            "metadata": {"origin": "USER_DEFINED"}}
    base.update(over)
    return base


def _did(client, verb):
    return any(call[0] == verb for call in client.calls)


def test_create_when_absent():
    """No existing zone -> POST networkIds, changed=true."""
    client = FakeClient(listing=[])
    module = FakeModule(_params())
    with pytest.raises(_Exit):
        zone.run(FakeUM(module, client))
    assert module.result["changed"] is True
    assert _did(client, "post")


def test_create_defaults_network_ids_to_empty():
    """Omitting network_ids sends networkIds=[] (API requires it non-null)."""
    client = FakeClient(listing=[])
    module = FakeModule(_params(network_ids=None))
    with pytest.raises(_Exit):
        zone.run(FakeUM(module, client))
    post = next(c for c in client.calls if c[0] == "post")
    assert post[2]["networkIds"] == []


def test_noop_when_matching():
    """Existing zone equals desired -> no write."""
    client = FakeClient(listing=[_existing()])
    module = FakeModule(_params())
    with pytest.raises(_Exit):
        zone.run(FakeUM(module, client))
    assert module.result["changed"] is False
    assert not _did(client, "put")


def test_network_ids_order_insensitive():
    """networkIds compares as a set, so order is not a change."""
    client = FakeClient(listing=[_existing(networkIds=["net-a", "net-b"])])
    module = FakeModule(_params(network_ids=["net-b", "net-a"]))
    with pytest.raises(_Exit):
        zone.run(FakeUM(module, client))
    assert module.result["changed"] is False


def test_update_when_networks_differ():
    """A different network set -> PUT, changed=true."""
    client = FakeClient(listing=[_existing(networkIds=["net-z"])])
    module = FakeModule(_params())
    with pytest.raises(_Exit):
        zone.run(FakeUM(module, client))
    assert module.result["changed"] is True
    assert _did(client, "put")


def test_delete_when_present():
    """state=absent with an existing zone -> DELETE, changed=true."""
    client = FakeClient(listing=[_existing()])
    module = FakeModule(_params(state="absent"))
    with pytest.raises(_Exit):
        zone.run(FakeUM(module, client))
    assert module.result["changed"] is True
    assert _did(client, "delete")


def test_absent_noop_when_missing():
    """state=absent with no existing zone -> changed=false."""
    client = FakeClient(listing=[])
    module = FakeModule(_params(state="absent"))
    with pytest.raises(_Exit):
        zone.run(FakeUM(module, client))
    assert module.result["changed"] is False
    assert not _did(client, "delete")


def test_check_mode_does_not_write():
    """check_mode computes changed but performs no POST."""
    client = FakeClient(listing=[])
    module = FakeModule(_params(), check_mode=True)
    with pytest.raises(_Exit):
        zone.run(FakeUM(module, client))
    assert module.result["changed"] is True
    assert not _did(client, "post")


def test_duplicate_name_fails():
    """Two zones sharing the name -> fail, ask for id."""
    client = FakeClient(listing=[_existing(id="a"), _existing(id="b")])
    module = FakeModule(_params())
    with pytest.raises(_Fail):
        zone.run(FakeUM(module, client))
    assert "disambiguate" in module.fail_msg
