# -*- coding: utf-8 -*-
# Copyright: (c) 2026, Sasha Karcz <sasha@starnix.net>
# GPL-3.0-or-later (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
"""Unit tests for the unifi_firewall_policy module (no network)."""
# pylint: disable=too-few-public-methods

import pytest

from ansible_collections.starnix.unifi.plugins.module_utils import unifi
from ansible_collections.starnix.unifi.plugins.modules import (
    unifi_firewall_policy as pol,
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
    """Record calls and return canned policy objects."""

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
    base = {"state": "present", "name": "p", "id": None, "enabled": True,
            "description": None, "action": {"type": "ALLOW"},
            "source": {"zoneId": "z1"}, "destination": {"zoneId": "z1"},
            "ip_protocol_scope": {"ipVersion": "IPV4"},
            "connection_state_filter": None, "ipsec_filter": None,
            "logging_enabled": False, "schedule": None}
    base.update(over)
    return base


def _existing(**over):
    """Return a live USER_DEFINED policy, richer than the desired subset."""
    base = {"id": "existing-id", "name": "p", "enabled": True, "index": 10000,
            "action": {"type": "ALLOW", "allowReturnTraffic": False},
            "source": {"zoneId": "z1",
                       "trafficFilter": {"type": "IP_ADDRESS"}},
            "destination": {"zoneId": "z1"},
            "ipProtocolScope": {"ipVersion": "IPV4"},
            "loggingEnabled": False,
            "metadata": {"origin": "USER_DEFINED"}}
    base.update(over)
    return base


def _did(client, verb):
    return any(call[0] == verb for call in client.calls)


def test_create_when_absent():
    """No existing policy -> POST, changed=true."""
    client = FakeClient(listing=[])
    module = FakeModule(_params())
    with pytest.raises(_Exit):
        pol.run(FakeUM(module, client))
    assert module.result["changed"] is True
    assert module.result["firewall_policy"]["id"] == "new-id"
    assert _did(client, "post")


def test_noop_ignores_server_injected_keys():
    """Server-added keys in opaque objects must not report changed."""
    client = FakeClient(listing=[_existing()])  # extra action/source keys
    module = FakeModule(_params())
    with pytest.raises(_Exit):
        pol.run(FakeUM(module, client))
    assert module.result["changed"] is False
    assert not _did(client, "put")


def test_connection_state_filter_order_insensitive():
    """connectionStateFilter compares as a set, so order is not a change."""
    client = FakeClient(listing=[_existing(
        connectionStateFilter=["ESTABLISHED", "RELATED"])])
    module = FakeModule(_params(
        connection_state_filter=["RELATED", "ESTABLISHED"]))
    with pytest.raises(_Exit):
        pol.run(FakeUM(module, client))
    assert module.result["changed"] is False


def test_update_when_action_differs():
    """A declared field that differs -> PUT, changed=true."""
    client = FakeClient(listing=[_existing(action={"type": "BLOCK"})])
    module = FakeModule(_params())  # desired action type ALLOW
    with pytest.raises(_Exit):
        pol.run(FakeUM(module, client))
    assert module.result["changed"] is True
    assert _did(client, "put")


def test_delete_when_present():
    """state=absent with an existing policy -> DELETE, changed=true."""
    client = FakeClient(listing=[_existing()])
    module = FakeModule(_params(state="absent"))
    with pytest.raises(_Exit):
        pol.run(FakeUM(module, client))
    assert module.result["changed"] is True
    assert module.result["firewall_policy"] == {}
    assert _did(client, "delete")


def test_absent_noop_when_missing():
    """state=absent with no existing policy -> changed=false."""
    client = FakeClient(listing=[])
    module = FakeModule(_params(state="absent"))
    with pytest.raises(_Exit):
        pol.run(FakeUM(module, client))
    assert module.result["changed"] is False
    assert not _did(client, "delete")


def test_check_mode_does_not_write():
    """check_mode computes changed but performs no POST."""
    client = FakeClient(listing=[])
    module = FakeModule(_params(), check_mode=True)
    with pytest.raises(_Exit):
        pol.run(FakeUM(module, client))
    assert module.result["changed"] is True
    assert not _did(client, "post")


def test_refuse_non_user_defined_by_id():
    """Targeting a SYSTEM_DEFINED policy by id is refused."""
    system_policy = _existing(id="sys-1",
                              metadata={"origin": "SYSTEM_DEFINED"})
    client = FakeClient(get_obj=system_policy)
    module = FakeModule(_params(id="sys-1"))
    with pytest.raises(_Fail):
        pol.run(FakeUM(module, client))
    assert "user-managed" in module.fail_msg
    assert not _did(client, "put")


def test_name_lookup_skips_non_user_defined():
    """Name lookup ignores DERIVED/SYSTEM_DEFINED, so it creates instead."""
    client = FakeClient(listing=[
        _existing(id="d-1", metadata={"origin": "DERIVED"})])
    module = FakeModule(_params())
    with pytest.raises(_Exit):
        pol.run(FakeUM(module, client))
    assert module.result["changed"] is True
    assert _did(client, "post")  # created; the DERIVED one was not adopted


def test_duplicate_name_fails():
    """Two user-defined policies sharing the name -> fail, ask for id."""
    client = FakeClient(listing=[_existing(id="a"), _existing(id="b")])
    module = FakeModule(_params())
    with pytest.raises(_Fail):
        pol.run(FakeUM(module, client))
    assert "disambiguate" in module.fail_msg
