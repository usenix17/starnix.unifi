# -*- coding: utf-8 -*-
# Copyright: (c) 2026, Sasha Karcz <sasha@starnix.net>
# GPL-3.0-or-later (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
"""Unit tests for the unifi_network module (no network calls)."""
# pylint: disable=too-few-public-methods

import pytest

from ansible_collections.starnix.unifi.plugins.module_utils import unifi
from ansible_collections.starnix.unifi.plugins.modules import (
    unifi_network as net,
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
        self.fail_kwargs = None

    def exit_json(self, **kwargs):
        """Record the result and halt."""
        self.result = kwargs
        raise _Exit()

    def fail_json(self, msg=None, **kwargs):
        """Record the failure and halt."""
        self.fail_msg = msg
        self.fail_kwargs = kwargs
        raise _Fail()


class FakeClient:
    """Record calls and return canned network objects."""

    def __init__(self, listing=None, references=None, delete_error=False):
        self.listing = listing or []
        self.references = references
        self.delete_error = delete_error
        self.calls = []

    def paginate(self, path):
        """Return the canned collection."""
        self.calls.append(("paginate", path))
        return iter(self.listing)

    def get(self, path, _query=None):
        """Return references for a references path; else a 404."""
        self.calls.append(("get", path))
        if path.endswith("/references"):
            return {"referenceResources": self.references or []}
        raise unifi.UniFiError("not found", status=404)

    def post(self, path, body=None):
        """Echo the body with a server-assigned id."""
        self.calls.append(("post", path, body))
        return {**body, "id": "new-id"}

    def put(self, path, body=None):
        """Echo the body, preserving the existing id."""
        self.calls.append(("put", path, body))
        return {**body, "id": "existing-id"}

    def delete(self, path, query=None):
        """Record a delete, or raise if configured to fail."""
        self.calls.append(("delete", path, query))
        if self.delete_error:
            raise unifi.UniFiError("in use", status=409)
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
    base = {"state": "present", "name": "Net", "id": None,
            "management": "GATEWAY", "enabled": True, "vlan_id": 10,
            "zone_id": None, "dhcp_guarding": None, "force": False}
    base.update(over)
    return base


def _existing(**over):
    """Return a live network object."""
    base = {"id": "existing-id", "name": "Net", "management": "GATEWAY",
            "enabled": True, "vlanId": 10, "zoneId": "z-existing",
            "metadata": {"origin": "USER_DEFINED"}, "default": False}
    base.update(over)
    return base


def _put_body(client):
    return next(c[2] for c in client.calls if c[0] == "put")


def _did(client, verb):
    return any(call[0] == verb for call in client.calls)


def test_create_when_absent():
    """No existing network -> POST with management + vlanId, changed=true."""
    client = FakeClient(listing=[])
    module = FakeModule(_params())
    with pytest.raises(_Exit):
        net.run(FakeUM(module, client))
    assert module.result["changed"] is True
    post = next(c for c in client.calls if c[0] == "post")
    assert post[2]["management"] == "GATEWAY" and post[2]["vlanId"] == 10


def test_noop_when_matching():
    """Existing network equals desired -> no write."""
    client = FakeClient(listing=[_existing()])
    module = FakeModule(_params())
    with pytest.raises(_Exit):
        net.run(FakeUM(module, client))
    assert module.result["changed"] is False
    assert not _did(client, "put")


def test_zone_id_carried_forward_on_update():
    """Omitting zone_id on update preserves the current zoneId in the PUT."""
    client = FakeClient(listing=[_existing()])
    module = FakeModule(_params(vlan_id=99))  # change forces a PUT
    with pytest.raises(_Exit):
        net.run(FakeUM(module, client))
    assert module.result["changed"] is True
    assert _put_body(client)["zoneId"] == "z-existing"


def test_dhcp_guarding_order_insensitive():
    """trustedDhcpServerIpAddresses compares as an unordered set."""
    client = FakeClient(listing=[_existing(dhcpGuarding={
        "trustedDhcpServerIpAddresses": ["1.1.1.1", "2.2.2.2"]})])
    module = FakeModule(_params(dhcp_guarding={
        "trusted_dhcp_server_ip_addresses": ["2.2.2.2", "1.1.1.1"]}))
    with pytest.raises(_Exit):
        net.run(FakeUM(module, client))
    assert module.result["changed"] is False


def test_update_when_vlan_differs():
    """A different VLAN id -> PUT, changed=true."""
    client = FakeClient(listing=[_existing(vlanId=20)])
    module = FakeModule(_params())  # desired vlan 10
    with pytest.raises(_Exit):
        net.run(FakeUM(module, client))
    assert module.result["changed"] is True
    assert _did(client, "put")


def test_delete_when_present():
    """state=absent with an existing network -> DELETE, changed=true."""
    client = FakeClient(listing=[_existing()])
    module = FakeModule(_params(state="absent"))
    with pytest.raises(_Exit):
        net.run(FakeUM(module, client))
    assert module.result["changed"] is True
    assert _did(client, "delete")


def test_delete_reports_references_on_failure():
    """A failed delete surfaces what still references the network."""
    client = FakeClient(listing=[_existing()], delete_error=True,
                        references=[{"type": "FIREWALL_POLICY", "id": "p1"}])
    module = FakeModule(_params(state="absent"))
    with pytest.raises(_Fail):
        net.run(FakeUM(module, client))
    assert module.fail_kwargs["referenceResources"] == [
        {"type": "FIREWALL_POLICY", "id": "p1"}]


def test_absent_noop_when_missing():
    """state=absent with no existing network -> changed=false."""
    client = FakeClient(listing=[])
    module = FakeModule(_params(state="absent"))
    with pytest.raises(_Exit):
        net.run(FakeUM(module, client))
    assert module.result["changed"] is False
    assert not _did(client, "delete")


def test_check_mode_does_not_write():
    """check_mode computes changed but performs no POST."""
    client = FakeClient(listing=[])
    module = FakeModule(_params(), check_mode=True)
    with pytest.raises(_Exit):
        net.run(FakeUM(module, client))
    assert module.result["changed"] is True
    assert not _did(client, "post")


def test_duplicate_name_fails():
    """Two networks sharing the name -> fail, ask for id."""
    client = FakeClient(listing=[_existing(id="a"), _existing(id="b")])
    module = FakeModule(_params())
    with pytest.raises(_Fail):
        net.run(FakeUM(module, client))
    assert "disambiguate" in module.fail_msg
