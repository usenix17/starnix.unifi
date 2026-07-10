# -*- coding: utf-8 -*-
# Copyright: (c) 2026, Sasha Karcz <sasha@starnix.net>
# GPL-3.0-or-later (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
"""Unit tests for the unifi_firewall_policy_order module (no network)."""
# pylint: disable=too-few-public-methods

import pytest

from ansible_collections.starnix.unifi.plugins.modules import (
    unifi_firewall_policy_order as order,
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
    """Return a canned ordering on GET and record the PUT."""

    def __init__(self, current):
        self.current = current
        self.calls = []

    def get(self, path, query=None):
        """Return the canned ordering wrapper."""
        self.calls.append(("get", path, query))
        return {"orderedFirewallPolicyIds": self.current}

    def put(self, path, body=None, query=None):
        """Echo the body."""
        self.calls.append(("put", path, body, query))
        return body


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
    base = {"state": "present", "source_zone_id": "z1",
            "destination_zone_id": "z1",
            "before_system_defined": ["a", "b"],
            "after_system_defined": None}
    base.update(over)
    return base


def _did(client, verb):
    return any(call[0] == verb for call in client.calls)


def test_noop_when_order_matches():
    """Current order equals desired -> no PUT, changed=false."""
    client = FakeClient({"beforeSystemDefined": ["a", "b"],
                         "afterSystemDefined": []})
    module = FakeModule(_params())
    with pytest.raises(_Exit):
        order.run(FakeUM(module, client))
    assert module.result["changed"] is False
    assert not _did(client, "put")


def test_reorder_is_a_change():
    """Different order (same members) -> PUT, changed=true."""
    client = FakeClient({"beforeSystemDefined": ["b", "a"],
                         "afterSystemDefined": []})
    module = FakeModule(_params())  # desired ["a", "b"]
    with pytest.raises(_Exit):
        order.run(FakeUM(module, client))
    assert module.result["changed"] is True
    assert _did(client, "put")


def test_full_replace_drops_omitted():
    """Omitting after clears it; a non-empty current after -> changed."""
    client = FakeClient({"beforeSystemDefined": ["a", "b"],
                         "afterSystemDefined": ["c"]})
    module = FakeModule(_params())  # after defaults to []
    with pytest.raises(_Exit):
        order.run(FakeUM(module, client))
    assert module.result["changed"] is True
    put = next(c for c in client.calls if c[0] == "put")
    assert put[2]["orderedFirewallPolicyIds"]["afterSystemDefined"] == []


def test_check_mode_does_not_write():
    """check_mode reports the change but performs no PUT."""
    client = FakeClient({"beforeSystemDefined": ["b", "a"],
                         "afterSystemDefined": []})
    module = FakeModule(_params(), check_mode=True)
    with pytest.raises(_Exit):
        order.run(FakeUM(module, client))
    assert module.result["changed"] is True
    assert not _did(client, "put")


def test_absent_is_rejected():
    """state=absent fails with a clear message."""
    client = FakeClient({"beforeSystemDefined": [], "afterSystemDefined": []})
    module = FakeModule(_params(state="absent"))
    with pytest.raises(_Fail):
        order.run(FakeUM(module, client))
    assert "empty list" in module.fail_msg
