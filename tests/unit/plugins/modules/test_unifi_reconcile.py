# -*- coding: utf-8 -*-
# Copyright: (c) 2026, Sasha Karcz <sasha@starnix.net>
# GNU General Public License v3.0+ (see LICENSE or gnu.org/licenses/gpl-3.0)
# SPDX-License-Identifier: GPL-3.0-or-later
"""Unit tests for the unifi_reconcile bulk module (no network)."""
# pylint: disable=protected-access

import pytest

from ansible_collections.starnix.unifi.plugins.module_utils import unifi
from ansible_collections.starnix.unifi.plugins.modules import (
    unifi_reconcile as rec,
)

_GROUP_SPEC = ("groups", "traffic-matching-lists", rec._group_body, (), False)


class FakeClient:
    """Record calls; serve canned collections, ordering, and dhcp nets."""

    def __init__(self, listing=None, ordering=None, dhcp_nets=None):
        self.listing = listing or []
        self.ordering = ordering or {}
        self.dhcp_nets = dhcp_nets or []
        self.calls = []

    def paginate(self, base):
        """Yield the canned collection."""
        self.calls.append(("paginate", base))
        return iter(self.listing)

    def get(self, path, query=None):
        """Serve ordering or classic networkconf reads."""
        self.calls.append(("get", path))
        if path.endswith("/ordering"):
            key = (query["sourceFirewallZoneId"],
                   query["destinationFirewallZoneId"])
            return {"orderedFirewallPolicyIds": self.ordering.get(key, {})}
        return {"data": self.dhcp_nets}

    def post(self, base, body=None):
        """Record a create."""
        self.calls.append(("post", base, body))
        return {**body, "id": "new"}

    def put(self, path, body=None, query=None):
        """Record an update."""
        self.calls.append(("put", path, body, query))
        return body

    def delete(self, path):
        """Record a delete."""
        self.calls.append(("delete", path))
        return {}


def _opts(**over):
    base = {"check": False, "prune": False, "max_delete": 10}
    base.update(over)
    return base


def _did(client, verb):
    return any(call[0] == verb for call in client.calls)


def _group(name, value):
    return {"name": name, "type": "IPV4_ADDRESSES",
            "items": [{"type": "IP_ADDRESS", "value": value}]}


# -- body builders --------------------------------------------------------
def test_zone_body_defaults_network_ids():
    """A zone with no networks sends networkIds=[]."""
    assert rec._zone_body({"name": "z"}) == {"name": "z", "networkIds": []}


def test_policy_body_prunes_none_and_defaults_logging():
    """Unset optional fields are dropped; loggingEnabled defaults to false."""
    body = rec._policy_body({
        "name": "p", "enabled": True, "action": {"type": "ALLOW"},
        "source": {}, "destination": {},
        "ip_protocol_scope": {"ipVersion": "IPV4"}})
    assert "ipsecFilter" not in body
    assert body["loggingEnabled"] is False
    assert body["ipProtocolScope"] == {"ipVersion": "IPV4"}


def test_dhcp_fields_sets_and_blanks_slots():
    """dns_servers fills slot 1, blanks slot 2, and enables DNS."""
    fields = rec._dhcp_fields({"dns_servers": ["1.1.1.1"], "lease_time": 3600})
    assert fields["dhcpd_dns_enabled"] is True
    assert fields["dhcpd_dns_1"] == "1.1.1.1"
    assert fields["dhcpd_dns_2"] == ""
    assert fields["dhcpd_leasetime"] == 3600


# -- collection reconcile -------------------------------------------------
def test_collection_create():
    """A missing item is created."""
    client = FakeClient(listing=[])
    changes = []
    rec._reconcile_collection(client, "/b", _GROUP_SPEC,
                              [_group("g", "1.1.1.1")], _opts(), changes)
    assert changes == [{"type": "groups", "action": "create", "name": "g"}]
    assert _did(client, "post")


def test_collection_noop():
    """A matching item makes no change and no write."""
    client = FakeClient(listing=[{"id": "g1", **_group("g", "1.1.1.1")}])
    changes = []
    rec._reconcile_collection(client, "/b", _GROUP_SPEC,
                              [_group("g", "1.1.1.1")], _opts(), changes)
    assert not changes
    assert not _did(client, "put")


def test_collection_update():
    """A differing item is updated (PUT)."""
    client = FakeClient(listing=[{"id": "g1", **_group("g", "1.1.1.1")}])
    changes = []
    rec._reconcile_collection(client, "/b", _GROUP_SPEC,
                              [_group("g", "9.9.9.9")], _opts(), changes)
    assert changes == [{"type": "groups", "action": "update", "name": "g"}]
    assert _did(client, "put")


def test_check_mode_records_but_does_not_write():
    """check_mode reports the change but performs no POST."""
    client = FakeClient(listing=[])
    changes = []
    rec._reconcile_collection(client, "/b", _GROUP_SPEC,
                              [_group("g", "1.1.1.1")], _opts(check=True),
                              changes)
    assert changes and not _did(client, "post")


def test_user_defined_only_filter():
    """A DERIVED object is invisible, so the desired item is created."""
    spec = ("policies", "firewall/policies", rec._policy_body,
            ("connectionStateFilter",), True)
    derived = {"id": "d", "name": "P", "metadata": {"origin": "DERIVED"}}
    client = FakeClient(listing=[derived])
    changes = []
    rec._reconcile_collection(
        client, "/b", spec,
        [{"name": "P", "enabled": True, "action": {"type": "ALLOW"},
          "source": {}, "destination": {},
          "ip_protocol_scope": {"ipVersion": "IPV4"}}],
        _opts(), changes)
    assert changes[0]["action"] == "create"


def test_prune_deletes_unlisted():
    """With prune, a managed item not in the desired set is deleted."""
    client = FakeClient(listing=[{"id": "g1", **_group("keep", "1.1.1.1")},
                                 {"id": "g2", **_group("drop", "2.2.2.2")}])
    changes = []
    rec._reconcile_collection(client, "/b", _GROUP_SPEC,
                              [_group("keep", "1.1.1.1")],
                              _opts(prune=True), changes)
    assert {"type": "groups", "action": "delete", "name": "drop"} in changes
    assert _did(client, "delete")


def test_prune_guard_aborts():
    """Prune beyond max_delete raises instead of mass-deleting."""
    listing = [{"id": str(i), **_group(f"x{i}", "1.1.1.1")} for i in range(5)]
    client = FakeClient(listing=listing)
    with pytest.raises(unifi.UniFiError):
        rec._reconcile_collection(client, "/b", _GROUP_SPEC, [],
                                  _opts(prune=True, max_delete=2), [])


# -- ordering -------------------------------------------------------------
def test_ordering_change_and_noop():
    """Reorder is a change; the same order is a no-op."""
    order = {("z1", "z2"): {"beforeSystemDefined": ["a", "b"],
                            "afterSystemDefined": []}}
    changes = []
    rec._reconcile_ordering(
        FakeClient(ordering=order), "s",
        [{"source_zone": "z1", "destination_zone": "z2",
          "before_system_defined": ["b", "a"]}], _opts(), changes)
    assert changes and changes[0]["action"] == "update"
    changes = []
    rec._reconcile_ordering(
        FakeClient(ordering=order), "s",
        [{"source_zone": "z1", "destination_zone": "z2",
          "before_system_defined": ["a", "b"]}], _opts(), changes)
    assert not changes


# -- dhcp -----------------------------------------------------------------
def test_dhcp_patch_and_skip_unknown():
    """DHCP patches a matching network; unknown names are skipped."""
    nets = [{"_id": "n1", "name": "Aux", "dhcpd_dns_enabled": True,
             "dhcpd_dns_1": "1.1.1.1"}]
    changes = []
    rec._reconcile_dhcp(FakeClient(dhcp_nets=nets), "default",
                        [{"name": "Aux", "dns_servers": ["9.9.9.9"]}],
                        _opts(), changes)
    assert changes[0] == {"type": "dhcp", "action": "update", "name": "Aux"}
    changes = []
    rec._reconcile_dhcp(FakeClient(dhcp_nets=[]), "default",
                        [{"name": "Nope", "dns_servers": ["9.9.9.9"]}],
                        _opts(), changes)
    assert not changes


def test_dhcp_noop_when_matching():
    """Re-applying current DNS is a no-op."""
    nets = [{"_id": "n1", "name": "Aux", "dhcpd_dns_enabled": True,
             "dhcpd_dns_1": "1.1.1.1", "dhcpd_dns_2": ""}]
    changes = []
    rec._reconcile_dhcp(FakeClient(dhcp_nets=nets), "default",
                        [{"name": "Aux", "dns_servers": ["1.1.1.1"]}],
                        _opts(), changes)
    assert not changes
