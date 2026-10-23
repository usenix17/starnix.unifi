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

_GROUP_SPEC = ("groups", rec._group_body, (), None)


class FakeClient:
    """Record calls; serve canned ordering and dhcp reads."""

    def __init__(self, ordering=None, dhcp_nets=None):
        self.ordering = ordering or {}
        self.dhcp_nets = dhcp_nets or []
        self.calls = []

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


# -- name resolution ------------------------------------------------------
def test_resolve_name_uuid_and_unknown():
    """A name resolves; a UUID passes through; an unknown name fails."""
    mapping = {"Internal": "zid"}
    uuid = "88f7af54-98f8-306a-a1c7-c9349722b1f6"
    assert rec._resolve("Internal", mapping) == "zid"
    assert rec._resolve(uuid, mapping) == uuid
    with pytest.raises(unifi.UniFiError):
        rec._resolve("Nope", mapping)


def test_resolve_policy_resolves_zone_and_list():
    """Zone and list names become ids in source/destination."""
    maps = {"zones": {"Internal": "zid"}, "lists": {"Nebula": "lid"},
            "networks": {}, "policies": {}}
    item = {"name": "p",
            "source": {"zoneId": "Internal", "trafficFilter": {
                "type": "IP_ADDRESS", "ipAddressFilter": {
                    "type": "TRAFFIC_MATCHING_LIST",
                    "trafficMatchingListId": "Nebula"}}},
            "destination": {"zoneId": "Internal"}}
    out = rec._resolve_policy(item, maps)
    assert out["source"]["zoneId"] == "zid"
    assert out["destination"]["zoneId"] == "zid"
    assert (out["source"]["trafficFilter"]["ipAddressFilter"]
            ["trafficMatchingListId"]) == "lid"


def test_resolve_zone_and_network():
    """Zone network names and a network's zone name resolve."""
    maps = {"zones": {"Aux": "azid"}, "networks": {"Guest": "gid"},
            "lists": {}, "policies": {}}
    assert rec._resolve_zone({"name": "z", "network_ids": ["Guest"]},
                             maps)["network_ids"] == ["gid"]
    assert rec._resolve_network({"name": "n", "zone_id": "Aux"},
                                maps)["zone_id"] == "azid"


# -- body builders --------------------------------------------------------
def test_policy_body_prunes_none_and_defaults_logging():
    """Unset optional fields are dropped; loggingEnabled defaults to false."""
    body = rec._policy_body({
        "name": "p", "enabled": True, "action": {"type": "ALLOW"},
        "source": {}, "destination": {},
        "ip_protocol_scope": {"ipVersion": "IPV4"}})
    assert "ipsecFilter" not in body
    assert body["loggingEnabled"] is False


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
    client = FakeClient()
    changes = []
    rec._reconcile_collection(client, "/b", [], [_group("g", "1.1.1.1")],
                              _GROUP_SPEC, {}, _opts(), changes)
    assert changes == [{"type": "groups", "action": "create", "name": "g"}]
    assert _did(client, "post")


def test_collection_noop_and_update():
    """A matching item is a no-op; a differing item is updated."""
    current = [{"id": "g1", **_group("g", "1.1.1.1")}]
    client = FakeClient()
    changes = []
    rec._reconcile_collection(client, "/b", current, [_group("g", "1.1.1.1")],
                              _GROUP_SPEC, {}, _opts(), changes)
    assert not changes and not _did(client, "put")
    rec._reconcile_collection(client, "/b", current, [_group("g", "9.9.9.9")],
                              _GROUP_SPEC, {}, _opts(), changes)
    assert changes == [{"type": "groups", "action": "update", "name": "g"}]
    assert _did(client, "put")


def test_check_mode_records_but_does_not_write():
    """check_mode reports the change but performs no POST."""
    client = FakeClient()
    changes = []
    rec._reconcile_collection(client, "/b", [], [_group("g", "1.1.1.1")],
                              _GROUP_SPEC, {}, _opts(check=True), changes)
    assert changes and not _did(client, "post")


def test_policy_resolution_through_reconcile():
    """A policy's names are resolved before the body is compared/built."""
    spec = ("policies", rec._policy_body, ("connectionStateFilter",),
            rec._resolve_policy)
    maps = {"zones": {"Internal": "zid"}, "lists": {}, "networks": {},
            "policies": {}}
    current = [{"id": "p1", "name": "P", "enabled": True,
                "action": {"type": "ALLOW"}, "source": {"zoneId": "zid"},
                "destination": {"zoneId": "zid"},
                "ipProtocolScope": {"ipVersion": "IPV4"},
                "loggingEnabled": False,
                "metadata": {"origin": "USER_DEFINED"}}]
    changes = []
    rec._reconcile_collection(
        FakeClient(), "/b", current,
        [{"name": "P", "enabled": True, "action": {"type": "ALLOW"},
          "source": {"zoneId": "Internal"},
          "destination": {"zoneId": "Internal"},
          "ip_protocol_scope": {"ipVersion": "IPV4"}}],
        spec, maps, _opts(), changes)
    assert not changes  # "Internal" resolved to zid -> matches -> no-op


def test_policy_list_order_is_not_drift():
    """Reordered networkIds/items are a no-op; changed members still update."""
    spec = ("policies", rec._policy_body, unifi.POLICY_SET_KEYS, None)
    ips = [{"type": "IP_ADDRESS", "value": v} for v in ("a", "b", "c")]
    live = {"id": "p1", "name": "P", "enabled": True,
            "action": {"type": "ALLOW"}, "loggingEnabled": False,
            "source": {"zoneId": "z", "trafficFilter": {
                "type": "NETWORK", "networkFilter": {
                    "networkIds": ["n3", "n1", "n2"]}}},
            "destination": {"zoneId": "z", "trafficFilter": {
                "type": "IP_ADDRESS",
                "ipAddressFilter": {"items": ips[::-1]}}}}

    def want(nets, items):
        return {"name": "P", "enabled": True, "action": {"type": "ALLOW"},
                "source": {"zoneId": "z", "trafficFilter": {
                    "type": "NETWORK",
                    "networkFilter": {"networkIds": nets}}},
                "destination": {"zoneId": "z", "trafficFilter": {
                    "type": "IP_ADDRESS",
                    "ipAddressFilter": {"items": items}}}}

    changes = []
    rec._reconcile_collection(FakeClient(), "/b", [live],
                              [want(["n1", "n2", "n3"], ips)], spec, {},
                              _opts(), changes)
    assert not changes
    rec._reconcile_collection(FakeClient(), "/b", [live],
                              [want(["n1", "n2"], ips)], spec, {},
                              _opts(), changes)
    assert changes == [{"type": "policies", "action": "update", "name": "P"}]


def test_prune_deletes_and_guards():
    """Prune deletes unlisted; beyond max_delete it aborts."""
    current = [{"id": "g1", **_group("keep", "1.1.1.1")},
               {"id": "g2", **_group("drop", "2.2.2.2")}]
    client = FakeClient()
    changes = []
    rec._reconcile_collection(client, "/b", current,
                              [_group("keep", "1.1.1.1")], _GROUP_SPEC, {},
                              _opts(prune=True), changes)
    assert {"type": "groups", "action": "delete", "name": "drop"} in changes
    with pytest.raises(unifi.UniFiError):
        rec._reconcile_collection(client, "/b", current, [], _GROUP_SPEC, {},
                                  _opts(prune=True, max_delete=0), [])


# -- ordering + dhcp ------------------------------------------------------
def test_ordering_resolves_names_and_updates():
    """Zone/policy names resolve; a different order is a change."""
    maps = {"zones": {"Internal": "zid"}, "policies": {"A": "aid", "B": "bid"},
            "lists": {}, "networks": {}}
    order = {("zid", "zid"): {"beforeSystemDefined": ["aid", "bid"],
                              "afterSystemDefined": []}}
    changes = []
    rec._reconcile_ordering(
        FakeClient(ordering=order), "s",
        [{"source_zone": "Internal", "destination_zone": "Internal",
          "before_system_defined": ["B", "A"]}], maps, _opts(), changes)
    assert changes and changes[0]["action"] == "update"


def test_dhcp_patch_and_noop():
    """DHCP patches a drifted network and no-ops a matching one."""
    nets = [{"_id": "n1", "name": "Aux", "dhcpd_dns_enabled": True,
             "dhcpd_dns_1": "1.1.1.1", "dhcpd_dns_2": ""}]
    changes = []
    rec._reconcile_dhcp(FakeClient(dhcp_nets=nets), "default",
                        [{"name": "Aux", "dns_servers": ["9.9.9.9"]}],
                        _opts(), changes)
    assert changes[0]["type"] == "dhcp"
    changes = []
    rec._reconcile_dhcp(FakeClient(dhcp_nets=nets), "default",
                        [{"name": "Aux", "dns_servers": ["1.1.1.1"]}],
                        _opts(), changes)
    assert not changes


# -- static + traffic routes ----------------------------------------------
class RouteClient(FakeClient):
    """Serve classic routing/networkconf and v2 trafficroutes reads."""

    def __init__(self, static=None, traffic=None, nets=None):
        super().__init__()
        self.static = static or []
        self.traffic = traffic or []
        self.nets = nets or []

    def get(self, path, query=None):
        """Route reads to the canned collections."""
        self.calls.append(("get", path))
        if path.endswith("/rest/routing"):
            return {"data": self.static}
        if path.endswith("/rest/networkconf"):
            return {"data": self.nets}
        return self.traffic


_NETS = [{"_id": "wan1", "name": "CenturyLink"},
         {"_id": "wan2", "name": "FiberFirst"}]

_LIVE_STATIC = {"_id": "r1", "name": "Nebula", "enabled": True,
                "type": "static-route", "static-route_type": "nexthop-route",
                "static-route_network": "100.69.0.0/22",
                "static-route_nexthop": "192.168.1.56",
                "static-route_distance": 2, "site_id": "s",
                "gateway_device": "aa:bb", "gateway_type": "default"}


def _nebula(**over):
    item = {"name": "Nebula", "network": "100.69.0.0/22",
            "type": "nexthop-route", "next_hop": "192.168.1.56",
            "distance": 2}
    item.update(over)
    return item


def _cf_route(**over):
    item = {"description": "CF", "matching_target": "IP",
            "network_id": "CenturyLink", "kill_switch_enabled": False,
            "ip_addresses": [{"ip_or_subnet": "198.41.192.0/24",
                              "ip_version": "v4", "ports": [7844],
                              "port_ranges": []}],
            "target_devices": [{"type": "ALL_CLIENTS"}]}
    item.update(over)
    return item


def _params(**over):
    base = {"classic_site": "default", "static_routes": [],
            "traffic_routes": []}
    base.update(over)
    return base


def test_static_route_body_maps_fields():
    """Friendly keys map to static-route_* fields; unset keys are omitted."""
    body = rec._static_route_body(_nebula())
    assert body == {"name": "Nebula", "enabled": True, "type": "static-route",
                    "static-route_type": "nexthop-route",
                    "static-route_network": "100.69.0.0/22",
                    "static-route_nexthop": "192.168.1.56",
                    "static-route_distance": 2}
    hole = rec._static_route_body({"name": "B", "network": "203.0.113.0/24",
                                   "type": "blackhole", "distance": 1,
                                   "enabled": False})
    assert "static-route_nexthop" not in hole and hole["enabled"] is False


def test_static_route_noop_against_live():
    """A route matching the live object (plus server fields) is a no-op."""
    client = RouteClient(static=[_LIVE_STATIC])
    changes = []
    rec._reconcile_routes(client, _params(static_routes=[_nebula()]),
                          _opts(), changes)
    assert not changes and not _did(client, "put")


def test_static_route_update_overlays_live_object():
    """An update PUTs the live object with only the desired fields changed."""
    client = RouteClient(static=[_LIVE_STATIC])
    changes = []
    rec._reconcile_routes(client, _params(static_routes=[_nebula(
        next_hop="192.168.1.99")]), _opts(), changes)
    assert changes == [{"type": "static_routes", "action": "update",
                        "name": "Nebula"}]
    verb, path, body = client.calls[-1][:3]
    assert (verb, path) == ("put", "/api/s/default/rest/routing/r1")
    assert body["static-route_nexthop"] == "192.168.1.99"
    assert body["gateway_device"] == "aa:bb"


def test_traffic_route_create_resolves_network_name():
    """A missing traffic route is created with its WAN name resolved."""
    client = RouteClient(nets=_NETS)
    changes = []
    rec._reconcile_routes(client, _params(traffic_routes=[_cf_route()]),
                          _opts(), changes)
    assert changes == [{"type": "traffic_routes", "action": "create",
                        "name": "CF"}]
    verb, path, body = client.calls[-1]
    assert (verb, path) == ("post", "/v2/api/site/default/trafficroutes")
    assert body["network_id"] == "wan1" and body["enabled"] is True


def test_traffic_route_noop_update_and_id_passthrough():
    """Matching live route is a no-op; a raw network id passes through."""
    live = {"_id": "t1", "enabled": True, "domains": [], "regions": [],
            "ip_ranges": [], "next_hop": "",
            **_cf_route(network_id="wan1")}
    client = RouteClient(traffic=[live], nets=_NETS)
    changes = []
    rec._reconcile_routes(client, _params(traffic_routes=[_cf_route()]),
                          _opts(), changes)
    assert not changes
    rec._reconcile_routes(client, _params(traffic_routes=[_cf_route(
        network_id="wan2")]), _opts(), changes)
    assert changes[0]["action"] == "update"
    assert client.calls[-1][2]["network_id"] == "wan2"


def test_traffic_route_unknown_network_fails():
    """An unknown egress network name is an error, not a silent create."""
    with pytest.raises(unifi.UniFiError):
        rec._reconcile_routes(RouteClient(nets=_NETS), _params(
            traffic_routes=[_cf_route(network_id="Nope")]), _opts(), [])


def test_routes_check_mode_and_missing_key():
    """check mode writes nothing; an item without its match key fails."""
    client = RouteClient(nets=_NETS)
    changes = []
    rec._reconcile_routes(client, _params(static_routes=[_nebula()],
                                          traffic_routes=[_cf_route()]),
                          _opts(check=True), changes)
    assert len(changes) == 2 and not _did(client, "post")
    with pytest.raises(unifi.UniFiError):
        rec._reconcile_routes(client, _params(
            traffic_routes=[{"matching_target": "IP"}]), _opts(), [])


def test_route_prune_deletes_by_id_and_guards():
    """Prune removes unlisted routes by _id and honors max_delete."""
    stray = dict(_LIVE_STATIC, _id="r2", name="Old")
    client = RouteClient(static=[_LIVE_STATIC, stray])
    changes = []
    rec._reconcile_routes(client, _params(static_routes=[_nebula()]),
                          _opts(prune=True), changes)
    assert changes == [{"type": "static_routes", "action": "delete",
                        "name": "Old"}]
    assert ("delete", "/api/s/default/rest/routing/r2") in client.calls
    with pytest.raises(unifi.UniFiError):
        rec._reconcile_routes(client, _params(static_routes=[_nebula()]),
                              _opts(prune=True, max_delete=0), [])
