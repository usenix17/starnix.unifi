# -*- coding: utf-8 -*-
# Copyright: (c) 2026, Sasha Karcz <sasha@starnix.net>
# GNU General Public License v3.0+ (see LICENSE or gnu.org/licenses/gpl-3.0)
# SPDX-License-Identifier: GPL-3.0-or-later
"""Reconcile the whole UniFi firewall/network/DHCP state in one invocation."""

DOCUMENTATION = r"""
module: unifi_reconcile
short_description: Reconcile the whole UniFi state in a single invocation
version_added: "0.1.0"
description:
  - Bulk equivalent of the per-resource modules. Given the desired lists of
    lists, zones, networks, policies, ordering, and per-network DHCP options,
    it fetches each collection B(once), compares
    in memory, and writes B(only) the drift -- all in one module process.
  - Use this instead of looping the singular modules when you manage many
    resources; a full reconcile that would take minutes as per-resource tasks
    completes in seconds here (one process instead of one per resource).
  - Each list element has the same shape as the corresponding singular module's
    parameters (opaque objects such as C(action)/C(source)/C(destination) are
    passed through verbatim; cross-references must already be UUIDs).
  - Matching is by C(name) (unique). Only user-defined zones and policies are
    considered. DHCP patches existing networks by name; unknown names are
    skipped. The classic API is used for DHCP (see O(classic_site)).
author:
  - Sasha Karcz (@usenix17)
extends_documentation_fragment:
  - starnix.unifi.auth
options:
  groups:
    description:
      - Desired traffic-matching lists; see
        M(starnix.unifi.unifi_firewall_group).
    type: list
    elements: dict
    default: []
  zones:
    description:
      - Desired firewall zones; see M(starnix.unifi.unifi_firewall_zone).
    type: list
    elements: dict
    default: []
  networks:
    description: Desired networks (see M(starnix.unifi.unifi_network)).
    type: list
    elements: dict
    default: []
  policies:
    description:
      - Desired firewall policies; see
        M(starnix.unifi.unifi_firewall_policy).
    type: list
    elements: dict
    default: []
  ordering:
    description:
      - Desired policy ordering per zone pair. Each element has C(source_zone),
        C(destination_zone) (zone UUIDs) and C(before_system_defined) /
        C(after_system_defined) (policy UUID lists).
    type: list
    elements: dict
    default: []
  dhcp:
    description:
      - Desired per-network DHCP options; see
        M(starnix.unifi.unifi_network_dhcp).
    type: list
    elements: dict
    default: []
  classic_site:
    description:
      - Classic-API site B(name) used for the O(dhcp) reconcile (the v1 O(site)
        does not apply there).
    type: str
    default: default
  prune:
    description:
      - Delete user-defined groups/zones/networks/policies that are not in the
        desired lists. Off by default; ordering and DHCP are never pruned.
    type: bool
    default: false
  max_delete:
    description:
      - Safety cap; if O(prune) would delete more than this many items of any
        one type, the module fails instead.
    type: int
    default: 10
"""

EXAMPLES = r"""
- name: Reconcile the entire UniFi config in one call
  starnix.unifi.unifi_reconcile:
    host: heimdal.starnix.net
    api_key: "{{ lookup('env', 'UNIFI_API_KEY') }}"
    groups: "{{ unifi_groups }}"
    zones: "{{ unifi_zones }}"
    networks: "{{ unifi_networks }}"
    policies: "{{ unifi_policies }}"
    ordering: "{{ unifi_ordering }}"
    dhcp: "{{ unifi_dhcp }}"
"""

RETURN = r"""
changes:
  description: One entry per resource this run created, updated, or deleted.
  type: list
  elements: dict
  returned: success
  sample:
    - {type: "policies", action: "update", name: "Allow DNS"}
"""

# Imports follow the documentation variables, as required by ansible-test
# validate-modules.
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.starnix.unifi.plugins.module_utils.unifi import (
    UniFiClient,
    UniFiError,
    needs_update,
    prune,
    unifi_argument_spec,
)


def _group_body(item):
    return {"type": item["type"], "name": item["name"], "items": item["items"]}


def _zone_body(item):
    return {"name": item["name"], "networkIds": item.get("network_ids") or []}


def _network_body(item):
    return prune({
        "management": item["management"], "name": item["name"],
        "enabled": item["enabled"], "vlanId": item.get("vlan_id"),
        "zoneId": item.get("zone_id"),
    })


def _policy_body(item):
    return prune({
        "enabled": item["enabled"], "name": item["name"],
        "description": item.get("description"),
        "action": item.get("action"), "source": item.get("source"),
        "destination": item.get("destination"),
        "ipProtocolScope": item.get("ip_protocol_scope"),
        "connectionStateFilter": item.get("connection_state_filter"),
        "ipsecFilter": item.get("ipsec_filter"),
        "loggingEnabled": item.get("logging_enabled", False),
        "schedule": item.get("schedule"),
    })


# param name -> (v1 sub-path, body builder, set_keys, user-defined-only)
_COLLECTIONS = [
    ("groups", "traffic-matching-lists", _group_body, (), False),
    ("zones", "firewall/zones", _zone_body, ("networkIds",), True),
    ("networks", "networks", _network_body, (), False),
    ("policies", "firewall/policies", _policy_body,
     ("connectionStateFilter",), True),
]

_DHCP_SLOTS = {"dns_servers": ("dhcpd_dns", 4),
               "ntp_servers": ("dhcpd_ntp", 2),
               "wins_servers": ("dhcpd_wins", 2)}


def _manageable(objects, user_only):
    """Filter to the objects this module may manage."""
    if not user_only:
        return list(objects)
    return [o for o in objects
            if (o.get("metadata") or {}).get("origin") == "USER_DEFINED"]


def _reconcile_collection(client, base, spec, desired, opts, changes):
    """Create/update (and optionally prune) one name-matched collection."""
    param, _path, build, set_keys, user_only = spec
    current = _manageable(client.paginate(base), user_only)
    by_name = {}
    for obj in current:
        by_name.setdefault(obj["name"], obj)
    wanted = set()
    for item in desired:
        wanted.add(item["name"])
        body = build(item)
        cur = by_name.get(item["name"])
        if cur is None:
            if not opts["check"]:
                client.post(base, body=body)
            changes.append({"type": param, "action": "create",
                            "name": item["name"]})
        elif needs_update(body, cur, set_keys=set(set_keys))[0]:
            if not opts["check"]:
                client.put(f"{base}/{cur['id']}", body=body)
            changes.append({"type": param, "action": "update",
                            "name": item["name"]})
    if opts["prune"]:
        _prune_collection(client, base, param, current, wanted, opts,
                          changes)


def _prune_collection(client, base, param, current, wanted, opts, changes):
    """Delete managed objects of one type that are not in the desired set."""
    stale = [o for o in current if o["name"] not in wanted]
    if len(stale) > opts["max_delete"]:
        raise UniFiError(
            f"prune would delete {len(stale)} {param} (> max_delete="
            f"{opts['max_delete']}); aborting. Raise max_delete to proceed.")
    for obj in stale:
        if not opts["check"]:
            client.delete(f"{base}/{obj['id']}")
        changes.append({"type": param, "action": "delete",
                        "name": obj["name"]})


def _reconcile_ordering(client, site_id, desired, opts, changes):
    """Set the evaluation order for each declared zone pair."""
    path = f"/v1/sites/{site_id}/firewall/policies/ordering"
    for item in desired:
        query = {"sourceFirewallZoneId": item["source_zone"],
                 "destinationFirewallZoneId": item["destination_zone"]}
        cur = (client.get(path, query=query)
               .get("orderedFirewallPolicyIds") or {})
        want = {"beforeSystemDefined": item.get("before_system_defined") or [],
                "afterSystemDefined": item.get("after_system_defined") or []}
        have = {"beforeSystemDefined": cur.get("beforeSystemDefined") or [],
                "afterSystemDefined": cur.get("afterSystemDefined") or []}
        if have != want:
            if not opts["check"]:
                client.put(path, body={"orderedFirewallPolicyIds": want},
                           query=query)
            changes.append({"type": "ordering", "action": "update",
                            "name": f"{item['source_zone']} -> "
                                    f"{item['destination_zone']}"})


def _dhcp_fields(item):
    """Map a desired DHCP item to its classic dhcpd_* fields."""
    fields = {}
    for param, (prefix, count) in _DHCP_SLOTS.items():
        servers = item.get(param)
        if servers is not None:
            fields[f"{prefix}_enabled"] = bool(servers)
            for i in range(1, count + 1):
                fields[f"{prefix}_{i}"] = servers[i - 1] if i <= len(servers) \
                    else ""
    if item.get("lease_time") is not None:
        fields["dhcpd_leasetime"] = item["lease_time"]
    return fields


def _reconcile_dhcp(client, classic_site, desired, opts, changes):
    """Patch DHCP options on existing classic networks, matched by name."""
    base = f"/api/s/{classic_site}/rest/networkconf"
    by_name = {n["name"]: n for n in client.get(base).get("data", []) or []}
    for item in desired:
        net = by_name.get(item["name"])
        if net is None:
            continue
        fields = _dhcp_fields(item)
        differs = any(("" if net.get(k) is None else net.get(k)) != v
                      for k, v in fields.items())
        if differs:
            if not opts["check"]:
                client.put(f"{base}/{net['_id']}", body={**net, **fields})
            changes.append({"type": "dhcp", "action": "update",
                            "name": item["name"]})


def _client(params, base_path):
    """Build a UniFiClient for the given API base path."""
    return UniFiClient(
        host=params["host"], port=params["port"], api_key=params["api_key"],
        validate_certs=params["validate_certs"], ca_path=params.get("ca_path"),
        timeout=params["timeout"], api_base_path=base_path)


def run(module):
    """Reconcile every provided resource type in a single process."""
    params = module.params
    opts = {"check": module.check_mode, "prune": params["prune"],
            "max_delete": params["max_delete"]}
    changes = []
    v1 = _client(params, params["api_base_path"])
    site_id = v1.resolve_site(params["site"])
    for spec in _COLLECTIONS:
        if params[spec[0]]:
            base = f"/v1/sites/{site_id}/{spec[1]}"
            _reconcile_collection(v1, base, spec, params[spec[0]], opts,
                                  changes)
    if params["ordering"]:
        _reconcile_ordering(v1, site_id, params["ordering"], opts, changes)
    if params["dhcp"]:
        classic = _client(params, "/proxy/network")
        _reconcile_dhcp(classic, params["classic_site"], params["dhcp"],
                        opts, changes)
    module.exit_json(changed=bool(changes), changes=changes)


def main():
    """Module entry point."""
    spec = unifi_argument_spec()
    for name in ("groups", "zones", "networks", "policies", "ordering",
                 "dhcp"):
        spec[name] = {"type": "list", "elements": "dict", "default": []}
    spec.update(
        classic_site={"type": "str", "default": "default"},
        prune={"type": "bool", "default": False},
        max_delete={"type": "int", "default": 10},
    )
    module = AnsibleModule(argument_spec=spec, supports_check_mode=True)
    try:
        run(module)
    except UniFiError as exc:
        module.fail_json(msg=str(exc), unifi_status=exc.status,
                         unifi_error=exc.envelope)


if __name__ == "__main__":
    main()
