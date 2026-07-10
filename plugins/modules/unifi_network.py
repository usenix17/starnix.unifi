# -*- coding: utf-8 -*-
# Copyright: (c) 2026, Sasha Karcz <sasha@starnix.net>
# GPL-3.0-or-later (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
"""Manage UniFi networks (VLANs) via the v1 Integration API."""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.starnix.unifi.plugins.module_utils.unifi import (
    UniFiError,
    UniFiModule,
    needs_update,
    unifi_argument_spec,
)

DOCUMENTATION = r"""
module: unifi_network
short_description: Manage UniFi networks (VLANs)
version_added: "0.1.0"
description:
  - Create, update, and delete UniFi networks via the official Integration API
    (C(/v1/sites/{site}/networks)).
  - "Scope: in this API version a network object exposes only its VLAN
    identity (name, VLAN id, management mode, enabled) and firewall zone.
    There are no subnet, gateway, DHCP range/lease, or DHCP-DNS fields, so
    this module cannot manage DHCP-provided DNS servers or IP addressing;
    use the controller UI for those."
author:
  - Sasha Karcz (@usenix17)
extends_documentation_fragment:
  - starnix.unifi.auth
options:
  name:
    description:
      - Network name. Used as the lookup key when O(id) is not given.
    type: str
    required: true
  id:
    description:
      - UUID of an existing network. Authoritative; takes precedence over
        O(name).
    type: str
  management:
    description:
      - Network management mode. Required when O(state=present).
      - V(GATEWAY) is a routed network; V(UNMANAGED) is VLAN-only. Newer
        controllers may accept further values.
    type: str
    choices: [GATEWAY, UNMANAGED]
  enabled:
    description:
      - Whether the network is enabled.
    type: bool
    default: true
  vlan_id:
    description:
      - VLAN id (maps to C(vlanId)). Required when O(state=present).
    type: int
  zone_id:
    description:
      - UUID of the firewall zone the network belongs to (maps to C(zoneId)).
      - On update, omitting this B(preserves) the current zone; a bare
        full-replace PUT would otherwise clear it. Pass a value to reassign.
    type: str
  dhcp_guarding:
    description:
      - DHCP snooping configuration (maps to C(dhcpGuarding)). Omit to leave it
        unset.
    type: dict
    suboptions:
      trusted_dhcp_server_ip_addresses:
        description:
          - IP addresses allowed to serve DHCP on this network. Compared as
            an unordered set.
        type: list
        elements: str
        default: []
  state:
    description:
      - Whether the network should exist.
    type: str
    choices: [present, absent]
    default: present
  force:
    description:
      - On O(state=absent), pass C(force=true) to the delete request.
    type: bool
    default: false
"""

EXAMPLES = r"""
- name: Ensure a VLAN-only guest network exists
  starnix.unifi.unifi_network:
    host: heimdal.starnix.net
    api_key: "{{ lookup('env', 'UNIFI_API_KEY') }}"
    name: GuestVLAN
    management: UNMANAGED
    vlan_id: 40
    state: present

- name: Remove a network
  starnix.unifi.unifi_network:
    host: heimdal.starnix.net
    api_key: "{{ lookup('env', 'UNIFI_API_KEY') }}"
    name: GuestVLAN
    state: absent
    force: true
"""

RETURN = r"""
network:
  description: The network after the operation; an empty dict when absent.
  type: dict
  returned: success
  sample:
    id: "efb6ea9e-f402-4afa-af5f-420a39f6b3d5"
    name: "Aux"
    management: "GATEWAY"
    enabled: true
    vlanId: 5
    zoneId: "53432a66-51c0-4f3f-b226-02aac511a439"
    metadata: { origin: "USER_DEFINED" }
"""


def find_current(um, net_path, network_id, name):
    """Return the live network by UUID, or by name; else None."""
    if network_id:
        try:
            return um.client.get(f"{net_path}/{network_id}")
        except UniFiError as exc:
            if exc.status == 404:
                return None
            raise
    matches = [n for n in um.client.paginate(net_path)
               if n.get("name") == name]
    if len(matches) > 1:
        um.fail(f"found {len(matches)} networks named {name!r}; "
                "disambiguate with 'id'.")
    return matches[0] if matches else None


def _build_body(params, current):
    """Map user params to the API body.

    The firewall C(zoneId) is carried forward from the current network when the
    caller does not set O(zone_id), so a full-replace PUT never silently
    unsets it.
    """
    body = {
        "management": params["management"],
        "name": params["name"],
        "enabled": params["enabled"],
        "vlanId": params["vlan_id"],
    }
    zone = params.get("zone_id")
    if zone is None and current:
        zone = current.get("zoneId")
    if zone is not None:
        body["zoneId"] = zone
    guarding = params.get("dhcp_guarding")
    if guarding is not None:
        ips = guarding.get("trusted_dhcp_server_ip_addresses") or []
        body["dhcpGuarding"] = {"trustedDhcpServerIpAddresses": ips}
    return body


def _references(um, net_path, network_id):
    """Best-effort: what still references a network, for delete fails."""
    try:
        refs = um.client.get(f"{net_path}/{network_id}/references")
    except UniFiError:
        return None
    return refs.get("referenceResources")


def _absent(um, net_path, current):
    """Ensure the network does not exist."""
    if not current:
        um.module.exit_json(changed=False, network={})
    diff = {"before": current, "after": {}}
    if not um.module.check_mode:
        query = {"force": "true"} if um.module.params["force"] else None
        try:
            um.client.delete(f"{net_path}/{current['id']}", query=query)
        except UniFiError as exc:
            um.module.fail_json(
                msg=str(exc), unifi_error=exc.envelope,
                referenceResources=_references(um, net_path, current["id"]))
    um.module.exit_json(changed=True, network={}, diff=diff)


def _present(um, net_path, current):
    """Ensure the network exists and matches the declared spec."""
    check = um.module.check_mode
    body = _build_body(um.module.params, current)

    if current is None:
        diff = {"before": {}, "after": body}
        result = body if check else um.client.post(net_path, body=body)
        um.module.exit_json(changed=True, network=result, diff=diff)

    changed, diff = needs_update(
        body, current, set_keys={"trustedDhcpServerIpAddresses"})
    if not changed:
        um.module.exit_json(changed=False, network=current, diff=diff)
    if check:
        merged = {**current, **body}
        um.module.exit_json(changed=True, network=merged, diff=diff)
    updated = um.client.put(f"{net_path}/{current['id']}", body=body)
    um.module.exit_json(changed=True, network=updated, diff=diff)


def run(um):
    """Dispatch to the present/absent handler for the resolved network."""
    params = um.module.params
    net_path = f"/v1/sites/{um.site_id}/networks"
    current = find_current(um, net_path, params.get("id"), params["name"])
    if params["state"] == "absent":
        _absent(um, net_path, current)
    else:
        _present(um, net_path, current)


def main():
    """Module entry point."""
    spec = unifi_argument_spec()
    spec.update(
        name={"type": "str", "required": True},
        id={"type": "str"},
        management={"type": "str", "choices": ["GATEWAY", "UNMANAGED"]},
        enabled={"type": "bool", "default": True},
        vlan_id={"type": "int"},
        zone_id={"type": "str"},
        dhcp_guarding={"type": "dict", "options": {
            "trusted_dhcp_server_ip_addresses": {
                "type": "list", "elements": "str", "default": []}}},
        state={"type": "str", "choices": ["present", "absent"],
               "default": "present"},
        force={"type": "bool", "default": False},
    )
    module = AnsibleModule(
        argument_spec=spec,
        supports_check_mode=True,
        required_if=[["state", "present", ["management", "vlan_id"]]],
    )
    um = UniFiModule(module)
    try:
        run(um)
    except UniFiError as exc:
        um.handle(exc)


if __name__ == "__main__":
    main()
