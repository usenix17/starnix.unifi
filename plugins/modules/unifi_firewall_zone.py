# -*- coding: utf-8 -*-
# Copyright: (c) 2026, Sasha Karcz <sasha@starnix.net>
# GPL-3.0-or-later (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
"""Manage UniFi firewall zones."""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.starnix.unifi.plugins.module_utils.unifi import (
    UniFiError,
    UniFiModule,
    needs_update,
    unifi_argument_spec,
)

DOCUMENTATION = r"""
module: unifi_firewall_zone
short_description: Manage UniFi firewall zones
version_added: "0.1.0"
description:
  - Create, update, and delete UniFi firewall zones and the set of networks
    assigned to them, via the official Integration API
    (C(/v1/sites/{site}/firewall/zones)).
  - Modifying or deleting a built-in (non-configurable) zone is rejected by the
    controller; the API error is surfaced.
author:
  - Sasha Karcz (@usenix17)
extends_documentation_fragment:
  - starnix.unifi.auth
options:
  name:
    description:
      - Zone name. Used as the lookup key when O(id) is not given.
    type: str
    required: true
  id:
    description:
      - UUID of an existing zone. Authoritative lookup; takes precedence over
        O(name).
    type: str
  network_ids:
    description:
      - UUIDs of the networks assigned to the zone; maps to C(networkIds).
      - Names are not resolved; pass network UUIDs. Omit or pass an empty
        list for a zone with no networks. Compared as an unordered set.
    type: list
    elements: str
  state:
    description:
      - Whether the zone should exist.
    type: str
    choices: [present, absent]
    default: present
"""

EXAMPLES = r"""
- name: Ensure an Aux zone exists with two networks
  starnix.unifi.unifi_firewall_zone:
    host: heimdal.starnix.net
    api_key: "{{ lookup('env', 'UNIFI_API_KEY') }}"
    name: Aux
    network_ids:
      - 7f6409fa-8689-4e65-8e66-cd1787c4de78
    state: present

- name: Remove a custom zone
  starnix.unifi.unifi_firewall_zone:
    host: heimdal.starnix.net
    api_key: "{{ lookup('env', 'UNIFI_API_KEY') }}"
    name: Aux
    state: absent
"""

RETURN = r"""
firewall_zone:
  description: The zone after the operation; an empty dict when absent.
  type: dict
  returned: success
  sample:
    id: "d6f5022b-774b-4fc0-a17c-66f88c6943cd"
    name: "Aux"
    networkIds: ["7f6409fa-8689-4e65-8e66-cd1787c4de78"]
    metadata: { origin: "USER_DEFINED" }
"""


def find_current(um, zone_path, zone_id, name):
    """Return the live zone by UUID (authoritative) or by name, else None."""
    if zone_id:
        try:
            return um.client.get(f"{zone_path}/{zone_id}")
        except UniFiError as exc:
            if exc.status == 404:
                return None
            raise
    matches = [z for z in um.client.paginate(zone_path)
               if z.get("name") == name]
    if len(matches) > 1:
        um.fail(f"found {len(matches)} zones named {name!r}; "
                "disambiguate with 'id'.")
    return matches[0] if matches else None


def _absent(um, zone_path, current):
    """Ensure the zone does not exist."""
    if not current:
        um.module.exit_json(changed=False, firewall_zone={})
    diff = {"before": current, "after": {}}
    if not um.module.check_mode:
        um.client.delete(f"{zone_path}/{current['id']}")
    um.module.exit_json(changed=True, firewall_zone={}, diff=diff)


def _present(um, zone_path, current):
    """Ensure the zone exists with the declared network set."""
    params = um.module.params
    check = um.module.check_mode
    body = {"name": params["name"], "networkIds": params["network_ids"] or []}

    if current is None:
        diff = {"before": {}, "after": body}
        result = body if check else um.client.post(zone_path, body=body)
        um.module.exit_json(changed=True, firewall_zone=result, diff=diff)

    changed, diff = needs_update(body, current, set_keys={"networkIds"})
    if not changed:
        um.module.exit_json(changed=False, firewall_zone=current, diff=diff)
    if check:
        merged = {**current, **body}
        um.module.exit_json(changed=True, firewall_zone=merged, diff=diff)
    updated = um.client.put(f"{zone_path}/{current['id']}", body=body)
    um.module.exit_json(changed=True, firewall_zone=updated, diff=diff)


def run(um):
    """Dispatch to the present/absent handler for the resolved zone."""
    params = um.module.params
    zone_path = f"/v1/sites/{um.site_id}/firewall/zones"
    current = find_current(um, zone_path, params.get("id"), params["name"])
    if params["state"] == "absent":
        _absent(um, zone_path, current)
    else:
        _present(um, zone_path, current)


def main():
    """Module entry point."""
    spec = unifi_argument_spec()
    spec.update(
        name={"type": "str", "required": True},
        id={"type": "str"},
        network_ids={"type": "list", "elements": "str"},
        state={"type": "str", "choices": ["present", "absent"],
               "default": "present"},
    )
    module = AnsibleModule(argument_spec=spec, supports_check_mode=True)
    um = UniFiModule(module)
    try:
        run(um)
    except UniFiError as exc:
        um.handle(exc)


if __name__ == "__main__":
    main()
