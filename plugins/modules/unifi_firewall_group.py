# -*- coding: utf-8 -*-
# Copyright: (c) 2026, Sasha Karcz <sasha@starnix.net>
# GPL-3.0-or-later (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
"""Manage UniFi traffic-matching lists (address/port groups)."""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.starnix.unifi.plugins.module_utils.unifi import (
    UniFiError,
    UniFiModule,
    needs_update,
    unifi_argument_spec,
)

DOCUMENTATION = r"""
module: unifi_firewall_group
short_description: Manage UniFi traffic-matching lists (address/port groups)
version_added: "0.1.0"
description:
  - Create, update, and delete UniFi traffic-matching lists -- the reusable
    address and port groups referenced by firewall policies -- via the official
    Integration API (C(/v1/sites/{site}/traffic-matching-lists)).
author:
  - Sasha Karcz (@usenix17)
extends_documentation_fragment:
  - starnix.unifi.auth
options:
  name:
    description:
      - Name of the list. Used as the lookup key when O(id) is not given.
    type: str
    required: true
  id:
    description:
      - UUID of an existing list. Authoritative lookup; takes precedence over
        O(name).
    type: str
  type:
    description:
      - The list discriminator. Required when O(state=present).
      - Newer controllers may accept further values; those would be added as
        choices in a later release.
    type: str
    choices:
      - IPV4_ADDRESSES
      - IPV6_ADDRESSES
      - PORTS
  items:
    description:
      - The list members, sent to the API verbatim. Each element is a dict with
        C(type) and C(value) keys, e.g. V({type: IP_ADDRESS, value:
        192.168.1.10}), V({type: SUBNET, value: 10.0.0.0/8}), or V({type:
        PORT_NUMBER, value: 443}).
      - Required and must be non-empty when O(state=present). Comparison is
        order-sensitive.
    type: list
    elements: dict
  recreate:
    description:
      - Permit changing an existing list's O(type) by deleting and recreating
        it. Without this, a type change fails, since flipping the discriminator
        via an update is rejected by the API.
    type: bool
    default: false
  state:
    description:
      - Whether the list should exist.
    type: str
    choices: [present, absent]
    default: present
"""

EXAMPLES = r"""
- name: Ensure the internal-DNS address list exists
  starnix.unifi.unifi_firewall_group:
    host: heimdal.starnix.net
    api_key: "{{ lookup('env', 'UNIFI_API_KEY') }}"
    name: internal-dns
    type: IPV4_ADDRESSES
    items:
      - { type: IP_ADDRESS, value: 192.168.1.53 }
      - { type: IP_ADDRESS, value: 10.17.89.53 }
    state: present

- name: Remove a list by UUID
  starnix.unifi.unifi_firewall_group:
    host: heimdal.starnix.net
    api_key: "{{ lookup('env', 'UNIFI_API_KEY') }}"
    name: internal-dns
    id: 860509ec-a8ad-4631-9699-dcb242e98879
    state: absent
"""

RETURN = r"""
firewall_group:
  description: The list after the operation; an empty dict when absent.
  type: dict
  returned: success
  sample:
    id: "860509ec-a8ad-4631-9699-dcb242e98879"
    type: "IPV4_ADDRESSES"
    name: "internal-dns"
    items:
      - { type: "IP_ADDRESS", value: "192.168.1.53" }
"""


def find_current(um, list_path, group_id, name):
    """Return the live list by UUID (authoritative) or by name, else None."""
    if group_id:
        try:
            return um.client.get(f"{list_path}/{group_id}")
        except UniFiError as exc:
            if exc.status == 404:
                return None
            raise
    matches = [g for g in um.client.paginate(list_path)
               if g.get("name") == name]
    if len(matches) > 1:
        um.fail(f"found {len(matches)} traffic-matching-lists named "
                f"{name!r}; disambiguate with 'id'.")
    return matches[0] if matches else None


def _absent(um, list_path, current):
    """Ensure the list does not exist."""
    if not current:
        um.module.exit_json(changed=False, firewall_group={})
    diff = {"before": current, "after": {}}
    if not um.module.check_mode:
        um.client.delete(f"{list_path}/{current['id']}")
    um.module.exit_json(changed=True, firewall_group={}, diff=diff)


def _present(um, list_path, current):
    """Ensure the list exists and matches the declared spec."""
    params = um.module.params
    check = um.module.check_mode
    if not params["items"]:
        um.fail("items must be non-empty when state=present.")
    desired = {"type": params["type"], "name": params["name"],
               "items": params["items"]}

    if current is None:
        diff = {"before": {}, "after": desired}
        result = desired if check else um.client.post(list_path, body=desired)
        um.module.exit_json(changed=True, firewall_group=result, diff=diff)

    if current.get("type") != params["type"]:
        if not params["recreate"]:
            um.fail(f"existing list {current['id']} has type "
                    f"{current.get('type')!r}; changing to {params['type']!r} "
                    "requires recreate=true.")
        diff = {"before": current, "after": desired}
        if not check:
            um.client.delete(f"{list_path}/{current['id']}")
            desired = um.client.post(list_path, body=desired)
        um.module.exit_json(changed=True, firewall_group=desired, diff=diff)

    changed, diff = needs_update(desired, current)
    if not changed:
        um.module.exit_json(changed=False, firewall_group=current, diff=diff)
    if check:
        merged = {**current, **desired}
        um.module.exit_json(changed=True, firewall_group=merged, diff=diff)
    updated = um.client.put(f"{list_path}/{current['id']}", body=desired)
    um.module.exit_json(changed=True, firewall_group=updated, diff=diff)


def run(um):
    """Dispatch to the present/absent handler for the resolved list."""
    params = um.module.params
    list_path = f"/v1/sites/{um.site_id}/traffic-matching-lists"
    current = find_current(um, list_path, params.get("id"), params["name"])
    if params["state"] == "absent":
        _absent(um, list_path, current)
    else:
        _present(um, list_path, current)


def main():
    """Module entry point."""
    spec = unifi_argument_spec()
    spec.update(
        name={"type": "str", "required": True},
        id={"type": "str"},
        type={"type": "str",
              "choices": ["IPV4_ADDRESSES", "IPV6_ADDRESSES", "PORTS"]},
        items={"type": "list", "elements": "dict"},
        recreate={"type": "bool", "default": False},
        state={"type": "str", "choices": ["present", "absent"],
               "default": "present"},
    )
    module = AnsibleModule(
        argument_spec=spec,
        supports_check_mode=True,
        required_if=[["state", "present", ["type", "items"]]],
    )
    um = UniFiModule(module)
    try:
        run(um)
    except UniFiError as exc:
        um.handle(exc)


if __name__ == "__main__":
    main()
