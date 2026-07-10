# -*- coding: utf-8 -*-
# Copyright: (c) 2026, Sasha Karcz <sasha@starnix.net>
# GNU General Public License v3.0+ (see LICENSE or gnu.org/licenses/gpl-3.0)
# SPDX-License-Identifier: GPL-3.0-or-later
"""Manage UniFi firewall policy evaluation order for a zone pair."""

DOCUMENTATION = r"""
module: unifi_firewall_policy_order
short_description: Set UniFi firewall policy evaluation order for a zone pair
version_added: "0.1.0"
description:
  - Declaratively sets the evaluation order of user-defined firewall policies
    for one directed source/destination zone pair, via the ordering endpoint
    (C(/v1/sites/{site}/firewall/policies/ordering)).
  - User policies are ordered in two buckets around the immutable
    system-defined policies -- O(before_system_defined) and
    O(after_system_defined). List order is evaluation order.
  - This is a strict full replacement for the pair. The lists you pass ARE the
    complete desired order; any user policy for the pair that you omit is
    dropped from the ordering. To keep a policy, list it.
author:
  - Sasha Karcz (@usenix17)
extends_documentation_fragment:
  - starnix.unifi.auth
options:
  source_zone_id:
    description:
      - UUID of the source zone (maps to the C(sourceFirewallZoneId) query
        parameter).
    type: str
    required: true
  destination_zone_id:
    description:
      - UUID of the destination zone (maps to C(destinationFirewallZoneId)).
    type: str
    required: true
  before_system_defined:
    description:
      - Ordered policy UUIDs evaluated before the system-defined policies.
        Omit or pass an empty list to clear this bucket.
    type: list
    elements: str
  after_system_defined:
    description:
      - Ordered policy UUIDs evaluated after the system-defined policies.
        Omit or pass an empty list to clear this bucket.
    type: list
    elements: str
  state:
    description:
      - Only V(present) is supported. There is no delete operation for
        ordering; clear a bucket by passing an empty list.
    type: str
    choices: [present, absent]
    default: present
"""

EXAMPLES = r"""
- name: Order Internal-to-Internal policies (Roblox block first)
  starnix.unifi.unifi_firewall_policy_order:
    host: heimdal.starnix.net
    api_key: "{{ lookup('env', 'UNIFI_API_KEY') }}"
    source_zone_id: 08803f57-0793-4f45-9239-7f74fc1f0ce5
    destination_zone_id: 08803f57-0793-4f45-9239-7f74fc1f0ce5
    before_system_defined:
      - "{{ roblox.firewall_policy.id }}"
      - "{{ allow_all.firewall_policy.id }}"
"""

RETURN = r"""
ordering:
  description: The resulting ordering for the zone pair.
  type: dict
  returned: success
  sample:
    source_zone_id: "08803f57-0793-4f45-9239-7f74fc1f0ce5"
    destination_zone_id: "08803f57-0793-4f45-9239-7f74fc1f0ce5"
    orderedFirewallPolicyIds:
      beforeSystemDefined: ["16e826be-d79d-47bb-929c-bf25cce629cc"]
      afterSystemDefined: []
"""

# Imports follow the documentation variables, as required by ansible-test
# validate-modules.
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.starnix.unifi.plugins.module_utils.unifi import (
    UniFiError,
    UniFiModule,
    unifi_argument_spec,
)


def _norm(ordered):
    """Normalize an orderedFirewallPolicyIds dict for compare/diff."""
    ordered = ordered or {}
    return {
        "beforeSystemDefined": ordered.get("beforeSystemDefined") or [],
        "afterSystemDefined": ordered.get("afterSystemDefined") or [],
    }


def _result(params, ordered):
    """Shape the returned ordering object for a zone pair."""
    return {
        "source_zone_id": params["source_zone_id"],
        "destination_zone_id": params["destination_zone_id"],
        "orderedFirewallPolicyIds": ordered,
    }


def run(um):
    """Enforce the declared ordering for the zone pair."""
    params = um.module.params
    if params["state"] == "absent":
        um.fail("state=absent is not supported for ordering; clear a bucket "
                "by passing an empty list instead.")
    path = f"/v1/sites/{um.site_id}/firewall/policies/ordering"
    query = {"sourceFirewallZoneId": params["source_zone_id"],
             "destinationFirewallZoneId": params["destination_zone_id"]}
    desired = {
        "beforeSystemDefined": params["before_system_defined"] or [],
        "afterSystemDefined": params["after_system_defined"] or [],
    }
    current = _norm(um.client.get(path, query=query)
                    .get("orderedFirewallPolicyIds"))
    diff = {"before": current, "after": desired}

    if current == desired:
        um.module.exit_json(changed=False,
                            ordering=_result(params, current), diff=diff)
    if um.module.check_mode:
        um.module.exit_json(changed=True,
                            ordering=_result(params, desired), diff=diff)
    resp = um.client.put(path, body={"orderedFirewallPolicyIds": desired},
                         query=query)
    ordered = resp.get("orderedFirewallPolicyIds", desired)
    um.module.exit_json(changed=True, ordering=_result(params, ordered),
                        diff=diff)


def main():
    """Module entry point."""
    spec = unifi_argument_spec()
    spec.update(
        source_zone_id={"type": "str", "required": True},
        destination_zone_id={"type": "str", "required": True},
        before_system_defined={"type": "list", "elements": "str"},
        after_system_defined={"type": "list", "elements": "str"},
        state={"type": "str", "choices": ["present", "absent"],
               "default": "present"},
    )
    module = AnsibleModule(
        argument_spec=spec,
        supports_check_mode=True,
        required_one_of=[["before_system_defined", "after_system_defined"]],
    )
    um = UniFiModule(module)
    try:
        run(um)
    except UniFiError as exc:
        um.handle(exc)


if __name__ == "__main__":
    main()
