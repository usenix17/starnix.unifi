# -*- coding: utf-8 -*-
# Copyright: (c) 2026, Sasha Karcz <sasha@starnix.net>
# GPL-3.0-or-later (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
"""Manage UniFi zone-based firewall policies."""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.starnix.unifi.plugins.module_utils.unifi import (
    UniFiError,
    UniFiModule,
    needs_update,
    prune,
    unifi_argument_spec,
)

DOCUMENTATION = r"""
module: unifi_firewall_policy
short_description: Manage UniFi zone-based firewall policies
version_added: "0.1.0"
description:
  - Create, update, and delete policies of the UniFi zone-based (Policy Engine)
    firewall, via the official Integration API
    (C(/v1/sites/{site}/firewall/policies)).
  - Only user-defined policies are managed. Policies the controller reports as
    C(DERIVED) or C(SYSTEM_DEFINED) are never modified; targeting one by O(id)
    fails.
  - Updates use a full replace (PUT), so O(state=present) requires the complete
    policy body every run, exactly as the API does.
  - The nested objects O(action), O(source), O(destination),
    O(ip_protocol_scope), and O(schedule) are opaque and passed through
    unchanged; their schema is not published in the UniFi API export. Obtain a
    working shape by inspecting an existing policy.
notes:
  - Policy evaluation order is not managed here; use
    M(starnix.unifi.unifi_firewall_policy_order).
author:
  - Sasha Karcz (@usenix17)
extends_documentation_fragment:
  - starnix.unifi.auth
options:
  name:
    description:
      - Policy name. Used as the lookup key when O(id) is not given.
    type: str
    required: true
  id:
    description:
      - UUID of an existing policy. Authoritative lookup; takes precedence over
        O(name).
    type: str
  enabled:
    description:
      - Whether the policy is enabled.
    type: bool
    default: true
  description:
    description:
      - Free-form description stored on the policy.
    type: str
  action:
    description:
      - The policy action, sent verbatim. Required when O(state=present).
      - Schema is not documented by the export; e.g. V({type: ALLOW,
        allowReturnTraffic: false}) or V({type: BLOCK}).
    type: dict
  source:
    description:
      - The source match, sent verbatim: a dict with C(zoneId) and an optional
        C(trafficFilter). Required when O(state=present).
      - Zone names are not resolved; pass the zone UUID. Obtain a working
        C(trafficFilter) shape from an existing policy.
    type: dict
  destination:
    description:
      - The destination match, sent verbatim, same shape as O(source). Required
        when O(state=present).
    type: dict
  ip_protocol_scope:
    description:
      - Maps to C(ipProtocolScope), sent verbatim, e.g. V({ipVersion: IPV4}) or
        V({ipVersion: IPV4_AND_IPV6}). Required when O(state=present).
    type: dict
  connection_state_filter:
    description:
      - Maps to C(connectionStateFilter). Omit to match all states. Compared as
        an unordered set.
    type: list
    elements: str
    choices: [NEW, INVALID, ESTABLISHED, RELATED]
  ipsec_filter:
    description:
      - Maps to C(ipsecFilter). Omit to match both encrypted and unencrypted.
    type: str
    choices: [MATCH_ENCRYPTED, MATCH_NOT_ENCRYPTED]
  logging_enabled:
    description:
      - Maps to C(loggingEnabled); whether matches are logged.
    type: bool
    default: false
  schedule:
    description:
      - Maps to C(schedule), sent verbatim. Omit for an always-active policy.
    type: dict
  state:
    description:
      - Whether the policy should exist.
    type: str
    choices: [present, absent]
    default: present
"""

EXAMPLES = r"""
- name: Allow the Restricted zone to reach internal DNS
  starnix.unifi.unifi_firewall_policy:
    host: heimdal.starnix.net
    api_key: "{{ lookup('env', 'UNIFI_API_KEY') }}"
    name: Allow Restricted to internal DNS
    enabled: true
    action: { type: ALLOW, allowReturnTraffic: false }
    source:
      zoneId: 6a1cae38-c2f1-7820-30b3-5fca00000000
    destination:
      zoneId: 08803f57-0793-4f45-9239-7f74fc1f0ce5
      trafficFilter:
        type: PORT
        portFilter: { type: PORTS, ports: [53] }
    ip_protocol_scope: { ipVersion: IPV4_AND_IPV6 }
    state: present

- name: Remove a policy by UUID
  starnix.unifi.unifi_firewall_policy:
    host: heimdal.starnix.net
    api_key: "{{ lookup('env', 'UNIFI_API_KEY') }}"
    name: Allow Restricted to internal DNS
    id: 16e826be-d79d-47bb-929c-bf25cce629cc
    state: absent
"""

RETURN = r"""
firewall_policy:
  description: The policy after the operation; an empty dict when absent.
  type: dict
  returned: success
  sample:
    id: "16e826be-d79d-47bb-929c-bf25cce629cc"
    name: "Allow Restricted to internal DNS"
    enabled: true
    action: { type: "ALLOW", allowReturnTraffic: false }
    metadata: { origin: "USER_DEFINED" }
"""

_REQUIRED_ON_PRESENT = ("action", "source", "destination", "ip_protocol_scope")


def find_current(um, pol_path, policy_id, name):
    """Return the live policy by UUID, or by name among USER_DEFINED ones."""
    if policy_id:
        try:
            return um.client.get(f"{pol_path}/{policy_id}")
        except UniFiError as exc:
            if exc.status == 404:
                return None
            raise
    matches = [
        p for p in um.client.paginate(pol_path)
        if p.get("name") == name
        and (p.get("metadata") or {}).get("origin") == "USER_DEFINED"
    ]
    if len(matches) > 1:
        um.fail(f"found {len(matches)} user-defined policies named {name!r}; "
                "disambiguate with 'id'.")
    return matches[0] if matches else None


def _build_body(params):
    """Map user params to the API body, dropping unset (None) fields."""
    return prune({
        "enabled": params["enabled"],
        "name": params["name"],
        "description": params.get("description"),
        "action": params.get("action"),
        "source": params.get("source"),
        "destination": params.get("destination"),
        "ipProtocolScope": params.get("ip_protocol_scope"),
        "connectionStateFilter": params.get("connection_state_filter"),
        "ipsecFilter": params.get("ipsec_filter"),
        "loggingEnabled": params["logging_enabled"],
        "schedule": params.get("schedule"),
    })


def _absent(um, pol_path, current):
    """Ensure the policy does not exist."""
    if not current:
        um.module.exit_json(changed=False, firewall_policy={})
    diff = {"before": current, "after": {}}
    if not um.module.check_mode:
        um.client.delete(f"{pol_path}/{current['id']}")
    um.module.exit_json(changed=True, firewall_policy={}, diff=diff)


def _present(um, pol_path, current):
    """Ensure the policy exists and matches the declared spec."""
    body = _build_body(um.module.params)
    check = um.module.check_mode

    if current is None:
        diff = {"before": {}, "after": body}
        result = body if check else um.client.post(pol_path, body=body)
        um.module.exit_json(changed=True, firewall_policy=result, diff=diff)

    changed, diff = needs_update(body, current,
                                 set_keys={"connectionStateFilter"})
    if not changed:
        um.module.exit_json(changed=False, firewall_policy=current, diff=diff)
    if check:
        merged = {**current, **body}
        um.module.exit_json(changed=True, firewall_policy=merged, diff=diff)
    updated = um.client.put(f"{pol_path}/{current['id']}", body=body)
    um.module.exit_json(changed=True, firewall_policy=updated, diff=diff)


def run(um):
    """Dispatch to the present/absent handler for the resolved policy."""
    params = um.module.params
    pol_path = f"/v1/sites/{um.site_id}/firewall/policies"
    current = find_current(um, pol_path, params.get("id"), params["name"])
    if current:
        origin = (current.get("metadata") or {}).get("origin")
        if origin != "USER_DEFINED":
            um.fail(f"policy {current['id']} has origin {origin!r} and is not "
                    "user-managed; refusing to modify it.")
    if params["state"] == "absent":
        _absent(um, pol_path, current)
    else:
        _present(um, pol_path, current)


def main():
    """Module entry point."""
    spec = unifi_argument_spec()
    spec.update(
        name={"type": "str", "required": True},
        id={"type": "str"},
        enabled={"type": "bool", "default": True},
        description={"type": "str"},
        action={"type": "dict"},
        source={"type": "dict"},
        destination={"type": "dict"},
        ip_protocol_scope={"type": "dict"},
        connection_state_filter={
            "type": "list", "elements": "str",
            "choices": ["NEW", "INVALID", "ESTABLISHED", "RELATED"]},
        ipsec_filter={"type": "str",
                      "choices": ["MATCH_ENCRYPTED", "MATCH_NOT_ENCRYPTED"]},
        logging_enabled={"type": "bool", "default": False},
        schedule={"type": "dict"},
        state={"type": "str", "choices": ["present", "absent"],
               "default": "present"},
    )
    module = AnsibleModule(
        argument_spec=spec,
        supports_check_mode=True,
        required_if=[["state", "present", list(_REQUIRED_ON_PRESENT)]],
    )
    um = UniFiModule(module)
    try:
        run(um)
    except UniFiError as exc:
        um.handle(exc)


if __name__ == "__main__":
    main()
