# -*- coding: utf-8 -*-
# Copyright: (c) 2026, Sasha Karcz <sasha@starnix.net>
# GNU General Public License v3.0+ (see LICENSE or gnu.org/licenses/gpl-3.0)
# SPDX-License-Identifier: GPL-3.0-or-later
"""Manage a UniFi network's DHCP-advertised DNS servers (classic API)."""

DOCUMENTATION = r"""
module: unifi_network_dhcp
short_description: Set a UniFi network's DHCP-advertised DNS servers
version_added: "0.1.0"
description:
  - Sets the DNS servers a UniFi network hands out over DHCP, idempotently.
  - "Note: the official v1 Integration API does not expose DHCP or DNS fields,
    so this module uses the controller's classic (legacy) API endpoint
    C(/proxy/network/api/s/{site}/rest/networkconf). It is the durable,
    as-code fix for DHCP-DNS drift (for example an Aux VLAN reverting to the
    wrong resolvers after a controller restore)."
  - Unlike the other modules in this collection, O(site) is the classic site
    B(name) (e.g. V(default)), not the v1 site UUID.
author:
  - Sasha Karcz (@usenix17)
options:
  host:
    description: Hostname or IP address of the UniFi controller.
    type: str
    required: true
  port:
    description: TCP port of the controller's HTTPS interface.
    type: int
    default: 443
  api_key:
    description:
      - UniFi API key, sent as the C(X-API-KEY) header. May be supplied via the
        E(UNIFI_API_KEY) environment variable.
    type: str
    required: true
  validate_certs:
    description: Whether to validate the controller's TLS certificate.
    type: bool
    default: true
  ca_path:
    description: Path to a CA bundle for a private-CA controller certificate.
    type: path
  timeout:
    description: Per-request timeout in seconds.
    type: int
    default: 30
  site:
    description:
      - The classic site B(name) (not the v1 UUID), as used by the legacy API.
    type: str
    default: default
  name:
    description:
      - Name of the network (as shown in the controller) whose DHCP DNS to set.
    type: str
    required: true
  dns_servers:
    description:
      - Up to four DHCP-advertised DNS servers, in priority order.
      - An empty list disables custom DNS, reverting the network to the
        controller default. Order is significant.
    type: list
    elements: str
    default: []
"""

EXAMPLES = r"""
- name: Pin the Aux VLAN to the internal resolvers
  starnix.unifi.unifi_network_dhcp:
    host: heimdal.starnix.net
    api_key: "{{ lookup('env', 'UNIFI_API_KEY') }}"
    name: Aux
    dns_servers:
      - 192.168.1.53
      - 10.17.89.53
"""

RETURN = r"""
network_dhcp:
  description: The resulting DHCP-DNS configuration for the network.
  type: dict
  returned: success
  sample:
    name: "Aux"
    dhcpd_dns_enabled: true
    dns_servers: ["192.168.1.53", "10.17.89.53"]
"""

# Imports follow the documentation variables, as required by ansible-test
# validate-modules.
from ansible.module_utils.basic import AnsibleModule, env_fallback
from ansible_collections.starnix.unifi.plugins.module_utils.unifi import (
    UniFiClient,
    UniFiError,
)


_DNS_KEYS = ("dhcpd_dns_1", "dhcpd_dns_2", "dhcpd_dns_3", "dhcpd_dns_4")


def current_dns(net):
    """Return the network's DHCP DNS servers in order, skipping blanks."""
    return [net[k] for k in _DNS_KEYS if net.get(k)]


def plan(net, servers):
    """Return ``(changed, put_body_or_None)`` for the desired DNS servers.

    The classic API replaces the whole network object on PUT, so the body is
    the current object with only the DHCP-DNS fields adjusted; unused
    ``dhcpd_dns_N`` keys are removed.
    """
    changed = (current_dns(net) != servers
               or bool(net.get("dhcpd_dns_enabled")) != bool(servers))
    if not changed:
        return False, None
    body = dict(net)
    body["dhcpd_dns_enabled"] = bool(servers)
    for i, key in enumerate(_DNS_KEYS):
        if i < len(servers):
            body[key] = servers[i]
        else:
            body.pop(key, None)
    return True, body


def run(module):
    """Ensure the named network advertises the declared DNS servers."""
    params = module.params
    servers = params["dns_servers"]
    if len(servers) > 4:
        module.fail_json(msg="dns_servers accepts at most four addresses.")
    client = UniFiClient(
        host=params["host"], port=params["port"], api_key=params["api_key"],
        validate_certs=params["validate_certs"], ca_path=params.get("ca_path"),
        timeout=params["timeout"], api_base_path="/proxy/network")
    base = f"/api/s/{params['site']}/rest/networkconf"
    try:
        nets = client.get(base).get("data", []) or []
        matches = [n for n in nets if n.get("name") == params["name"]]
        if not matches:
            module.fail_json(
                msg=f"no network named {params['name']!r} on site "
                    f"{params['site']!r}.")
        if len(matches) > 1:
            module.fail_json(
                msg=f"multiple networks named {params['name']!r}; names must "
                    "be unique.")
        net = matches[0]
        changed, body = plan(net, servers)
        result = {"name": params["name"], "dhcpd_dns_enabled": bool(servers),
                  "dns_servers": servers}
        diff = {
            "before": {"dhcpd_dns_enabled": bool(net.get("dhcpd_dns_enabled")),
                       "dns_servers": current_dns(net)},
            "after": {"dhcpd_dns_enabled": bool(servers),
                      "dns_servers": servers},
        }
        if changed and not module.check_mode:
            client.put(f"{base}/{net['_id']}", body=body)
        module.exit_json(changed=changed, network_dhcp=result, diff=diff)
    except UniFiError as exc:
        module.fail_json(msg=str(exc), unifi_status=exc.status,
                         unifi_error=exc.envelope)


def main():
    """Module entry point."""
    module = AnsibleModule(
        argument_spec={
            "host": {"type": "str", "required": True},
            "port": {"type": "int", "default": 443},
            "api_key": {"type": "str", "required": True, "no_log": True,
                        "fallback": (env_fallback, ["UNIFI_API_KEY"])},
            "validate_certs": {"type": "bool", "default": True},
            "ca_path": {"type": "path"},
            "timeout": {"type": "int", "default": 30},
            "site": {"type": "str", "default": "default"},
            "name": {"type": "str", "required": True},
            "dns_servers": {"type": "list", "elements": "str", "default": []},
        },
        supports_check_mode=True,
    )
    run(module)


if __name__ == "__main__":
    main()
