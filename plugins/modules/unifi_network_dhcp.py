# -*- coding: utf-8 -*-
# Copyright: (c) 2026, Sasha Karcz <sasha@starnix.net>
# GNU General Public License v3.0+ (see LICENSE or gnu.org/licenses/gpl-3.0)
# SPDX-License-Identifier: GPL-3.0-or-later
"""Manage a UniFi network's DHCP options (classic API)."""

DOCUMENTATION = r"""
module: unifi_network_dhcp
short_description: Manage a UniFi network's DHCP options (DNS, NTP, boot, ...)
version_added: "0.1.0"
description:
  - Idempotently manages a UniFi network's DHCP options -- DNS, NTP, WINS,
    network boot (PXE), lease time, and more.
  - "Note: the official v1 Integration API exposes no DHCP fields, so this
    module uses the controller's classic (legacy) API endpoint
    C(/proxy/network/api/s/{site}/rest/networkconf). It is the durable,
    as-code fix for DHCP option drift (for example an Aux VLAN reverting to the
    wrong resolvers after a controller restore)."
  - This module B(patches) the network; it changes only the options you specify
    and leaves every other network setting untouched. Unlike the other modules
    in this collection, O(site) is the classic site B(name) (e.g. V(default)),
    not the v1 site UUID.
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
      - Name of the network (as shown in the controller) to configure.
    type: str
    required: true
  dns_servers:
    description:
      - Up to four DHCP-advertised DNS servers, in priority order. An empty
        list disables custom DNS. Omit to leave the DNS setting unchanged.
    type: list
    elements: str
  ntp_servers:
    description:
      - Up to two DHCP-advertised NTP servers. An empty list disables custom
        NTP. Omit to leave it unchanged.
    type: list
    elements: str
  wins_servers:
    description:
      - Up to two WINS servers. An empty list disables WINS. Omit to leave it
        unchanged.
    type: list
    elements: str
  lease_time:
    description:
      - DHCP lease time in seconds (maps to C(dhcpd_leasetime)).
    type: int
  tftp_server:
    description:
      - TFTP server address handed out via DHCP (maps to C(dhcpd_tftp_server)).
    type: str
  wpad_url:
    description:
      - WPAD proxy auto-config URL (maps to C(dhcpd_wpad_url)).
    type: str
  unifi_controller:
    description:
      - UniFi controller address advertised via DHCP option 43 (maps to
        C(dhcpd_unifi_controller)).
    type: str
  boot:
    description:
      - Network boot / PXE options. Omit to leave boot settings unchanged; each
        sub-option is applied only when set.
    type: dict
    suboptions:
      enabled:
        description: Whether network boot is enabled (C(dhcpd_boot_enabled)).
        type: bool
      server:
        description: Boot server (next-server) address (C(dhcpd_boot_server)).
        type: str
      filename:
        description: Boot file name (C(dhcpd_boot_filename)).
        type: str
  options:
    description:
      - Escape hatch for any other classic DHCP fields, given as raw
        C(dhcpd_*) key/value pairs and sent verbatim (for example
        C(dhcpd_conflict_checking) or C(dhcpd_gateway_enabled)). Use for
        options this module does not model explicitly.
    type: dict
"""

EXAMPLES = r"""
- name: Pin Aux DNS and hand out NTP + a PXE boot file
  starnix.unifi.unifi_network_dhcp:
    host: heimdal.starnix.net
    api_key: "{{ lookup('env', 'UNIFI_API_KEY') }}"
    name: Aux
    dns_servers:
      - 192.168.1.53
      - 10.17.89.53
    ntp_servers:
      - 192.168.1.1
    lease_time: 86400
    boot:
      enabled: true
      server: 192.168.1.10
      filename: pxelinux.0
"""

RETURN = r"""
network_dhcp:
  description: The network name and the DHCP fields this run manages.
  type: dict
  returned: success
  sample:
    name: "Aux"
    dhcp_options:
      dhcpd_dns_enabled: true
      dhcpd_dns_1: "192.168.1.53"
      dhcpd_dns_2: "10.17.89.53"
"""

# Imports follow the documentation variables, as required by ansible-test
# validate-modules.
from ansible.module_utils.basic import AnsibleModule, env_fallback
from ansible_collections.starnix.unifi.plugins.module_utils.unifi import (
    UniFiClient,
    UniFiError,
)


# param name -> (classic field prefix, number of numbered slots)
_SLOTS = {"dns": ("dhcpd_dns", 4), "ntp": ("dhcpd_ntp", 2),
          "wins": ("dhcpd_wins", 2)}
# scalar param name -> classic field
_SCALARS = {"lease_time": "dhcpd_leasetime",
            "tftp_server": "dhcpd_tftp_server",
            "wpad_url": "dhcpd_wpad_url",
            "unifi_controller": "dhcpd_unifi_controller"}
# boot sub-option -> classic field
_BOOT = {"enabled": "dhcpd_boot_enabled", "server": "dhcpd_boot_server",
         "filename": "dhcpd_boot_filename"}


def _slot_fields(prefix, servers, count):
    """Return the enabled flag and numbered slot fields for a server list."""
    fields = {f"{prefix}_enabled": bool(servers)}
    for i in range(1, count + 1):
        fields[f"{prefix}_{i}"] = servers[i - 1] if i <= len(servers) else ""
    return fields


def _norm(value):
    """Treat None and empty string as equal when comparing string fields."""
    return "" if value is None else value


def desired_fields(params):
    """Map the set parameters to their classic C(dhcpd_*) fields."""
    fields = {}
    for key, (prefix, count) in _SLOTS.items():
        servers = params[f"{key}_servers"]
        if servers is not None:
            fields.update(_slot_fields(prefix, servers, count))
    for param, field in _SCALARS.items():
        if params[param] is not None:
            fields[field] = params[param]
    boot = params["boot"]
    if boot is not None:
        for sub, field in _BOOT.items():
            if boot.get(sub) is not None:
                fields[field] = boot[sub]
    if params["options"]:
        fields.update(params["options"])
    return fields


def plan(net, params):
    """Return ``(changed, put_body_or_None, fields)`` for the desired options.

    The classic API replaces the whole network object on PUT, so the body is
    the current object with the managed fields overlaid; unspecified fields are
    preserved.
    """
    fields = desired_fields(params)
    differs = {k: v for k, v in fields.items()
               if _norm(net.get(k)) != _norm(v)}
    if not differs:
        return False, None, fields
    body = dict(net)
    body.update(fields)
    return True, body, fields


def _validate_lengths(params, module):
    """Fail if a server list exceeds the number of available slots."""
    for key, (_prefix, count) in _SLOTS.items():
        servers = params[f"{key}_servers"]
        if servers is not None and len(servers) > count:
            module.fail_json(
                msg=f"{key}_servers accepts at most {count} addresses.")


def _resolve_network(client, base, name, module):
    """Return the single classic network object named ``name``."""
    matches = [n for n in client.get(base).get("data", []) or []
               if n.get("name") == name]
    if not matches:
        module.fail_json(msg=f"no network named {name!r} on this site.")
    if len(matches) > 1:
        module.fail_json(
            msg=f"multiple networks named {name!r}; names must be unique.")
    return matches[0]


def run(module):
    """Ensure the named network advertises the declared DHCP options."""
    params = module.params
    _validate_lengths(params, module)
    client = UniFiClient(
        host=params["host"], port=params["port"], api_key=params["api_key"],
        validate_certs=params["validate_certs"], ca_path=params.get("ca_path"),
        timeout=params["timeout"], api_base_path="/proxy/network")
    base = f"/api/s/{params['site']}/rest/networkconf"
    try:
        net = _resolve_network(client, base, params["name"], module)
        changed, body, fields = plan(net, params)
        diff = {"before": {k: net.get(k) for k in fields}, "after": fields}
        if changed and not module.check_mode:
            client.put(f"{base}/{net['_id']}", body=body)
        module.exit_json(
            changed=changed,
            network_dhcp={"name": params["name"], "dhcp_options": fields},
            diff=diff)
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
            "dns_servers": {"type": "list", "elements": "str"},
            "ntp_servers": {"type": "list", "elements": "str"},
            "wins_servers": {"type": "list", "elements": "str"},
            "lease_time": {"type": "int"},
            "tftp_server": {"type": "str"},
            "wpad_url": {"type": "str"},
            "unifi_controller": {"type": "str"},
            "boot": {"type": "dict", "options": {
                "enabled": {"type": "bool"},
                "server": {"type": "str"},
                "filename": {"type": "str"},
            }},
            "options": {"type": "dict"},
        },
        required_one_of=[[
            "dns_servers", "ntp_servers", "wins_servers", "lease_time",
            "tftp_server", "wpad_url", "unifi_controller", "boot", "options",
        ]],
        supports_check_mode=True,
    )
    run(module)


if __name__ == "__main__":
    main()
