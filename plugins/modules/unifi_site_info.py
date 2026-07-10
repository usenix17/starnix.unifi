# -*- coding: utf-8 -*-
# Copyright: (c) 2026, Sasha Karcz <sasha@starnix.net>
# GNU General Public License v3.0+ (see LICENSE or gnu.org/licenses/gpl-3.0)
# SPDX-License-Identifier: GPL-3.0-or-later
"""Return UniFi controller info and the site list (read-only)."""

DOCUMENTATION = r"""
module: unifi_site_info
short_description: Return UniFi controller info and the list of sites
version_added: "0.1.0"
description:
  - Read-only. Returns the UniFi Network application version and the list of
    sites on the controller, via the official Integration API.
  - This is the supported way to discover a site UUID, which the other modules
    in this collection require in their O(site) parameter. It also doubles as a
    connectivity and credential check.
  - Never changes anything; O(site) is accepted for a uniform interface but is
    ignored by this module.
author:
  - Sasha Karcz (@usenix17)
extends_documentation_fragment:
  - starnix.unifi.auth
"""

EXAMPLES = r"""
- name: Discover the controller version and site UUIDs
  starnix.unifi.unifi_site_info:
    host: heimdal.starnix.net
    api_key: "{{ lookup('env', 'UNIFI_API_KEY') }}"
  register: unifi

- name: Show the sites (each element includes the site UUID as 'id')
  ansible.builtin.debug:
    var: unifi.sites
"""

RETURN = r"""
application_version:
  description: The UniFi Network application version, from C(GET /v1/info).
  type: str
  returned: success
  sample: "10.4.57"
sites:
  description:
    - The list of sites on the controller, returned verbatim from
      C(GET /v1/sites). Each element includes at least C(id) (the site UUID).
  type: list
  elements: dict
  returned: success
  sample:
    - id: "88f7af54-98f8-306a-a1c7-c9349722b1f6"
      internalReference: "default"
      name: "Default"
"""

# Imports follow the documentation variables, as required by ansible-test
# validate-modules.
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.starnix.unifi.plugins.module_utils.unifi import (
    UniFiError,
    UniFiModule,
    unifi_argument_spec,
)


def run(um):
    """Fetch controller info and sites, then exit with the result."""
    info = um.client.get("/v1/info")
    sites = list(um.client.paginate("/v1/sites"))
    um.module.exit_json(
        changed=False,
        application_version=info.get("applicationVersion"),
        sites=sites,
    )


def main():
    """Module entry point."""
    module = AnsibleModule(
        argument_spec=unifi_argument_spec(),
        supports_check_mode=True,
    )
    um = UniFiModule(module)
    try:
        run(um)
    except UniFiError as exc:
        um.handle(exc)


if __name__ == "__main__":
    main()
