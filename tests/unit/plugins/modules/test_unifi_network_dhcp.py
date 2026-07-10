# -*- coding: utf-8 -*-
# Copyright: (c) 2026, Sasha Karcz <sasha@starnix.net>
# GNU General Public License v3.0+ (see LICENSE or gnu.org/licenses/gpl-3.0)
# SPDX-License-Identifier: GPL-3.0-or-later
"""Unit tests for the unifi_network_dhcp plan logic (no network)."""

from ansible_collections.starnix.unifi.plugins.modules import (
    unifi_network_dhcp as dhcp,
)


def _net(**over):
    """Return a classic networkconf object with two DNS servers set."""
    base = {"_id": "n1", "name": "Aux", "purpose": "corporate",
            "dhcpd_dns_enabled": True, "dhcpd_dns_1": "192.168.1.53",
            "dhcpd_dns_2": "10.17.89.53"}
    base.update(over)
    return base


def test_current_dns_skips_blanks():
    """current_dns returns set servers in order, ignoring empty/None."""
    net = _net(dhcpd_dns_2="", dhcpd_dns_3=None)
    assert dhcp.current_dns(net) == ["192.168.1.53"]


def test_noop_when_matching():
    """Matching servers -> no change, no body."""
    changed, body = dhcp.plan(_net(), ["192.168.1.53", "10.17.89.53"])
    assert changed is False
    assert body is None


def test_order_is_significant():
    """Swapping primary/secondary is a change."""
    changed, _body = dhcp.plan(_net(), ["10.17.89.53", "192.168.1.53"])
    assert changed is True


def test_change_sets_and_clears_keys():
    """Fewer servers updates dhcpd_dns_1 and drops the unused keys."""
    changed, body = dhcp.plan(_net(), ["1.1.1.1"])
    assert changed is True
    assert body["dhcpd_dns_1"] == "1.1.1.1"
    assert "dhcpd_dns_2" not in body
    assert body["dhcpd_dns_enabled"] is True


def test_empty_list_disables_custom_dns():
    """An empty list disables DHCP DNS and removes all server keys."""
    changed, body = dhcp.plan(_net(), [])
    assert changed is True
    assert body["dhcpd_dns_enabled"] is False
    assert "dhcpd_dns_1" not in body


def test_body_preserves_other_fields():
    """The full-object PUT body keeps unrelated network fields intact."""
    _changed, body = dhcp.plan(_net(), ["1.1.1.1"])
    assert body["purpose"] == "corporate"
    assert body["_id"] == "n1"
