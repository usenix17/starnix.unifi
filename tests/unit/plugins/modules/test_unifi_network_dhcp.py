# -*- coding: utf-8 -*-
# Copyright: (c) 2026, Sasha Karcz <sasha@starnix.net>
# GNU General Public License v3.0+ (see LICENSE or gnu.org/licenses/gpl-3.0)
# SPDX-License-Identifier: GPL-3.0-or-later
"""Unit tests for the unifi_network_dhcp plan logic (no network)."""

from ansible_collections.starnix.unifi.plugins.modules import (
    unifi_network_dhcp as dhcp,
)


def _params(**over):
    """Return a params dict with every managed option unset (None)."""
    base = {"dns_servers": None, "ntp_servers": None, "wins_servers": None,
            "lease_time": None, "tftp_server": None, "wpad_url": None,
            "unifi_controller": None, "boot": None, "options": None}
    base.update(over)
    return base


def _net(**over):
    """Return a classic networkconf object with DNS set and NTP off."""
    base = {"_id": "n1", "name": "Aux", "purpose": "corporate",
            "dhcpd_dns_enabled": True, "dhcpd_dns_1": "192.168.1.53",
            "dhcpd_dns_2": "10.17.89.53", "dhcpd_dns_3": "", "dhcpd_dns_4": "",
            "dhcpd_ntp_enabled": False, "dhcpd_leasetime": 86400}
    base.update(over)
    return base


def test_dns_noop():
    """Matching DNS servers -> no change."""
    changed, body, _f = dhcp.plan(
        _net(), _params(dns_servers=["192.168.1.53", "10.17.89.53"]))
    assert changed is False
    assert body is None


def test_dns_change_sets_and_clears_slots():
    """Fewer DNS servers updates slot 1 and blanks the rest."""
    changed, body, _f = dhcp.plan(_net(), _params(dns_servers=["1.1.1.1"]))
    assert changed is True
    assert body["dhcpd_dns_1"] == "1.1.1.1"
    assert body["dhcpd_dns_2"] == ""
    assert body["dhcpd_dns_enabled"] is True


def test_empty_list_disables():
    """An empty DNS list disables custom DNS."""
    changed, body, _f = dhcp.plan(_net(), _params(dns_servers=[]))
    assert changed is True
    assert body["dhcpd_dns_enabled"] is False
    assert body["dhcpd_dns_1"] == ""


def test_ntp_sets_enabled_and_slots():
    """Setting NTP servers turns NTP on and fills the slots."""
    _c, _b, fields = dhcp.plan(_net(), _params(ntp_servers=["192.168.1.1"]))
    assert fields["dhcpd_ntp_enabled"] is True
    assert fields["dhcpd_ntp_1"] == "192.168.1.1"
    assert fields["dhcpd_ntp_2"] == ""


def test_only_specified_options_are_managed():
    """Managing NTP leaves DNS fields out of the change set and intact."""
    _c, body, fields = dhcp.plan(_net(), _params(ntp_servers=["1.1.1.1"]))
    assert "dhcpd_dns_1" not in fields
    assert body["dhcpd_dns_1"] == "192.168.1.53"  # preserved by full-obj PUT


def test_lease_time_noop():
    """A lease time equal to the current value is not a change."""
    changed, _b, _f = dhcp.plan(_net(), _params(lease_time=86400))
    assert changed is False


def test_boot_options_mapped():
    """Boot sub-options map to the dhcpd_boot_* fields."""
    _c, _b, fields = dhcp.plan(_net(), _params(
        boot={"enabled": True, "server": "10.0.0.1", "filename": "pxe.0"}))
    assert fields["dhcpd_boot_enabled"] is True
    assert fields["dhcpd_boot_server"] == "10.0.0.1"
    assert fields["dhcpd_boot_filename"] == "pxe.0"


def test_boot_partial_only_sets_given_suboptions():
    """An unset boot sub-option is not written."""
    _c, _b, fields = dhcp.plan(_net(), _params(
        boot={"enabled": True, "server": None, "filename": None}))
    assert fields == {"dhcpd_boot_enabled": True}


def test_options_passthrough():
    """The generic options dict is sent as raw dhcpd_* fields."""
    _c, body, fields = dhcp.plan(
        _net(), _params(options={"dhcpd_conflict_checking": False}))
    assert fields["dhcpd_conflict_checking"] is False
    assert body["dhcpd_conflict_checking"] is False


def test_scalar_fields_mapped():
    """Scalar params map to their classic fields."""
    _c, _b, fields = dhcp.plan(_net(), _params(
        tftp_server="10.0.0.2", wpad_url="http://w/wpad.dat"))
    assert fields["dhcpd_tftp_server"] == "10.0.0.2"
    assert fields["dhcpd_wpad_url"] == "http://w/wpad.dat"
