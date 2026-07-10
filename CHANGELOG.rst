======================================
Starnix UniFi Collection Release Notes
======================================

.. contents:: Topics

v0.1.0
======

Release Summary
---------------

Initial development release of the ``starnix.unifi`` collection. Modules for
the UniFi zone-based (Policy Engine) firewall -- zones, policies, policy
ordering, and traffic-matching lists -- and for networks, on the official v1
Integration API, plus a classic-API module for DHCP options (DNS, NTP,
network boot, and more). Includes unit tests, gated integration targets, and
CI.

New Modules
-----------

- unifi_firewall_group - Manage UniFi traffic\-matching lists (address/port groups)
- unifi_firewall_policy - Manage UniFi zone\-based firewall policies
- unifi_firewall_policy_order - Set UniFi firewall policy evaluation order for a zone pair
- unifi_firewall_zone - Manage UniFi firewall zones
- unifi_network - Manage UniFi networks (VLANs)
- unifi_network_dhcp - Manage a UniFi network's DHCP options (DNS, NTP, boot, ...)
- unifi_site_info - Return UniFi controller info and the list of sites
