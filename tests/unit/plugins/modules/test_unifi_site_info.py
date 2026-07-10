# -*- coding: utf-8 -*-
# Copyright: (c) 2026, Sasha Karcz <sasha@starnix.net>
# GPL-3.0-or-later (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
"""Unit tests for the unifi_site_info module (no network)."""
# pylint: disable=too-few-public-methods

from ansible_collections.starnix.unifi.plugins.modules import unifi_site_info


class FakeModule:
    """Capture the exit_json result instead of exiting."""

    def __init__(self):
        self.result = None

    def exit_json(self, **kwargs):
        """Record the module result."""
        self.result = kwargs


class FakeClient:
    """Return canned /v1/info and /v1/sites payloads."""

    def get(self, _path):
        """Return a fake application-info payload."""
        return {"applicationVersion": "10.4.57"}

    def paginate(self, _path):
        """Yield fake site records."""
        return iter([
            {"id": "s-1", "internalReference": "default", "name": "Default"},
        ])


class FakeUM:
    """Minimal UniFiModule stand-in exposing client + module."""

    def __init__(self):
        self.client = FakeClient()
        self.module = FakeModule()


def test_run_returns_version_and_sites():
    """run() reports changed=false with the version and site list."""
    um = FakeUM()
    unifi_site_info.run(um)
    assert um.module.result["changed"] is False
    assert um.module.result["application_version"] == "10.4.57"
    assert um.module.result["sites"] == [
        {"id": "s-1", "internalReference": "default", "name": "Default"},
    ]
