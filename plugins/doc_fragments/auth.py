# -*- coding: utf-8 -*-
# Copyright: (c) 2026, Sasha Karcz <sasha@starnix.net>
# GPL-3.0-or-later (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
"""Shared connection documentation fragment for starnix.unifi modules."""


class ModuleDocFragment:  # pylint: disable=too-few-public-methods
    """Connection options included via ``starnix.unifi.auth``."""

    DOCUMENTATION = r"""
options:
  host:
    description:
      - Hostname or IP address of the UniFi controller (UDM / Network
        application).
    type: str
    required: true
  port:
    description:
      - TCP port the controller's HTTPS interface listens on.
    type: int
    default: 443
  api_key:
    description:
      - UniFi Network Integration API key, sent as the C(X-API-KEY) header.
      - May be supplied via the E(UNIFI_API_KEY) environment variable.
    type: str
    required: true
  validate_certs:
    description:
      - Whether to validate the controller's TLS certificate.
      - Set to V(false) only on a controller using its default self-signed
        certificate.
    type: bool
    default: true
  ca_path:
    description:
      - Path to a CA bundle used to validate the controller certificate, for
        deployments behind a private CA.
      - Ignored when O(validate_certs=false).
    type: path
  timeout:
    description:
      - Per-request timeout in seconds.
    type: int
    default: 30
  site:
    description:
      - The site to operate on, as a site UUID (from C(GET /v1/sites)).
      - The literal V(default) resolves automatically on a single-site
        controller and fails on a multi-site controller (pass the UUID).
    type: str
    default: default
  api_base_path:
    description:
      - Base path prefix for the Integration API. The documented and only
        supported value is the default; exposed purely as an escape hatch.
    type: str
    default: /proxy/network/integration
"""
