# -*- coding: utf-8 -*-
# Copyright: (c) 2026, Sasha Karcz <sasha@starnix.net>
# GPL-3.0-or-later (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
"""Shared HTTP client, argument spec, and diff helpers for starnix.unifi.

Targets the official UniFi Network Integration API (v1)::

    base:  https://<host>:<port>/proxy/network/integration
    auth:  X-API-KEY header
    site:  a UUID (GET /v1/sites); the literal "default" resolves on a
           single-site controller.

Two load-bearing decisions are encoded here (design doc section 4):

* Success is signalled by the absence of an exception; ``request`` never reads
  ``resp.status`` (avoids an AttributeError-on-every-call).
* Idempotency uses SUBSET comparison: only the keys the caller actually set are
  asserted against the live object. Server-injected or normalized keys in
  opaque objects (``trafficFilter`` etc.) never force a false change.
"""

import json
import re
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode

from ansible.module_utils.basic import env_fallback
from ansible.module_utils.urls import Request


def unifi_argument_spec():
    """Return the connection arguments shared by every module."""
    return {
        "host": {"type": "str", "required": True},
        "port": {"type": "int", "default": 443},
        "api_key": {"type": "str", "required": True, "no_log": True,
                    "fallback": (env_fallback, ["UNIFI_API_KEY"])},
        "validate_certs": {"type": "bool", "default": True},
        "ca_path": {"type": "path"},
        "timeout": {"type": "int", "default": 30},
        "site": {"type": "str", "default": "default"},
        "api_base_path": {"type": "str",
                          "default": "/proxy/network/integration"},
    }


class UniFiError(Exception):
    """A UniFi API or transport failure, carrying the response envelope."""

    def __init__(self, msg, status=None, code=None, envelope=None,
                 request_path=None):
        super().__init__(msg)
        self.status = status
        self.code = code
        self.envelope = envelope
        self.request_path = request_path


class UniFiClient:
    """A thin JSON client over ``ansible.module_utils.urls.Request``."""

    _UUID_RE = re.compile(
        r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}"
        r"-[0-9a-f]{4}-[0-9a-f]{12}$", re.I)

    def __init__(self, host, port, api_key, validate_certs=True, ca_path=None,
                 timeout=30, api_base_path="/proxy/network/integration"):
        self._base = f"https://{host}:{port}"
        self._prefix = api_base_path.rstrip("/")
        self._request = Request(
            headers={
                "X-API-KEY": api_key,
                "Accept": "application/json",
                "Content-Type": "application/json",
            },
            validate_certs=validate_certs,
            ca_path=ca_path,
            timeout=timeout,
        )

    def _url(self, path, query=None):
        url = f"{self._base}{self._prefix}{path}"
        if query:
            pruned = {k: v for k, v in query.items() if v is not None}
            if pruned:
                url = f"{url}?{urlencode(pruned)}"
        return url

    def request(self, method, path, query=None, body=None):
        """Perform one request and return decoded JSON (``{}`` if empty).

        Raises :class:`UniFiError` on any non-2xx status or transport failure.
        """
        data = json.dumps(body).encode("utf-8") if body is not None else None
        url = self._url(path, query)
        try:
            resp = self._request.open(method, url, data=data)
            raw = resp.read()
        except HTTPError as exc:  # HTTPError subclasses URLError: catch first
            raise self._to_unifi_error(exc) from exc
        except URLError as exc:
            raise UniFiError(f"Connection failed: {exc.reason}") from exc
        if not raw:
            return {}
        try:
            return json.loads(raw)
        except ValueError as exc:
            raise UniFiError(f"Malformed JSON in response: {exc}") from exc

    def _to_unifi_error(self, http_err):
        body = {}
        try:
            payload = http_err.read()  # read the error body exactly once
            if payload:
                body = json.loads(payload)
        except Exception:  # pylint: disable=broad-exception-caught
            body = {}
        msg = (body.get("message")
               or body.get("code")
               or getattr(http_err, "reason", None)
               or str(http_err)
               or "HTTP error")
        status = body.get("statusCode", getattr(http_err, "code", None))
        parts = [f"{status} {body.get('statusName', '')}: {msg}"]
        if body.get("code"):
            parts.append(f"(code={body['code']})")
        if body.get("requestId"):
            parts.append(f"[requestId={body['requestId']}]")
        return UniFiError(
            " ".join(parts),
            status=status,
            code=body.get("code"),
            envelope=body,
            request_path=body.get("requestPath"),
        )

    def get(self, path, query=None):
        """GET ``path`` and return the decoded JSON."""
        return self.request("GET", path, query=query)

    def post(self, path, body=None, query=None):
        """POST ``body`` to ``path`` and return the decoded JSON."""
        return self.request("POST", path, query=query, body=body)

    def put(self, path, body=None, query=None):
        """PUT ``body`` to ``path`` and return the decoded JSON."""
        return self.request("PUT", path, query=query, body=body)

    def patch(self, path, body=None, query=None):
        """PATCH ``body`` at ``path`` and return the decoded JSON."""
        return self.request("PATCH", path, query=query, body=body)

    def delete(self, path, query=None):
        """DELETE ``path`` and return the decoded JSON."""
        return self.request("DELETE", path, query=query)

    def paginate(self, path, query=None, page_size=200):
        """Yield every item across a paginated list endpoint.

        Advances the offset by the number of items actually returned (never the
        requested page size), matching the API rule ``offset + count >=
        totalCount``. Advancing by ``page_size`` would skip items whenever the
        server caps the limit below the request.
        """
        query = dict(query or {})
        offset = 0
        while True:
            page = self.request(
                "GET", path,
                query=dict(query, offset=offset, limit=page_size))
            data = page.get("data", []) or []
            yield from data
            count = page.get("count", len(data))
            total = page.get("totalCount", 0)
            if count == 0:
                break
            offset += count
            if offset >= total:
                break

    def resolve_site(self, site):
        """Return the site UUID for ``site`` (a UUID, or ``"default"``)."""
        if self._UUID_RE.match(site or ""):
            return site
        # The Site object exposes {id, internalReference, name}; writes use
        # only the authoritative id. "default" is the single-site shortcut.
        if site == "default":
            sites = list(self.paginate("/v1/sites"))
            if len(sites) == 1:
                return sites[0]["id"]
            raise UniFiError(
                "site='default' is ambiguous on a multi-site controller "
                f"({len(sites)} sites). Pass the site UUID explicitly.")
        raise UniFiError(
            f"site={site!r} is not a UUID. Pass a site UUID, or 'default' "
            "on a single-site controller.")


class UniFiModule:
    """Bind an ``AnsibleModule`` to a client and resolved site id."""

    def __init__(self, module):
        self.module = module
        params = module.params
        if params.get("ca_path") and not params["validate_certs"]:
            module.warn("ca_path is set but validate_certs=false; the CA path "
                        "is ignored while certificate validation is disabled.")
        self.client = UniFiClient(
            host=params["host"], port=params["port"],
            api_key=params["api_key"],
            validate_certs=params["validate_certs"],
            ca_path=params.get("ca_path"), timeout=params["timeout"],
            api_base_path=params["api_base_path"],
        )
        self._site_id = None

    @property
    def site_id(self):
        """Resolve (once, lazily) and return the site UUID for this run.

        Deferred so read-only modules that never touch a site-scoped path
        (e.g. ``unifi_site_info``) work even on a multi-site controller.
        """
        if self._site_id is None:
            self._site_id = self.client.resolve_site(
                self.module.params["site"])
        return self._site_id

    def fail(self, msg, **kwargs):
        """Fail the module run with ``msg`` and optional extra fields."""
        self.module.fail_json(msg=msg, **kwargs)

    def handle(self, exc):
        """Fail the run, surfacing the full :class:`UniFiError` envelope."""
        self.module.fail_json(
            msg=str(exc),
            unifi_status=exc.status,
            unifi_code=exc.code,
            unifi_request_path=exc.request_path,
            unifi_error=exc.envelope,
        )


def prune(value):
    """Recursively drop ``None`` so an omitted key equals a not-set key."""
    if isinstance(value, dict):
        return {k: prune(v) for k, v in value.items() if v is not None}
    if isinstance(value, list):
        return [prune(v) for v in value]
    return value


def _canon(values):
    """Return an order-insensitive canonical form for a set-typed field."""
    return sorted(json.dumps(v, sort_keys=True) for v in values)


def subset_equal(desired, current, set_keys=()):
    """Return ``True`` iff every key set in ``desired`` matches ``current``.

    Keys present only in ``current`` (server-injected defaults or expanded
    opaque sub-keys) are invisible. Nested dicts recurse with the same rule.
    ``set_keys`` names list fields compared order-insensitively.
    """
    for key, dval in desired.items():
        if dval is None:  # caller did not set it -> ignore
            continue
        cval = current.get(key)
        if key in set_keys and isinstance(dval, list) \
                and isinstance(cval, list):
            if _canon(dval) != _canon(cval):
                return False
        elif isinstance(dval, dict) and isinstance(cval, dict):
            if not subset_equal(dval, cval, set_keys):
                return False
        elif dval != cval:
            return False
    return True


def needs_update(desired_body, current_obj, set_keys=()):
    """Return ``(changed, {"before": ..., "after": ...})`` under subset rules.

    The diff lists only the caller-specified keys and their current values, so
    ``--diff`` output is meaningful rather than a wall of server defaults.
    """
    changed = not subset_equal(desired_body, current_obj, set_keys)
    before = {k: current_obj.get(k)
              for k in desired_body if desired_body[k] is not None}
    after = {k: v for k, v in desired_body.items() if v is not None}
    return changed, {"before": before, "after": after}
