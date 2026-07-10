# v1 Integration API -- Live Schema Discovery

Captured from the production UDM (Network 10.x) on 2026-07-09 by probing the
official Integration API. This is the **ground truth** for the field shapes the
published API export left opaque (`trafficFilter`, `action`, `ipProtocolScope`,
matching-list items). Modules are built against this, not the guessed docs.

- Base: `https://<host>:443/proxy/network/integration`
- Auth: `X-API-KEY`
- Sample size: 217 firewall policies, 29 traffic-matching-lists, 8 networks, 7 zones.

## Site object

```json
{ "id": "<uuid>", "internalReference": "<str>", "name": "<str>" }
```

`GET /v1/sites` returns `name` and `internalReference` in addition to `id`.
v0.1.0 still binds by `id` only (name matching is a later, additive feature).

## Firewall policy (`/v1/sites/{siteId}/firewall/policies`)

```jsonc
{
  "id": "<uuid>",                       // read-only
  "index": 10000,                       // read-only, managed via ordering endpoint
  "metadata": { "origin": "USER_DEFINED" },  // read-only
  "enabled": true,
  "name": "Allow all nebula",
  "description": "iac:allow-all-nebula-3",
  "action": { "type": "ALLOW", "allowReturnTraffic": false },
  "source": { "zoneId": "<uuid>", "trafficFilter": { ... } },   // trafficFilter optional
  "destination": { "zoneId": "<uuid>" },                        // omit trafficFilter = ANY
  "ipProtocolScope": { "ipVersion": "IPV4" },
  "connectionStateFilter": ["NEW"],     // optional
  "ipsecFilter": "MATCH_ENCRYPTED",     // optional
  "loggingEnabled": false,
  "schedule": { ... }                   // optional; unused in this deployment
}
```

### `action`
- `type`: **`ALLOW` | `BLOCK`** (observed). `REJECT` plausible but unconfirmed.
- `allowReturnTraffic`: bool, present on 157/217 (absent on many BLOCK rules).
  **Not in the published docs.**

### `metadata.origin` (read-only) -- **load-bearing for management**
- `USER_DEFINED` -- user-manageable; the only origin our modules create/update/
  delete and the only ids valid in the ordering endpoint.
- `DERIVED`, `SYSTEM_DEFINED` -- controller-owned. Modules must **filter these
  out** when listing/adopting and never attempt to mutate or reorder them.

### `ipProtocolScope`
- `ipVersion`: **`IPV4` | `IPV6` | `IPV4_AND_IPV6`** (docs guessed a "both"
  value; real token is `IPV4_AND_IPV6`).
- `protocolFilter`: object, present on 33/217. **The docs' guessed `protocol`
  string does not exist** -- it is a nested `protocolFilter` object. Treat as
  opaque for v0.1.0.

### `connectionStateFilter`
Observed values: `["NEW"]`, `["INVALID"]`, `["RELATED","ESTABLISHED"]`. Item
enum `NEW|INVALID|ESTABLISHED|RELATED`. Compare order-insensitively (`set_keys`).

### `trafficFilter` (the big gap -- fully mapped)

Optional per side; omit for "any". Shape is a discriminated union on `type`:

| `type` | sub-object | fields |
|---|---|---|
| `IP_ADDRESS` | `ipAddressFilter` | `{type: IP_ADDRESSES, ipAddresses:[...], matchOpposite}` **or** `{type: TRAFFIC_MATCHING_LIST, trafficMatchingListId, matchOpposite}` |
| `PORT` | `portFilter` | `{type: PORTS, ports:[...], matchOpposite}` **or** `{type: TRAFFIC_MATCHING_LIST, trafficMatchingListId, matchOpposite}` |
| `NETWORK` | `networkFilter` | `{networkIds:[<uuid>...], matchOpposite}` |
| `APPLICATION` | `applicationFilter` | `{applicationIds:[<int>...]}` |
| `DOMAIN` | `domainFilter` | `{type: DOMAINS, domains:[...]}` |

Distribution across 434 sides (src+dst of 217 policies):

```
272  <none> (ANY)
 54  IP_ADDRESS / ipAddressFilter=IP_ADDRESSES
 32  IP_ADDRESS / ipAddressFilter=TRAFFIC_MATCHING_LIST
 26  IP_ADDRESS + PORT combined (ipAddressFilter=IP_ADDRESSES, portFilter=PORTS)
 19  NETWORK / networkFilter
 13  PORT / portFilter=PORTS
  8  PORT / portFilter=TRAFFIC_MATCHING_LIST
  5  IP_ADDRESS + PORT (both TRAFFIC_MATCHING_LIST)
  3  APPLICATION / applicationFilter
  1  DOMAIN / domainFilter
```

Note: a single `trafficFilter` can carry **both** `ipAddressFilter` and
`portFilter` (address + port match) while `type` names the primary. Because
v0.1.0 treats `trafficFilter` as an opaque dict compared under subset rules, the
module passes the caller's structure through verbatim and does not need to model
this union -- but examples/tests must cover these shapes.

## Traffic-matching list (`/v1/sites/{siteId}/traffic-matching-lists`)

```json
{ "id": "<uuid>", "name": "bork-lagg", "type": "IPV4_ADDRESSES",
  "items": [ { "type": "IP_ADDRESS", "value": "192.168.1.86" } ] }
```

- `type`: `IPV4_ADDRESSES` (20), `PORTS` (9). `IPV6_ADDRESSES` plausible.
- `items[].type`: `IP_ADDRESS` (str value), `SUBNET` (str CIDR), `PORT_NUMBER`
  (**int** value). Value type depends on item type -- keep values untyped/raw.

## Zones / networks

- Zones: `GET .../firewall/zones` returns 7 total (system + custom); adopt/manage
  only where appropriate (system zones are not deletable).
- Networks: `GET .../networks` returns 8; DHCP DNS lives here (the field that
  broke Aux resolution). Exact network write-schema TBD -- probe before building
  `unifi_network`.

## Open items to confirm before the affected module ships
- `action.type`: is `REJECT` valid? (only ALLOW/BLOCK seen)
- `ipProtocolScope.protocolFilter`: inner shape (opaque for now)
- traffic-matching-list write body (POST/PUT) vs the read shape above
- network write schema (for `unifi_network`)
