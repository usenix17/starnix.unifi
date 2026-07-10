# starnix.unifi -- build plan

Design doc: `~/ArgoCD/starnix_unifi_design.md`. Live schema ground truth:
`docs/schema-discovery.md`. All Python: Google + PEP8 style, pylint 10/10.

## Done
- [x] Schema discovery against the live UDM (v1 API reachable; trafficFilter /
      action / ipProtocolScope / list shapes captured -> `docs/schema-discovery.md`)
- [x] Collection scaffold (galaxy.yml, meta/runtime.yml, changelogs, README,
      LICENSE, .gitignore, .pylintrc, test dirs)
- [x] `plugins/module_utils/unifi.py` -- client, arg spec, diff helpers
- [x] `plugins/doc_fragments/auth.py` -- shared connection options
- [x] `unifi_site_info` -- read-only; proves the arg-spec + client + module
      stack end to end. Verified live (app version 10.4.57, site UUID). Made
      `UniFiModule.site_id` lazy so info modules skip site resolution.
- [x] Unit tests: `module_utils` (17 tests -- paginate offset-by-count, error
      envelope, site resolution, subset_equal/needs_update/prune) + site_info.
      pylint 10/10, pycodestyle clean, 17/17 pass.

- [x] `unifi_firewall_group` (traffic-matching-lists) -- first write module.
      Probed the live write schema (body {type,name,items}; items required
      non-empty; type in IPV4_ADDRESSES/IPV6_ADDRESSES/PORTS; GET-by-id 404s
      clean). recreate flag guards a type change; dup name -> fail. 9 unit
      tests. **Verified live: full create/modify/delete idempotency gate.**

- [x] `unifi_firewall_policy` -- the centerpiece. Opaque action/source/dest/
      ipProtocolScope/schedule pass-through; adopts USER_DEFINED only (refuses
      DERIVED/SYSTEM_DEFINED by id); connectionStateFilter order-insensitive;
      full-replace PUT; required_if on present. 10 unit tests. **Verified live:
      re-create IDEMPOTENT proves opaque objects converge (the design's key
      bet).** Probed create/update body first (disabled policy, zero impact).

## Next
- [x] `unifi_firewall_zone` -- {name, networkIds}; networkIds required (default []), order-insensitive; system-zone rejection deferred to API. 9 unit tests, verified live (zones back to 7).
- [x] `unifi_firewall_policy_order` -- strict full-replace of before/after-system-defined buckets, positional compare, absent rejected. 5 unit tests. Verified live (throwaway zone + 2 disabled policies: set/reorder/idempotent).
- [ ] `unifi_network` -- probe the network write schema first
- [ ] `ansible-test sanity` clean; integration targets; CI matrix; Galaxy publish

## Notes / open API questions (confirm before the affected module ships)
- `action.type`: is `REJECT` valid? (only ALLOW/BLOCK observed)
- `ipProtocolScope.protocolFilter` inner shape (opaque for v0.1.0)
- traffic-matching-list and network **write** bodies vs their read shapes
- Only `metadata.origin == USER_DEFINED` objects are user-manageable
