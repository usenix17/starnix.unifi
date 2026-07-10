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

## Next
- [ ] `unifi_firewall_group` (traffic-matching-lists) -- confirm POST/PUT body
      vs the read shape first
- [ ] `unifi_firewall_policy` -- the template module (adopt USER_DEFINED only,
      opaque trafficFilter/action, subset comparison, check_mode + diff)
- [ ] `unifi_firewall_zone`
- [ ] `unifi_firewall_policy_order` -- wraps the ordering endpoint
- [ ] `unifi_network` -- probe the network write schema first
- [ ] `ansible-test sanity` clean; integration targets; CI matrix; Galaxy publish

## Notes / open API questions (confirm before the affected module ships)
- `action.type`: is `REJECT` valid? (only ALLOW/BLOCK observed)
- `ipProtocolScope.protocolFilter` inner shape (opaque for v0.1.0)
- traffic-matching-list and network **write** bodies vs their read shapes
- Only `metadata.origin == USER_DEFINED` objects are user-manageable
