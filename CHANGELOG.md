# Changelog

Dates are commit dates. Not production-tested.

## 2026-10-21
- `lists`: every refresh logs how old each list says it is (from its `Updated:` line) and warns above `lists.warnAfterHours` (default 6). The publisher's schedule is best-effort, so this makes the delay visible to whoever runs the module. A line that cannot be read is reported as such, not guessed.

## 2026-10-19
- Add `mode = connections` (concurrent limit, 12 h block, allow lists), a list refresher and kernel tuning, with tests.
- `lists.baseUrl` defaults to the raw path of `tor-relay-lists` (same layout as the older service).
- Exempt the Snowflake servers; keep configured allow addresses across list refreshes.

## 2026-10-06
- Mark as prototype; restore the daily scheduled CI run.

## 2026-08-29
- Add the module, the two-node VM test and the flake.
- Run the VM test daily, not only on pushes.
