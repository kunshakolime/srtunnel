# TODO

## Schedule `core.sync()`

`helpers/core.sync()` currently runs only after a user mutation (`@_auto_sync`) or
a manual sync from the dashboard. An expired user therefore keeps working until
an admin touches something.

- [ ] Add a `srtunnel sync` CLI verb that calls `core.sync()`.
- [ ] Add a systemd timer (every 5 min) + oneshot service in `configs/units/`.
- [ ] Teach `helpers/reconcile.py` about `.timer` units — it currently globs only
      `*.service` when installing units.
- [ ] Verify an expired account is removed with no API call in between.
