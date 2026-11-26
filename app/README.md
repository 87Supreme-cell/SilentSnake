# app (Flutter / Dart)

SilentSnake desktop dashboard for Linux. It's a client of the local REST API ([`docs/api/rest-api.md`](../docs/api/rest-api.md)) on `127.0.0.1:8765` and reads the API token from `$XDG_DATA_HOME/silentsnake/config/api-token`. The design follows `design:` in `silentsnake.yaml`, with `ronin-style-reference.jpg` as the primary style.

**Screens:**
- **Dashboard:** live throughput, capture engine health, risk ring, live connections (allowed or flagged), alerts with plain-English reasons, traffic per minute, top peers.
- **Connections:** every connection, with a flagged-only filter.
- **Live log:** rows typed by kind (flow, DNS, TLS, engine), a 5-minute timeline, filters and pause.

The deep scan card is shown disabled until the encrypted log store exists.

**Accessibility:** risk is always shown as a number, a label and an icon, never colour alone. Direction is shown by arrow shape, not colour. Animations are off when the system asks to reduce motion.

**Dependencies:** the Flutter SDK only (3.50.1, pinned with its hash in `dev/flutter/Containerfile`). No hosted packages are added. `pubspec.lock` records the SDK's own pinned packages.

```sh
scripts/app.sh flutter test                     # widget tests
scripts/app.sh flutter build linux --release    # → app/build/linux/x64/release/bundle/silentsnake
app/build/linux/x64/release/bundle/silentsnake [--page dashboard|connections|log]
scripts/screenshot-app.sh                       # real-data screenshots → docs/proof/screenshots/
```

Not built yet: desktop widgets, settings, deep scan, the LLM analyst panel, and audit/export screens.
