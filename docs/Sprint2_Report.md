# Sprint 2 Report (26-30 Oct)

**Sprint goal:** complete the dashboard (F4): push updates, charts, device inventory,
search and filters, export, phone layout, and a measured latency result.

## F4 Dashboard: delivered work

| Issue | Story | Delivered in |
| :--- | :--- | :--- |
| #6 | WebSocket live updates with polling fallback | `routes/ws.py`, `static/index.html` |
| #7 | Traffic-by-protocol chart | `routes/stats.py`, `static/index.html` |
| #8 | Device inventory panel | `routes/devices.py`, `static/index.html` |
| #9 | Packet search and filters | `queries.py`, `routes/packets.py`, filter bar |
| #10 | Export packets and alerts to CSV and JSON | `routes/export.py`, export links |
| #11 | Phone layout | responsive styles in `static/index.html` |
| #12 | Latency measurement | `latency.py`, `docs/Latency_Report.md` |

## Verification

- Unit tests: run `pytest --cov=src/dashboard --cov-branch` and note the result here.
- Latency (NFR-PERF-03): see `docs/Latency_Report.md`.
- Deviations from Sprint 1 are resolved: D-F4-01 (WebSocket added) and D-F4-03 (latency measured).
  See `docs/Deviations.md`.

## What went well / what to improve

- Update after the Sprint 2 review.
