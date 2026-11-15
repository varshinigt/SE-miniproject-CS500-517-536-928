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

## Planned vs delivered

| Issue | Story | Points | Status |
| :--- | :--- | :--- | :--- |
| #6 | WebSocket live updates with polling fallback | 5 | Done |
| #7 | Traffic-by-protocol chart | 3 | Done |
| #8 | Device inventory panel | 3 | Done |
| #9 | Packet search and filters | 3 | Done |
| #10 | Export packets and alerts to CSV and JSON | 3 | Done |
| #11 | Phone layout | 3 | Done |
| #12 | Latency measurement | 2 | Done |
| | **Total** | **22** | |

## Verification

- Unit tests: 189 passing across the project; dashboard line and branch coverage 96%.
- Latency (NFR-PERF-03): median 377 ms, 95th percentile 507 ms against the 1,000 ms limit. PASS. Full report: docs/Latency_Report.md.
- Security: Bandit reports no findings on src/dashboard.
- Deviations: D-F4-01 (WebSocket) and D-F4-03 (latency) are resolved. Unbuilt requirements REQ-F4-03, 04 and 05 are recorded in docs/Deviations.md.

## What went well / what to improve

- **What went well:**
  - Each story was built as a small feature commit followed by a test commit.
  - Shared queries meant the REST routes and the WebSocket stream reuse the same code.
  - Latency was measured with a repeatable tool, not estimated.
- **What to improve:**
  - Align the dashboard schema with the parser schema and connect real capture data.
  - Build the missing requirements: MAC vendor lookup, extra filters and PCAP export.
  - Integrate modules earlier instead of building in parallel.
  - Run the latency test on the Raspberry Pi once hardware is available.
