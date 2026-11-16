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

## F2 Protocol Parsing & Zeek Integration: Sprint 2

| Issue | Story | Delivered in |
| :--- | :--- | :--- |
| #38 | Zeek log ingestion supporting JSON and TSV, optional fields, malformed records, and file reading/following | `src/parser/zeek_ingest.py` |
| #39 | Bounded asynchronous packet queue to prevent unbounded queue growth, while preserving synchronous processing by default | Packet queue implementation and Ethernet capture integration |
| #40 | Expanded unit tests and coverage verification | `tests/unit/` |

### Verification

- Line coverage: **91.90%**
- Branch coverage: **85.37%**
- Both coverage targets exceeded 85%.
- Synthetic performance test: 5,000 packets processed, 0 dropped, and 0 errors.
- Measured throughput: approximately 446,704 packets/second under the synthetic test setup. This is not an end-to-end live network throughput measurement.

### What went well / what to improve

- Zeek ingestion handles both JSON and TSV log formats and supports malformed or optional fields.
- Bounded queue processing helps control memory usage during packet processing.
- Further validation with live network traffic and different capture environments would strengthen performance evaluation.
