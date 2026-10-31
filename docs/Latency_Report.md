# Dashboard Latency Report (NFR-PERF-03)

Measured on 2026-10-30 17:50 with Darwin arm64, Python 3.13.0.

Method: a marker packet is written to the database and timed until it arrives on the
`/ws/live` WebSocket, the same stream the browser uses. The server pushes a snapshot every 0.5 seconds.

| Metric | Value |
| :--- | :--- |
| Samples | 20 |
| Minimum | 201 ms |
| Mean | 373 ms |
| Median | 377 ms |
| 95th percentile | 507 ms |
| Maximum | 509 ms |
| Requirement | 95th percentile under 1000 ms |
| Result | **PASS** |
