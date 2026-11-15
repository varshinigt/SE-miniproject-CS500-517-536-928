# F4 Test Execution Record

Build: 393abc5 | Date: 2026-11-16 | Executed by: Varshini A
Environment: macOS arm64, Python 3.13.0, pytest, FastAPI TestClient and websockets

| TC ID | SRS traceability | Status | Evidence |
| :--- | :--- | :--- | :--- |
| TC-F4-01 | REQ-F4-01 | Pass | tests/unit/test_health.py, test_packets_api.py, test_alerts_api.py, test_ws_live.py |
| TC-F4-02 | REQ-F4-02, NFR-USE-01 | Pass | tests/unit/test_mobile_layout.py, test_ui.py; manual 375 px check: docs/reports/F4_mobile_375px.png |
| TC-F4-03 | REQ-F4-03, REQ-F4-04 | Partial: inventory by IP, last seen, protocol/host/text filters Pass; OUI lookup, first seen, interface/MAC/time filters not implemented | tests/unit/test_devices_api.py, test_packet_filters.py; see docs/Deviations.md |
| TC-F4-04 | REQ-F4-05 | Partial: CSV and JSON Pass; PCAP export not implemented | tests/unit/test_export_api.py; see docs/Deviations.md |
| TC-PERF-02 | NFR-PERF-03 | Pass for database to dashboard stream (median 377 ms, p95 507 ms, limit 2.0 s); capture to dashboard not measured | docs/Latency_Report.md, tests/unit/test_latency.py |
| TC-QA-01 | NFR-QA-01 | Pass for F4: line and branch coverage 96% (limit 85%) | docs/reports/F4_unit_and_coverage_report.txt |
