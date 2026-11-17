# F4 Dashboard System Validation Report

Build: 393abc5 | Date: 2026-11-16 | Executed by: Varshini A
Environment: macOS arm64 (MacBook Air), Python 3.13.0, uvicorn on port 8001 (port 8000 was already used by another local process), SQLite database filled with demo data by src/dashboard/seed.py (live mode).
Scope: end-to-end checks of the running dashboard API and WebSocket stream. These run on seeded demo data, not on live capture (see docs/Deviations.md, D-F4-02). They did not run on a Raspberry Pi.

## Results

| ID | SRS | Check | Expected | Actual | Result |
| :--- | :--- | :--- | :--- | :--- | :--- |
| ST-F4-01 | REQ-F4-01 | GET /health | status ok | {"status":"ok"} | Pass |
| ST-F4-02 | REQ-F4-01 | GET /packets?limit=2 | Two newest packets as JSON, newest first | Two packets (ids 508 and 507), newest first | Pass |
| ST-F4-03 | REQ-F4-04 | GET /packets?protocol=DNS&limit=2 | Only DNS packets | Two DNS packets (ids 502 and 500) | Pass |
| ST-F4-04 | REQ-F4-01 | GET /alerts?limit=2 | Two newest alerts with severity, rule, description | Two alerts (ids 35 and 34) | Pass |
| ST-F4-05 | REQ-F4-02 | GET /stats | Packet counts per protocol for the last 60 s | total 60: ARP 14, TCP 14, UDP 14, DNS 13, ICMP 5 | Pass |
| ST-F4-06 | REQ-F4-03 | GET /devices?limit=2 | Hosts with packet, byte and protocol counts and last seen | 192.168.1.10 (85 packets) and 192.168.1.23 (97 packets) with protocol lists | Pass |
| ST-F4-07 | REQ-F4-05 | GET /export/packets?format=csv&limit=2 | HTTP 200, CSV download with header row | 200 OK, text/csv, attachment packets.csv, header plus 2 rows | Pass |
| ST-F4-08 | REQ-F4-01 | GET /packets?limit=5000 | Rejected by input validation | HTTP 422 | Pass |
| ST-F4-09 | NFR-PERF-03 | Latency tool, 20 samples over /ws/live | 95th percentile under 1000 ms (SRS limit 2.0 s) | min 202 ms, mean 376 ms, median 379 ms, p95 508 ms, max 509 ms | Pass |

## Not covered

- PCAP export, MAC vendor lookup, and filtering by interface, MAC and time range are not implemented. See docs/Deviations.md.
- Capture to dashboard latency was not measured because capture is not connected to the dashboard.
- Testing on a Raspberry Pi 4 was not done because no Pi was available.
- Mobile layout (375 px) is covered by unit tests on the page markup; no browser screenshot is attached to this report.

## Raw output

Packets: id 508 ARP 192.168.1.10 to 192.168.1.23, id 507 UDP 192.168.1.1 to 192.168.1.10
Alerts: id 35 low DNS anomaly, id 34 medium Port scan
Stats: {"window":60,"total":60,"by_protocol":{"ARP":14,"TCP":14,"UDP":14,"DNS":13,"ICMP":5}}
CSV header: id,ts,src,dst,protocol,length,info
