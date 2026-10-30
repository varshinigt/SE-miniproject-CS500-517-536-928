# Sprint 1 Report (19-23 Oct)

**Sprint goal:** one working end-to-end slice: Ethernet traffic captured, parsed, stored, checked by detection rules and shown on the dashboard.

## F4 Dashboard: planned work

| Issue | SRS ID | Story | Points | Status |
| :--- | :--- | :--- | :--- | :--- |
| #1 | FR-F4-01 | REST API skeleton with health endpoint | 2 | Merged (#46) |
| #2 | FR-F4-01 | Packets endpoint reading from SQLite | 3 | Merged (#46) |
| #3 | FR-F4-01 | Alerts endpoint | 2 | Merged (#46) |
| #4 | FR-F4-02 | Dashboard page with live packet table | 5 | Merged (#48) |
| #5 | FR-F4-02 | Alert feed panel | 3 | Merged (#48) |
| | | **Total planned** | **15** | |

## F3 Threat Detection: planned work

| Issue | SRS ID | Story | Points | Status |
| :--- | :--- | :--- | :--- | :--- |
| #13 | REQ-F3-10 | Pluggable detection rule engine core (`DetectionEngine`, `BaseDetector`) | 3 | Merged |
| #14 | REQ-F3-09 | Standardized alert schema and serialization (`Alert`, `NormalizedRecord`) | 2 | Merged |
| #15 | REQ-F3-01 | Dynamic ARP cache poisoning detection (`ArpSpoofDetector`) | 3 | Merged |
| #16 | REQ-F3-02 | ARP reply flood detection with sliding-window eviction | 2 | Merged |
| #17 | REQ-F3-03 | TCP/UDP horizontal and vertical port scan detector (`PortScanDetector`) | 5 | Merged |
| | | **Total planned** | **15** | |

## F1 Packet Capture: planned work

| Issue | SRS ID | Story | Points | Status |
| :--- | :--- | :--- | :--- | :--- |
| #28 | REQ-F1-01 | Promiscuous Ethernet capture with safe error handling (`EthernetCapture`) | 5 | Merged (#54) |
| #29 | REQ-F1-05 | PCAP session recording, rotation and replay (`PcapSession`, `replay_pcap`) | 5 | Merged (#55) |
| #30 | NFR-PERF-01 | Capture statistics tracking and loss benchmark (`StatsTracker`, `capture_benchmark.py`) | 2 | Merged (#56) |
| | | **Total planned** | **12** | |

## Team velocity

Fill in from the Project board (Project -> Insights) after the PRs are merged.

| Member | Points planned | Points completed |
| :--- | :--- | :--- |
| Vishal Prasath | 12 | 12 |
| Tejaswini R Pujar | | |
| Ritu Ravish | 15 | 15 |
| Varshini A | 15 | 15 |
| **Team** | | |

## What went well / what to improve

### F1 Packet Capture (Vishal Prasath)
- **What went well:**
  - Implemented promiscuous Ethernet capture with graceful exception boundaries for missing NICs and unprivileged runs.
  - Implemented size- and duration-bounded PCAP rotation matching Wireshark format, along with deterministic replay for offline evaluation and testing.
  - Added session-level stats tracking for captured and dropped frames via Linux sysfs NIC counters, supported by unit tests with 100% test pass rate.
  - Maintained full CI compliance (flake8, Bandit, pip-audit, pytest).
- **What to improve:**
  - Execute the sustained 1,000 pps lossless capture benchmark on physical Raspberry Pi 4 hardware once deployed in lab.
  - Proceed with Sprint 2 wireless capture features (WiFi monitor mode hopping, BLE advertisements, and ESP32 UDP ingestion).

### F4 Dashboard (Varshini A)
- **What went well:**
  - Delivered the REST API (health, packets, alerts), the live packet table and the alert feed, with 22 unit tests and 98% line and branch coverage.
  - CI caught a missing dependency and a Bandit warning on our first PRs; both were fixed the same day (#47 and #49).
  - Rotating reviewers kept every PR reviewed before merge.
- **What to improve:**
  - Replace polling with WebSocket push and measure dashboard latency against NFR-PERF-03 (both done in Sprint 2).
  - Align the dashboard queries with the final parser schema once F2 is integrated.

### F3 Threat Detection (Ritu Ravish)
- **What went well:**
  - Decoupled `DetectionEngine` from individual rules via the `BaseDetector` strategy pattern, making rules modular and independently testable.
  - Achieved high unit test coverage across ARP spoofing, ARP reply flooding, and TCP/UDP port scanning rules with sliding-window time eviction and memory bounding.
  - Maintained zero high-severity Bandit SAST warnings and compliant flake8 linting in CI.
- **What to improve:**
  - Wire the detection engine directly to the F2 parser stream queue and persist generated alerts to the shared SQLite database instead of using in-memory callbacks.
  - Move hardcoded rule thresholds from constructor defaults into a centralized configuration module (`src/detection/config.py`).

