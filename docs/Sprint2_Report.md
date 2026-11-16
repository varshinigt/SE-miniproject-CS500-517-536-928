# Sprint 2 Report (24-30 Oct)

**Sprint goal:** Deliver full multi-interface capture, wireless threat detection, centralized rule configuration, resilient input hardening, SAST security automation, real-time WebSocket dashboard, search/filter/export, and complete project verification.

---

## F3 Threat Detection & Security: delivered work (Ritu Ravish)

| Issue | SRS ID | Story | Points | Status | Delivered in |
| :--- | :--- | :--- | :--- | :--- | :--- |
| #18 | FR-F3-05 | WiFi Deauthentication and Disassociation Floods | 3 | Done | `src/detection/rules/wifi_deauth.py` |
| #19 | FR-F3-06 | Rogue and Evil-Twin Wireless Access Points | 5 | Done | `src/detection/rules/rogue_ap.py` |
| #20 | FR-F3-07 | BLE Advertisement Floods and MAC Churning | 3 | Done | `src/detection/rules/ble_flood.py` |
| #21 | FR-F3-08 | Dynamic Rule Configuration and Sliding Window Thresholds | 3 | Done | `src/detection/config.py` |
| #23 | SEC-01 | Automated Bandit SAST and SonarQube Pipeline | 2 | Done | `.bandit`, `sonar-project.properties` |
| #24 | SEC-02 | Harden Packet Processing Against Malformed and Fuzzed Inputs | 3 | Done | `src/detection/engine.py` |
| | | **Total planned & delivered** | **19** | | |

---

## F4 Dashboard: delivered work (Varshini A)

| Issue | SRS ID | Story | Points | Status | Delivered in |
| :--- | :--- | :--- | :--- | :--- | :--- |
| #6 | FR-F4-01 | WebSocket live updates with polling fallback | 5 | Done | `src/dashboard/routes/ws.py`, `src/dashboard/static/index.html` |
| #7 | FR-F4-02 | Traffic-by-protocol chart | 3 | Done | `src/dashboard/routes/stats.py`, `src/dashboard/static/index.html` |
| #8 | FR-F4-03 | Device inventory panel | 3 | Done | `src/dashboard/routes/devices.py`, `src/dashboard/static/index.html` |
| #9 | FR-F4-04 | Packet search and filters | 3 | Done | `src/dashboard/queries.py`, `src/dashboard/routes/packets.py` |
| #10 | FR-F4-05 | Export packets and alerts to CSV and JSON | 3 | Done | `src/dashboard/routes/export.py`, export links |
| #11 | NFR-USE-01 | Phone layout (responsive styles) | 3 | Done | `src/dashboard/static/index.html` |
| #12 | NFR-PERF-03 | Latency measurement | 2 | Done | `src/dashboard/latency.py`, `docs/Latency_Report.md` |
| | | **Total planned & delivered** | **22** | | |

---

## F1 & F2 Highlights (Vishal Prasath & Tejaswini R Pujar)

- **F1 Packet Capture (Vishal Prasath):** Implemented PCAP session recording, size/time-bounded rotation, capture replay harness, and sysfs NIC loss counter benchmarks.
- **F2 Protocol Parsing & Registry (Tejaswini R Pujar):** Completed L2–L7 protocol parsing, pluggable protocol registry, and WiFi/BLE parser decoders mapping into unified schema (`NormalizedRecord`).

---

## Team Velocity

Summary of velocity across Sprint 1 and Sprint 2:

| Member | Role & Module | Sprint 1 Points | Sprint 2 Points | Total Velocity |
| :--- | :--- | :--- | :--- | :--- |
| Vishal Prasath | DevOps Lead / F1 Capture | 12 | 12 | 24 |
| Tejaswini R Pujar | QA Lead / F2 Parsing | 10 | 12 | 22 |
| Ritu Ravish | Security Lead / F3 Detection | 15 | 19 | 34 |
| Varshini A | Scrum Master / F4 Dashboard | 15 | 22 | 37 |
| **Team Total** | | **52** | **65** | **117** |

---

## Verification & Quality Gates

- **Unit Tests:** 189 total passing unit tests project-wide (69 in F3 Threat Detection, 120 across F1, F2, F4).
- **Code Coverage:** F3 Threat Detection achieved **94% line and branch coverage** (565 statements, 23 missed, 194 branches, 22 partial). F4 Dashboard achieved **96% line and branch coverage**. Both exceed the project $\ge 85\%$ threshold (NFR-QA-01).
- **Security (SEC-01 & SEC-02):** Bandit SAST scan completed with **0 High, 0 Medium, and 0 Low** vulnerabilities across `src/detection` and `src/dashboard`. Automated fuzzing test suite (`test_fuzzing.py`) verified that corrupted packets, NaN/inf timestamps, and oversized buffers are quarantined without dropping engine threads.
- **Linting & Code Style:** Flake8 executed with zero errors (`0` reported).
- **Latency (NFR-PERF-03):** Measured median end-to-end update latency of **377 ms** and 95th percentile latency of **507 ms** (well below the 1,000 ms SRS limit). Full details in `docs/Latency_Report.md`.
- **Deviations:** All Sprint 1 and Sprint 2 deviations, resolved items, and carried-over items are formally documented in `docs/Deviations.md`.

---

## What went well / what to improve

### F3 Threat Detection & Security (Ritu Ravish)
- **What went well:**
  - Expanded threat detection across the wireless spectrum: implemented 802.11 deauthentication/disassociation flood detection (`WifiDeauthDetector`), Rogue/Evil-Twin AP detection with security downgrade monitoring (`RogueApDetector`), and BLE advertisement flood and MAC address churning detection (`BleFloodDetector`).
  - Implemented centralized, type-validated configuration management (`src/detection/config.py`) supporting dynamic runtime threshold reloads without interrupting active packet inspection (FR-F3-08).
  - Hardened `DetectionEngine` against malformed, fuzzed, and corrupted packet inputs (NaN/inf timestamps, out-of-bounds ports, giant payloads) with defensive error isolation preventing single-detector failures from stopping the inspection pipeline (SEC-02).
  - Configured automated security scanning with `.bandit` and SonarQube properties (`sonar-project.properties`), achieving zero high/medium security issues and clean flake8 compliance across the codebase.
  - Authored the comprehensive Software Test Plan (`docs/TestPlan.md`), documenting test strategies, environments, execution criteria, formal test cases, and the complete Requirements Traceability Matrix (RTM).
  - Achieved 100% unit test pass rate across 69 unit and integration tests, with 94% line and branch coverage measured on the F3 Threat Detection subsystem.
- **What to improve:**
  - Execute end-to-end hardware validation on the physical Raspberry Pi 4 Model B with live monitor-mode WiFi adapters and ESP32 sniffer probes during the final release freeze.
  - Implement DNS tunneling detection (REQ-F3-04) in a post-release update once live application-layer DNS traffic logging is fully coupled with Zeek on hardware.

### F4 Dashboard (Varshini A)
- **What went well:**
  - Each story was built as a small feature commit followed by a test commit.
  - Shared queries meant the REST routes and the WebSocket stream reuse the same code.
  - Latency was measured with a repeatable tool, not estimated.
- **What to improve:**
  - Align the dashboard schema with the parser schema and connect real capture data.
  - Build the missing requirements: MAC vendor lookup, extra filters and PCAP export.
  - Integrate modules earlier instead of building in parallel.
  - Run the latency test on the Raspberry Pi once hardware is available.
