# Sprint 2 Report (24-29 Oct)

**Sprint goal:** Deliver full multi-interface capture, wireless threat detection, centralized rule configuration, resilient input hardening, SAST security automation, real-time WebSocket dashboard, search/filter/export, and complete project verification.

## F3 Threat Detection & Security: planned work (Ritu Ravish)

| Issue | SRS ID | Story | Points | Status |
| :--- | :--- | :--- | :--- | :--- |
| #18 | FR-F3-05 | WiFi Deauthentication and Disassociation Floods (`WifiDeauthDetector`) | 3 | Completed |
| #19 | FR-F3-06 | Rogue and Evil-Twin Wireless Access Points (`RogueApDetector`) | 5 | Completed |
| #20 | FR-F3-07 | BLE Advertisement Floods and MAC Churning (`BleFloodDetector`) | 3 | Completed |
| #21 | FR-F3-08 | Dynamic Rule Configuration and Sliding Window Thresholds (`DetectionConfig`) | 3 | Completed |
| #23 | SEC-01 | Automated Bandit SAST and SonarQube Pipeline (`.bandit`, `sonar-project.properties`) | 2 | Completed |
| #24 | SEC-02 | Harden Packet Processing Against Malformed and Fuzzed Inputs (`DetectionEngine.validate_record`) | 3 | Completed |
| | | **Total planned** | **19** | |

## Team velocity

Fill in from the Project board after all Sprint 2 PRs are merged.

| Member | Points planned | Points completed |
| :--- | :--- | :--- |
| Vishal Prasath | | |
| Tejaswini R Pujar | | |
| Ritu Ravish | 19 | 19 |
| Varshini A | | |
| **Team** | | |

## What went well / what to improve

### F3 Threat Detection & Security (Ritu Ravish)
- **What went well:**
  - Expanded threat detection across the wireless spectrum: implemented 802.11 deauthentication/disassociation flood detection (`WifiDeauthDetector`), Rogue/Evil-Twin AP detection with security downgrade monitoring (`RogueApDetector`), and BLE advertisement flood and MAC address churning detection (`BleFloodDetector`).
  - Implemented centralized, type-validated configuration management (`src/detection/config.py`) supporting dynamic runtime threshold reloads without interrupting active packet inspection (FR-F3-08).
  - Hardened `DetectionEngine` against malformed, fuzzed, and corrupted packet inputs (NaN/inf timestamps, out-of-bounds ports, giant payloads) with defensive error isolation preventing single-detector failures from stopping the inspection pipeline (SEC-02).
  - Configured automated security scanning with `.bandit` and SonarQube properties (`sonar-project.properties`), achieving zero high/medium security issues and clean flake8 compliance across the codebase.
  - Authored the comprehensive Software Test Plan (`docs/TestPlan.md`), documenting test strategies, environments, execution criteria, 23 formal test cases, and the complete Requirements Traceability Matrix (RTM).
  - Achieved 100% unit test pass rate across 69 unit and integration tests, with 94% line and branch coverage measured on the F3 Threat Detection subsystem.
- **What to improve:**
  - Execute end-to-end hardware validation on the physical Raspberry Pi 4 Model B with live monitor-mode WiFi adapters and ESP32 sniffer probes during the final release freeze.
