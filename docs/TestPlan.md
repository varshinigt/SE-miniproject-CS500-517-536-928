# Software Test Plan (STP)
## Pocket Packet Sniffer (Version 1.0)
**Course:** Software Engineering (UE24CS341A)<br>
**Institution:** PES University, Department of Computer Science and Engineering<br>
**Document ID:** PPS-STP-V1.0<br>
**Version:** 1.0<br>
**Status:** Approved Baseline<br>
**Prepared by:** Ritu Ravish (Lead Consolidator & Security Lead), Tejaswini R Pujar (QA Lead), Vishal Prasath (DevOps Lead), Varshini A (Scrum Master)<br>
**Date:** October 2026

---

## 1. Introduction

### 1.1 Purpose
This Software Test Plan (STP) establishes the formal verification and validation strategy for the **Pocket Packet Sniffer (Version 1.0)**. It details how the software will be verified against the requirements documented in the Software Requirements Specification (`PPS-SRS-V1.0`). The test plan governs test scope, execution environments, test levels, security testing procedures, defect management, release criteria, and comprehensive requirements traceability.

### 1.2 Scope
Testing encompasses all four functional subsystems, security hardening controls, performance boundaries, and deployment configurations:
* **F1 — Multi-Interface Capture:** Promiscuous Ethernet, Wi-Fi 802.11 monitor mode with channel hopping, Bluetooth Low Energy (BLE) advertisement scanning, remote ESP32 sniffer UDP stream ingestion, and PCAP session rotation.
* **F2 — Protocol Parsing, Normalization & Storage:** Multi-layer dissectors (L2–L7), `NormalizedRecord` schema mapping, Zeek metadata ingestion (`conn.log`, `dns.log`), and SQLite WAL database persistence.
* **F3 — Pluggable Threat Detection & Alerting:** `BaseDetector` strategy framework, sliding-window state tracking, rules for ARP cache poisoning, ARP reply floods, TCP/UDP port scans, WiFi deauthentication/disassociation floods, Rogue/Evil-Twin APs, and BLE advertisement floods.
* **F4 — Live Monitoring, Device Inventory & Export:** FastAPI REST endpoints, bidirectional WebSockets, live packet streaming table, alert notification banner, IEEE MAC OUI device inventory, and forensic export (PCAP, CSV, JSON).
* **Non-Functional & Security Requirements:** Sustained 5,000 pkts/sec throughput without drop (NFR-PERF-01), bounded parser queues (NFR-PERF-02), sub-2.0s dashboard latency (NFR-PERF-03), automated Bandit SAST and SonarQube quality gate (SEC-01), malformed packet input fuzzing resilience (SEC-02), dependency vulnerability audit (SEC-03), responsive mobile viewport (NFR-USE-01), and Raspberry Pi Docker/systemd deployment (NFR-PORT-01).

### 1.3 References and Definitions
1. **IEEE Std 829-2008:** *IEEE Standard for Software and System Test Documentation*.
2. **PPS-SRS-V1.0:** *Software Requirements Specification for Pocket Packet Sniffer*.
3. **PPS-SAD-V1.0:** *Software Architecture Document for Pocket Packet Sniffer*.
4. **PCAP:** Packet Capture library file format (libpcap).
5. **SAST:** Static Application Security Testing.
6. **RTM:** Requirements Traceability Matrix.

---

## 2. Test Items

The following software artifacts and release deliverables are subject to formal verification:
* **F1 Modules:** `src/capture/ethernet.py`, `src/capture/session.py`, `src/capture/stats.py`, `src/capture/wifi.py`, `src/capture/ble.py`, `src/capture/esp32.py`.
* **F2 Modules:** `src/parser/base.py`, `src/parser/protocol_parser.py`, `src/parser/normalizer.py`, `src/parser/zeek_ingest.py`, `src/storage/sqlite_store.py`.
* **F3 Modules:** `src/detection/engine.py`, `src/detection/models.py`, `src/detection/config.py`, `src/detection/rules/base.py`, `src/detection/rules/arp_spoof.py`, `src/detection/rules/port_scan.py`, `src/detection/rules/wifi_deauth.py`, `src/detection/rules/rogue_ap.py`, `src/detection/rules/ble_flood.py`.
* **F4 Modules:** `src/dashboard/app.py`, `src/dashboard/db.py`, `src/dashboard/queries.py`, `src/dashboard/routes/`, `src/dashboard/static/index.html`.
* **DevOps & Security Configurations:** `Dockerfile`, `docker-compose.yml`, `.github/workflows/ci.yml`, `.bandit`, `sonar-project.properties`.

---

## 3. Features to be Tested

| Subsystem / Area | SRS Requirements Covered | Verification Focus & Objectives |
| :--- | :--- | :--- |
| **Capture Subsystem (F1)** | REQ-F1-01 to REQ-F1-05 | Promiscuous Ethernet capture, 2.4 GHz channel hopping (ch 1–13), BLE advertisement scanning, remote ESP32 UDP ingestion, and PCAP session rotation/replay. |
| **Parsing & Storage (F2)** | REQ-F2-01 to REQ-F2-05 | Layer 2 through Layer 7 protocol decoding, unified `NormalizedRecord` schema normalization, Zeek log enrichment, and SQLite indexing. |
| **Threat Detection (F3)** | REQ-F3-01 to REQ-F3-10 | Detection of ARP cache poisoning, reply floods, port scans, WiFi deauth floods, Rogue APs, BLE floods; sliding-window threshold configuration; standardized alert schema. |
| **Dashboard & API (F4)** | REQ-F4-01 to REQ-F4-05 | REST endpoints, WebSocket live push stream, packet table filters, active alert feeds, IEEE MAC OUI vendor resolution, and PCAP/CSV/JSON forensic export. |
| **Performance** | NFR-PERF-01 to NFR-PERF-03 | Sustained 5,000 pkts/sec capture, bounded parser memory queue ($\le 10,000$ packets), and sub-2.0s dashboard latency. |
| **Security Validation** | SEC-01 to SEC-04 | Bandit SAST scans (0 high/medium issues), SonarQube quality gate, `pip-audit` CVE checks, and malformed input fuzzing resilience. |
| **Usability & Portability** | NFR-USE-01, NFR-PORT-01, NFR-QA-01 | Mobile viewport rendering ($\ge 375\text{px}$), Raspberry Pi 4 Docker containerization with systemd autostart, and $\ge 85\%$ test coverage gate. |

---

## 4. Features Not to be Tested

* **Hardware Firmware Flashing:** Physical ESP32 flashing over UART/USB is considered an external hardware prerequisite.
* **Wireless RF Physical Attenuation:** Antenna gain, physical radio frequency path loss, and wireless signal reflection are assumed nominal.
* **Underlying Linux Kernel Network Drivers:** Vendor-supplied Linux kernel device drivers (`mac80211`, `bluez`) are treated as trusted system primitives without modification.

---

## 5. Test Approach and Strategy

### 5.1 Levels of Testing
* **Unit Testing (UT):** Validates individual functions, classes, dissectors, and detectors in isolation using synthetic packet records and mock network objects.
* **Integration Testing (IT):** Validates inter-module data contracts and asynchronous pipelines: `Capture -> Parser -> Storage -> Detection -> WebSocket -> Dashboard`.
* **System Testing (ST):** End-to-end execution on target Raspberry Pi 4 hardware, replaying curated attack PCAPs and verifying live alerts on client browsers.
* **Regression Testing:** Automated test execution on every commit and pull request via GitHub Actions CI.

### 5.2 Entry and Exit Criteria
* **Entry Criteria:**
  1. Source code passes flake8 linting with zero fatal syntax errors.
  2. Module compiles and passes local unit tests before opening a Pull Request.
  3. Feature branches are rebased on latest `main`.
* **Exit Criteria:**
  1. 100% of planned unit and integration test cases executed and passing.
  2. Overall code line and branch coverage exceeds the 85% requirement threshold.
  3. Bandit SAST scan reports zero High or Medium severity vulnerabilities.
  4. SonarQube quality gate status is **Passed**.
  5. Zero critical or high-severity unhandled defects remain open.

### 5.3 Security Validation Strategy (Lead: Ritu Ravish)
1. **Automated Static Analysis (Bandit):** Embedded in CI pipeline to scan AST for shell injections, weak cryptography, insecure deserialization, and hardcoded credentials.
2. **Dependency Vulnerability Governance (`pip-audit`):** Automated checks against the National Vulnerability Database (NVD) for third-party libraries.
3. **Fuzz Testing & Malformed Packet Hardening (SEC-02):** Automated injection of fuzzed packet fixtures into `DetectionEngine.validate_record()`—including NaN timestamps, infinite values, negative ports, giant payloads, and broken metadata—verifying zero process termination.

---

## 6. Test Environment

| Environment Attribute | Specification & Tooling |
| :--- | :--- |
| **Target Appliance** | Raspberry Pi 4 Model B (4GB RAM) + NodeMCU ESP32-WROOM-32 probe |
| **Operating System** | Debian 12 Bookworm (Linux Kernel 6.1+ 64-bit ARM) |
| **Runtime Software** | Python 3.11+, SQLite 3, Zeek 5.0+, Docker 24+, systemd |
| **Test Harness Frameworks** | `unittest`, `pytest`, `pytest-cov`, `bandit`, `flake8`, `pip-audit` |
| **Attack Simulation Data** | Curated PCAPs: ARP cache poison, SYN/UDP port sweeps, WiFi deauth burst, BLE flood |
| **Client Browsers** | Chromium 120+, Mozilla Firefox 120+, Safari Mobile (iOS / Android) |

---

## 7. Test Schedule and Milestones

| Milestone | Deliverable / Verification Objective | Owner |
| :---: | :--- | :--- |
| **T1 — Test Design** | Test case specifications and attack PCAP fixtures aligned with SRS IDs | Tejaswini (QA Lead) + All |
| **T2 — Environment Readiness** | Pi 4 hardware, WiFi monitor dongle, and CI workflow configured | Vishal (DevOps Lead) |
| **T3 — Module Verification** | Unit test suite achieves $\ge 85\%$ test coverage on feature branches | Each Module Owner |
| **T4 — Integration & System** | End-to-end PCAP replay, live WebSocket stream, and alert verification | QA Lead + Module Owners |
| **T5 — Security Hardening** | Bandit/SonarQube zero-finding gate and malformed packet fuzz tests | Ritu (Security Lead) |
| **T6 — Release Sign-off** | Working prototype video demonstration and final STP approval | Whole Team |

---

## 8. Roles and Responsibilities

| Role | Assigned Member | Primary Testing Responsibilities |
| :--- | :--- | :--- |
| **QA Lead** | Tejaswini R Pujar | Overall test strategy, defect tracking, test execution coordination, and parser verification. |
| **DevOps Lead** | Vishal Prasath | CI/CD automation, Docker test containers, capture throughput benchmarks, and hardware deployment. |
| **Security Lead** | Ritu Ravish | Bandit SAST scanning, SonarQube quality gate, packet fuzzing hardening, and detection verification. |
| **Scrum Master** | Varshini A | Requirements traceability, sprint test cadence, dashboard usability, and export verification. |

---

## 9. Test Case Catalogue

The following 23 formal test cases verify functional and non-functional requirements across all project subsystems:

| TC ID | SRS Traceability | Test Objective | Preconditions | Execution Steps | Expected Result | Pass Criteria |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **TC-F1-01** | REQ-F1-01 | Ethernet promiscuous capture | Supported network interface `eth0` and authorized traffic. | 1. Initialize `EthernetCapture(interface='eth0')`.<br>2. Generate unicast frames addressed to other MACs.<br>3. Inspect captured frame output. | Frames are captured regardless of destination MAC; timestamps and interface are populated. | All transmitted packets captured; correct interface tag. |
| **TC-F1-02** | REQ-F1-02 | WiFi monitor channel hopping | Monitor-mode capable WiFi adapter and authorized AP. | 1. Enable monitor capture on `wlan0mon`.<br>2. Observe channel state over multiple hopping cycles. | Channels 1–13 are sequentially visited at configured interval (250ms). | Hopping thread rotates channels without crashing. |
| **TC-F1-03** | REQ-F1-03 | BLE advertisement capture | BlueZ HCI interface `hci0` active. | 1. Start BLE capture worker.<br>2. Transmit BLE advertising packets (`ADV_IND`).<br>3. Verify ingestion stream. | BLE frames captured with MAC, RSSI, and advertising data. | Valid BLE records emitted to parser buffer. |
| **TC-F1-04** | REQ-F1-04 | Remote ESP32 UDP frame ingest | ESP32 probe emitting UDP frames to port 5555. | 1. Open UDP receiver on port 5555.<br>2. Stream remote 802.11 frames from ESP32.<br>3. Verify parser reception. | UDP frames received, stripped of transport wrapper, and queued for decoding. | Zero dropped frames under 500 pkts/sec. |
| **TC-F1-05** | REQ-F1-05 | PCAP session recording & rotation | Active capture session generating traffic. | 1. Configure rotation at 50MB or 15 mins.<br>2. Generate traffic until boundary is reached.<br>3. Validate output files with `tshark`. | Files rotated cleanly with timestamped names; output conforms to valid libpcap format. | `tshark -r <file>` reads rotated PCAPs without corruption. |
| **TC-F2-01** | REQ-F2-01 | Multi-layer protocol decoding | Raw packet fixtures (Ethernet, ARP, IP, TCP, UDP, DNS). | 1. Pass raw frame bytes to `ProtocolParser.parse_frame()`.<br>2. Inspect dissected protocol layers. | Link, network, transport, and application fields accurately extracted. | All protocol fields match Wireshark dissection baseline. |
| **TC-F2-02** | REQ-F2-02 | Schema normalization | Diverse frames (Ethernet, WiFi, BLE). | 1. Pass diverse frames into `normalizer.normalize()`.<br>2. Verify output schema against `NormalizedRecord`. | All frames produce standardized `NormalizedRecord` objects with uniform field types. | 100% conformance to `NormalizedRecord` dataclass. |
| **TC-F2-03** | REQ-F2-03 | Zeek telemetry ingestion | Running Zeek monitor generating `conn.log`. | 1. Stream Zeek log entries to `ZeekIngester`.<br>2. Query SQLite connection records. | Zeek connection records enrich connection metadata table. | Zeek UID and service names correlated with packet records. |
| **TC-F2-04** | REQ-F2-04 | SQLite database persistence | Normalized packet records. | 1. Insert 1,000 normalized records into SQLite store.<br>2. Query by IP, MAC, and timestamp index. | Records inserted efficiently in batches; indexed queries return in $< 10\text{ms}$. | No SQL errors; WAL mode enabled; correct indices built. |
| **TC-F2-05** | REQ-F2-05 | Pluggable parser interface | Custom protocol parser plugin inheriting from `BaseParser`. | 1. Implement and register custom dissector.<br>2. Stream target protocol packets. | Custom dissector invoked seamlessly without core parser modification. | OCP compliance verified; custom payload parsed. |
| **TC-F3-01** | REQ-F3-01 | Dynamic ARP cache poisoning detection | Clean baseline ARP cache. | 1. Register IP `192.168.1.1` to MAC `00:11:22:33:44:01`.<br>2. Ingest conflicting ARP reply claiming same IP with MAC `aa:bb:cc:dd:ee:ff`. | Detection Engine flags conflict and generates `CRITICAL` severity `Alert`. | Alert emitted with offending and authentic MACs in evidence. |
| **TC-F3-02** | REQ-F3-02 | ARP reply flood detection | `ArpSpoofDetector` with threshold 5 replies / 3.0s. | 1. Send burst of 6 gratuitous ARP replies from single MAC in 1.0s.<br>2. Check emitted alerts. | Engine generates `HIGH` severity alert indicating ARP reply flood. | Exact burst count and MAC recorded in alert evidence. |
| **TC-F3-03** | REQ-F3-03 | TCP/UDP port scan detection | `PortScanDetector` with threshold 15 ports / 5.0s. | 1. Stream SYN packets from host to 16 distinct ports within 2.0s.<br>2. Verify port scan rule output. | `HIGH` severity alert generated specifying attacker IP and scanned ports. | Alert generated; horizontal/vertical scan distinguished. |
| **TC-F3-04** | REQ-F3-05 | WiFi deauthentication flood detection | `WifiDeauthDetector` with threshold 10 frames / 2.0s. | 1. Ingest 12 deauthentication frames targeting BSSID within 1.0s.<br>2. Verify rule alert. | `HIGH` severity alert generated with target BSSID, client MAC, and frame count. | Alert contains mitigation advice (PMF 802.11w). |
| **TC-F3-05** | REQ-F3-06 | Rogue & Evil-Twin AP detection | Authorized SSID baseline configured. | 1. Ingest beacon frame broadcasting known SSID from unauthorized BSSID.<br>2. Ingest beacon with downgraded security (OPEN). | Generates `CRITICAL` Evil-Twin alert and `HIGH` security downgrade alert. | Alerts deduplicated to prevent beacon flooding storms. |
| **TC-F3-06** | REQ-F3-07 | BLE advertisement flood detection | `BleFloodDetector` active. | 1. Ingest 25 BLE advertisements from single MAC in 2.0s.<br>2. Ingest frames from 12 distinct random MACs in 2.0s. | Emits BLE Advertisement Flood alert and BLE MAC Churning alert. | Handled incomplete BLE frames without exceptions. |
| **TC-F4-01** | REQ-F4-01, REQ-F4-02 | Live dashboard & WebSocket stream | Running dashboard backend and browser client. | 1. Open `http://<pi>:8000/`.<br>2. Verify WebSocket connection.<br>3. Ingest packets and alerts. | Packets appear in table within 2.0s; alert feed updates dynamically. | Sub-2.0s update latency achieved; connection resilient. |
| **TC-F4-02** | REQ-F4-03 | Device inventory & OUI lookup | Packets containing diverse MAC addresses. | 1. Ingest packets from Apple, Intel, and Raspberry Pi MAC OUIs.<br>2. Open `/api/devices` and dashboard table. | Devices table lists vendor name, first/last seen timestamps, and active protocol. | Known OUIs resolved correctly; unknown defaults safely. |
| **TC-F4-03** | REQ-F4-04 | Multi-interface search and filtering | Database populated with historical records. | 1. Filter by protocol=ARP and interface=eth0.<br>2. Search for specific IP substring. | Query results match applied filter criteria accurately. | Correct SQL WHERE clauses executed; fast pagination. |
| **TC-F4-04** | REQ-F4-05 | Session forensic export | Filtered traffic query. | 1. Request export in PCAP, CSV, and JSON formats.<br>2. Inspect exported file contents. | PCAP readable by Wireshark; CSV/JSON contain valid structured records. | Valid MIME headers; no truncated records. |
| **TC-SEC-01** | SEC-01 | Bandit SAST & SonarQube audit | Complete codebase. | 1. Execute `python -m bandit -r src -c .bandit`.<br>2. Execute SonarQube scan. | Zero High or Medium severity vulnerabilities reported. | CI build step passes cleanly. |
| **TC-SEC-02** | SEC-02 | Packet input fuzzing resilience | `DetectionEngine` input pipeline. | 1. Ingest NaN timestamps, negative ports, giant payloads, non-record objects.<br>2. Observe engine behavior. | Engine drops malformed records safely; increments `malformed_dropped`; zero crashes. | Robust error containment verified (UT_F3_04). |
| **TC-PERF-01** | NFR-PERF-01 | Lossless capture throughput benchmark | Traffic generator streaming frames. | 1. Run `scripts/capture_benchmark.py` at 1,000 to 5,000 pkts/sec for 60s.<br>2. Verify packet loss counters. | Packet drop percentage remains $< 0.1\%$ under target workload. | Sustained throughput achieved without memory leaks. |

---

## 10. Requirements Traceability Matrix (RTM)

This matrix maps each requirement from the Software Requirements Specification (`PPS-SRS-V1.0`) to its architectural component, code file, formal test cases, and verification status:

| Sl. | Requirement ID | Requirement Description | Subsystem | Owner | Code File Reference | Unit Test ID | System / Test Case ID | Status |
| :---: | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :---: |
| 1 | **REQ-F1-01** | Promiscuous Ethernet Capture | Capture | Vishal | `src/capture/ethernet.py` | `UT_F1_01, UT_F1_02` | `TC-F1-01` | **Verified** |
| 2 | **REQ-F1-02** | WiFi Monitor Mode & Hopping | Capture | Vishal | `src/capture/wifi.py` | `UT_F1_02` | `TC-F1-02` | **Verified** |
| 3 | **REQ-F1-03** | BLE Advertisement Capture | Capture | Vishal | `src/capture/ble.py` | `UT_F1_03` | `TC-F1-03` | **Verified** |
| 4 | **REQ-F1-04** | Remote ESP32 Frame Ingest | Capture | Vishal | `src/capture/esp32.py` | `UT_F1_04` | `TC-F1-04` | **Verified** |
| 5 | **REQ-F1-05** | PCAP Session Management & Rotation | Capture | Vishal | `src/capture/session.py` | `UT_F1_03, UT_F1_04` | `TC-F1-05` | **Verified** |
| 6 | **REQ-F2-01** | Multi-Layer Protocol Decoding | Parser | Tejaswini | `src/parser/protocol_parser.py`| `UT_F2_01` | `TC-F2-01` | **Verified** |
| 7 | **REQ-F2-02** | Unified Schema Normalization | Parser | Tejaswini | `src/parser/normalizer.py` | `UT_F2_02` | `TC-F2-02` | **Verified** |
| 8 | **REQ-F2-03** | Zeek Telemetry Ingestion | Parser | Tejaswini | `src/parser/zeek_ingest.py` | `UT_F2_03` | `TC-F2-03` | **Verified** |
| 9 | **REQ-F2-04** | SQLite Database Storage Layer | Parser | Tejaswini | `src/storage/sqlite_store.py` | `UT_F2_04` | `TC-F2-04` | **Verified** |
| 10 | **REQ-F2-05** | Pluggable Parser Interface | Parser | Tejaswini | `src/parser/base.py` | `UT_F2_05` | `TC-F2-05` | **Verified** |
| 11 | **REQ-F3-01** | ARP Cache Poisoning Detection | Detection | Ritu | `src/detection/rules/arp_spoof.py` | `UT_F3_01, UT_F3_02`| `TC-F3-01` | **Verified** |
| 12 | **REQ-F3-02** | ARP Reply Flood Detection | Detection | Ritu | `src/detection/rules/arp_spoof.py` | `UT_F3_03` | `TC-F3-02` | **Verified** |
| 13 | **REQ-F3-03** | TCP/UDP Port Scan Detection | Detection | Ritu | `src/detection/rules/port_scan.py` | `UT_F3_07` | `TC-F3-03` | **Verified** |
| 14 | **REQ-F3-04** | DNS Anomaly & Tunneling | Detection | Ritu | `src/detection/rules/dns_anomaly.py`| `UT_F3_08` | `TC-F3-01` | **Verified** |
| 15 | **REQ-F3-05** | WiFi 802.11 Deauth Flood Detection | Detection | Ritu | `src/detection/rules/wifi_deauth.py`| `UT_F3_09` | `TC-F3-04` | **Verified** |
| 16 | **REQ-F3-06** | Rogue & Evil-Twin AP Detection | Detection | Ritu | `src/detection/rules/rogue_ap.py` | `UT_F3_10` | `TC-F3-05` | **Verified** |
| 17 | **REQ-F3-07** | BLE Advertisement Flood & Spoofing | Detection | Ritu | `src/detection/rules/ble_flood.py` | `UT_F3_11` | `TC-F3-06` | **Verified** |
| 18 | **REQ-F3-08** | Configurable Dynamic Thresholds | Detection | Ritu | `src/detection/config.py` | `UT_F3_12` | `TC-F3-01` | **Verified** |
| 19 | **REQ-F3-09** | Standardized Alert Schema | Detection | Ritu | `src/detection/models.py` | `UT_F3_05` | `TC-F3-01` | **Verified** |
| 20 | **REQ-F3-10** | Pluggable Rule Engine Core | Detection | Ritu | `src/detection/engine.py` | `UT_F3_05, UT_F3_06`| `TC-F3-01` | **Verified** |
| 21 | **REQ-F4-01** | REST & WebSocket Backend API | Dashboard | Varshini | `src/dashboard/routes/` | `UT_F4_01` | `TC-F4-01` | **Verified** |
| 22 | **REQ-F4-02** | Live Web Dashboard & Visuals | Dashboard | Varshini | `src/dashboard/static/` | `UT_F4_02` | `TC-F4-01` | **Verified** |
| 23 | **REQ-F4-03** | Device Inventory & MAC Lookup | Dashboard | Varshini | `src/dashboard/routes/devices.py`| `UT_F4_03` | `TC-F4-02` | **Verified** |
| 24 | **REQ-F4-04** | Search, Filtering & History | Dashboard | Varshini | `src/dashboard/routes/packets.py`| `UT_F4_04` | `TC-F4-03` | **Verified** |
| 25 | **REQ-F4-05** | Session Export (PCAP/CSV/JSON) | Dashboard | Varshini | `src/dashboard/routes/export.py` | `UT_F4_05` | `TC-F4-04` | **Verified** |
| 26 | **SEC-01** | Bandit & SonarQube SAST | Security | Ritu | `.bandit`, `sonar-project.properties` | - | `TC-SEC-01` | **Verified** |
| 27 | **SEC-02** | Resilient Packet Processing | Security | Ritu | `src/detection/engine.py` | `UT_F3_04` | `TC-SEC-02` | **Verified** |
| 28 | **NFR-PERF-01** | Lossless Capture at Lab Rates | Quality | Vishal | `scripts/capture_benchmark.py` | `UT_F1_01` | `TC-PERF-01` | **Verified** |
| 29 | **NFR-PORT-01** | Raspberry Pi Docker & systemd | DevOps | Vishal | `Dockerfile`, `docker-compose.yml` | - | `TC-DEPLOY-01`| **Verified** |
| 30 | **NFR-USE-01** | Phone-Friendly Mobile Layout | Frontend | Varshini | `src/dashboard/static/` | `UT_F4_02` | `TC-F4-01` | **Verified** |

---

## 11. Approvals and Sign-Off

The baseline Software Test Plan and Requirements Traceability Matrix are formally approved:

| Role | Team Member Name | Status / Signature | Date |
| :--- | :--- | :--- | :--- |
| **Lead Consolidator & Security Lead** | Ritu Ravish | **Approved (V1.0 Baseline)** | October 29, 2026 |
| **QA Lead** | Tejaswini R Pujar | **Approved (V1.0 Baseline)** | October 29, 2026 |
| **DevOps Lead** | Vishal Prasath | **Approved (V1.0 Baseline)** | October 29, 2026 |
| **Scrum Master** | Varshini A | **Approved (V1.0 Baseline)** | October 29, 2026 |
