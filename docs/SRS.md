# Software Requirements Specification (SRS)

## 1. Introduction
### 1.1 Purpose
To be defined during the requirements phase.

### 1.2 Intended Audience
To be defined during the requirements phase.

### 1.3 Product Scope
To be defined during the requirements phase.

### 1.4 References
To be defined during the requirements phase.

## 2. Overall Description
### 2.1 Product Perspective
To be defined during the requirements phase.

### 2.2 Product Functions
To be defined during the requirements phase.

### 2.3 User Classes and Characteristics
To be defined during the requirements phase.

### 2.4 Operating Environment
To be defined during the requirements phase.

### 2.5 Design and Implementation Constraints
To be defined during the requirements phase.

### 2.6 Assumptions and Dependencies
To be defined during the requirements phase.

## 3. External Interface Requirements
### 3.1 User Interfaces
To be defined during the requirements phase.

### 3.2 Software Interfaces
#### 3.2.1 F3 Threat Detection Interfaces (Owner: Ritu Ravish)
* **Input Interface (F2 -> F3):** Ingests unified `NormalizedRecord` objects from the Protocol Parser (`src/parser`), providing link-layer, network-layer, transport-layer fields, and protocol-specific metadata across Ethernet, WiFi, and BLE.
* **Output Interface (F3 -> F4):** Dispatches structured `Alert` objects (serialized as dictionary/JSON) to the Live Monitoring Dashboard (`src/dashboard`) via pub/sub queue or WebSocket channel.

*(Software interfaces for F1, F2, and F4 to be defined by respective owners during requirements phase)*

### 3.3 Communication Interfaces
To be defined during the requirements phase.

## 4. Analysis Models
To be defined during the requirements phase.

## 5. System Features

### 5.1 System Feature 1: Multi-Interface Packet Capture (Owner: Vishal Prasath)
To be defined during the requirements phase.

### 5.2 System Feature 2: Protocol Parsing and Zeek Integration (Owner: Tejaswini R Pujar)
To be defined during the requirements phase.

### 5.3 System Feature 3: Threat and Anomaly Detection with Alerting (Owner: Ritu Ravish)

#### 5.3.1 Description and Priority
* **Description:** An extensible, pluggable rule-based detection engine that continuously inspects the normalized packet stream across Ethernet, WiFi, and Bluetooth Low Energy interfaces to identify network cyberattacks, protocol anomalies, and rogue entities in real time.
* **Priority:** High. (Benefit: 9, Penalty: 8, Cost: 5, Risk: 6)

#### 5.3.2 Stimulus/Response Sequences
1. **Stimulus:** F2 Parser streams a normalized ARP reply where the claimed IP is bound to a new, conflicting MAC address.
   * **Response:** Detection Engine flags an IP-MAC conflict, generates a `CRITICAL` severity `Alert` object with offending MAC addresses and timestamps, and emits it to the alert dispatch pipeline within 1 second.
2. **Stimulus:** A remote host sends SYN packets across 20 distinct destination ports within a 2-second sliding window.
   * **Response:** Detection Engine flags a horizontal/vertical port scan, generates a `HIGH` severity `Alert` containing the attacker IP, scanned port range, and packet counts.
3. **Stimulus:** A WiFi client receives bursts of 802.11 Deauthentication frames (subtype 0x000C) exceeding 15 frames per second.
   * **Response:** Detection Engine flags a WiFi Deauth Flood attack, generates a `CRITICAL` severity `Alert` detailing targeted BSSID, client MAC, and frame rate.
4. **Stimulus:** An unrecognized BLE peripheral transmits excessive advertisement packets (`ADV_IND`) exceeding the configured rate threshold.
   * **Response:** Detection Engine flags a BLE Advertisement Flood / DoS, generates a `MEDIUM` severity `Alert` with advertiser MAC and burst volume.

#### 5.3.3 Functional Requirements
* **REQ-F3-01 (ARP Spoofing / Cache Poisoning Detection):**
  The system shall maintain a dynamic IP-to-MAC baseline table and detect when an incoming ARP packet attempts to associate an existing IP with an unauthorized or conflicting MAC address.
* **REQ-F3-02 (ARP Reply Flood Detection):**
  The system shall monitor the rate of unsolicited/gratuitous ARP replies per MAC address and generate an alert if the count exceeds configurable threshold $N$ within sliding window $T$ seconds (default: 5 replies in 3s).
* **REQ-F3-03 (TCP/UDP Port Scan Detection):**
  The system shall track connection attempts from source IP addresses across multiple destination ports within a configurable sliding window and trigger an alert upon detecting horizontal sweeps or vertical port scans.
* **REQ-F3-04 (DNS Anomaly & Tunneling Detection):**
  The system shall analyze DNS query frequency, domain label length, entropy, and NXDOMAIN error ratios to detect DNS tunneling, domain generation algorithms (DGA), and high-volume DNS reconnaissance.
* **REQ-F3-05 (WiFi 802.11 Deauthentication Flood Detection):**
  The system shall monitor 802.11 management frames (subtypes 0x000C Deauth and 0x000A Disassoc) and trigger an alert if the frame rate directed at or broadcast by an AP exceeds the configurable flood threshold.
* **REQ-F3-06 (Rogue and Evil-Twin AP Detection):**
  The system shall inspect beacon and probe response frames to detect duplicate SSIDs operating with unexpected BSSIDs, differing channel configurations, or degraded encryption suites.
* **REQ-F3-07 (BLE Advertisement Flood & Spoofing Detection):**
  The system shall inspect Bluetooth Low Energy advertisement packets (`ADV_IND`, `ADV_NONCONN_IND`) to identify rapid MAC churning and high-rate advertising bursts indicating DoS or device spoofing.
* **REQ-F3-08 (Configurable Thresholds & Sliding Time Windows):**
  The system shall permit fine-tuning of rate thresholds, detection windows, whitelist IP/MAC entries, and rule activation states through a structured configuration file or API without recompilation.
* **REQ-F3-09 (Standardized Alert Generation and Evidence Packaging):**
  The system shall package every detected anomaly into a structured `Alert` schema including unique `alert_id`, epoch `timestamp`, `threat_type`, `severity` (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`), `evidence` dictionary, and `mitigation` guidance.
* **REQ-F3-10 (Pluggable Detection Rule Engine Architecture):**
  The system shall provide an extensible `BaseDetector` interface and `DetectionEngine` coordinator allowing detection rules to be dynamically registered, executed, and reset without modifying core pipeline code.

### 5.4 System Feature 4: Live Monitoring, Device Inventory and Reporting (Owner: Varshini A)
To be defined during the requirements phase.

## 6. Non-Functional Requirements

### 6.1 Performance
To be defined during the requirements phase.

### 6.2 Security Requirements (Lead: Ritu Ravish)
* **SEC-01 (Static Application Security Testing):**
  All codebase modules shall be scanned via **Bandit** (for Python vulnerabilities such as unsafe deserialization, hardcoded secrets, shell injection) and **SonarQube**, maintaining zero high-severity or critical vulnerabilities before PR merge.
* **SEC-02 (Resilient & Safe Packet Ingestion):**
  The detection engine shall enforce defensive data parsing and exception boundaries for every detector rule. Malformed, truncated, or deliberately corrupted network packets shall be caught and logged safely without causing memory leaks, thread starvation, or crash denial-of-service.
* **SEC-03 (Dependency Vulnerability Governance):**
  Third-party dependencies listed in `requirements.txt` shall undergo automated vulnerability auditing using `pip-audit` to prevent the introduction of known Common Vulnerabilities and Exposures (CVEs).
* **SEC-04 (Alert Data Integrity):**
  Alert records and evidence structures generated by the detection engine shall be immutable once created, ensuring forensically valid evidentiary records for network administrators.

### 6.3 Software Quality Attributes
To be defined during the requirements phase.

## 7. Other Requirements
To be defined during the requirements phase.

## 8. Appendix

### Appendix A: Glossary
* **ARP:** Address Resolution Protocol (RFC 826)
* **BLE:** Bluetooth Low Energy (Bluetooth 4.0+)
* **BSSID:** Basic Service Set Identifier (MAC address of wireless access point)
* **Deauth Attack:** 802.11 Deauthentication frame injection to forcibly disconnect clients
* **MITM:** Man-In-The-Middle attack
* **OCP:** Open/Closed Principle (SOLID software design)

### Appendix B: Field Layouts

#### F3 Alert Schema (Owner: Ritu Ravish)
| Field Name | Data Type | Description | Mandatory | Example |
| :--- | :--- | :--- | :--- | :--- |
| `alert_id` | String (UUID4) | Unique identifier for each alert instance | Y | `c3a7e4b2-8f1d-4e92-a16f-123456789abc` |
| `timestamp` | Float | Epoch timestamp in seconds | Y | `1728087600.125` |
| `threat_type` | Enum / String | Classification of detected attack | Y | `ARP_SPOOFING` |
| `severity` | Enum / String | Risk severity (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`) | Y | `CRITICAL` |
| `title` | String | Human-readable title of alert | Y | `ARP Cache Poisoning Detected` |
| `description` | String | Contextual explanation of anomaly | Y | `Host claiming IP with conflicting MAC` |
| `source_interface` | String | Network interface where traffic was captured | Y | `eth0` |
| `evidence` | JSON / Dict | Key-value dictionary containing observed metrics | Y | `{"claimed_ip": "192.168.1.1", ...}` |
| `mitigation` | String | Recommended defensive / remediation action | Y | `Enable Dynamic ARP Inspection (DAI)` |

*(Other field layouts to be added by respective module owners)*

### Appendix C: Requirement Traceability Matrix (RTM)

| Sl. No | Requirement ID | Brief Description of Requirement | Architecture Reference | Design Reference | Code File Reference | Test Case ID | System Test Case ID |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| 1 | REQ-F3-01 | ARP Cache Poisoning Detection | SDD Section 3.3 | UML Class: ArpSpoof | `src/detection/rules/arp_spoof.py` | UT_F3_01, UT_F3_02 | ST_F3_01 |
| 2 | REQ-F3-02 | ARP Reply Flood Detection | SDD Section 3.3 | UML Class: ArpSpoof | `src/detection/rules/arp_spoof.py` | UT_F3_03 | ST_F3_01 |
| 3 | REQ-F3-03 | TCP/UDP Port Scan Detection | SDD Section 3.3 | UML Class: PortScan | `src/detection/rules/port_scan.py` | UT_F3_07 | ST_F3_02 |
| 4 | REQ-F3-04 | DNS Anomaly & Tunneling | SDD Section 3.3 | UML Class: DnsAnomaly | `src/detection/rules/dns_anomaly.py` | UT_F3_08 | ST_F3_03 |
| 5 | REQ-F3-05 | WiFi 802.11 Deauth Flood | SDD Section 3.3 | UML Class: WifiDeauth | `src/detection/rules/wifi_deauth.py` | UT_F3_09 | ST_F3_04 |
| 6 | REQ-F3-06 | Rogue & Evil-Twin AP | SDD Section 3.3 | UML Class: RogueAp | `src/detection/rules/rogue_ap.py` | UT_F3_10 | ST_F3_05 |
| 7 | REQ-F3-07 | BLE Flood & Spoofing | SDD Section 3.3 | UML Class: BleFlood | `src/detection/rules/ble_flood.py` | UT_F3_11 | ST_F3_06 |
| 8 | REQ-F3-08 | Configurable Thresholds | SDD Section 3.3 | UML Class: Config | `src/detection/config.py` | UT_F3_12 | ST_F3_07 |
| 9 | REQ-F3-09 | Standardized Alert Schema | SDD Section 3.3 | UML Class: Alert | `src/detection/models.py` | UT_F3_05 | ST_F3_08 |
| 10 | REQ-F3-10 | Pluggable Rule Engine Core | SDD Section 3.3 | UML Class: BaseDetector | `src/detection/engine.py` | UT_F3_05, UT_F3_06 | ST_F3_09 |

*(Requirements for F1, F2, and F4 to be populated by respective owners)*
