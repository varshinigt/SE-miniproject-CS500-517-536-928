# Sprint 1 Report (19-23 Oct)

**Sprint goal:** one working end-to-end slice: Ethernet traffic captured, parsed, stored, checked by detection rules and shown on the dashboard.

## F4 Dashboard: planned work

| Issue | SRS ID | Story | Points | Status |
| :--- | :--- | :--- | :--- | :--- |
| #1 | FR-F4-01 | REST API skeleton with health endpoint | 2 | PR open |
| #2 | FR-F4-01 | Packets endpoint reading from SQLite | 3 | PR open |
| #3 | FR-F4-01 | Alerts endpoint | 2 | PR open |
| #4 | FR-F4-02 | Dashboard page with live packet table | 5 | PR open |
| #5 | FR-F4-02 | Alert feed panel | 3 | PR open |
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

## Team velocity

Fill in from the Project board (Project -> Insights) after the PRs are merged.

| Member | Points planned | Points completed |
| :--- | :--- | :--- |
| Vishal Prasath | | |
| Tejaswini R Pujar | | |
| Ritu Ravish | 15 | 15 |
| Varshini A | 15 | |
| **Team** | | |

## What went well / what to improve

### F3 Threat Detection (Ritu Ravish)
- **What went well:**
  - Decoupled `DetectionEngine` from individual rules via the `BaseDetector` strategy pattern, making rules modular and independently testable.
  - Achieved high unit test coverage across ARP spoofing, ARP reply flooding, and TCP/UDP port scanning rules with sliding-window time eviction and memory bounding.
  - Maintained zero high-severity Bandit SAST warnings and compliant flake8 linting in CI.
- **What to improve:**
  - Wire the detection engine directly to the F2 parser stream queue and persist generated alerts to the shared SQLite database instead of using in-memory callbacks.
  - Move hardcoded rule thresholds from constructor defaults into a centralized configuration module (`src/detection/config.py`).

