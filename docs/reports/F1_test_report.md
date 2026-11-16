# F1 Packet Capture: Unit Test and Coverage Report

**Owner:** Vishal Prasath
**Module:** `src/capture`
**Run date:** 2026-11-17 (updated after PR #78)
**Environment:** macOS, Python 3.9.6, pytest 8.3.5, pytest-cov 7.1.0

## Files in this report

| File | Contents |
| :--- | :--- |
| `F1_unit_and_coverage_report.txt` | Full pytest console output with per-file line and branch coverage |
| `F1_unit_tests.xml` | JUnit XML test results |
| `F1_coverage.xml` | Cobertura coverage XML (line and branch) |

To regenerate:

```bash
pytest tests/unit/test_ethernet_capture.py tests/unit/test_wifi_capture.py \
  tests/unit/test_ble_capture.py tests/unit/test_esp32_ingest.py \
  tests/unit/test_pcap_session.py tests/unit/test_capture_stats.py \
  tests/unit/test_packet_queue.py tests/unit/test_capture_runner.py tests/performance \
  -v --cov=src/capture --cov-branch --cov-report=term-missing \
  --cov-report=xml:docs/reports/F1_coverage.xml \
  --junitxml=docs/reports/F1_unit_tests.xml
```

## Result

**85 tests, 85 passed, 0 failed, 0 skipped.**

## Tests by requirement

| Requirement | Test file | Tests | Result |
| :--- | :--- | :---: | :--- |
| REQ-F1-01 Promiscuous Ethernet capture | `tests/unit/test_ethernet_capture.py` | 9 | Pass |
| REQ-F1-02 WiFi monitor mode and channel hopping | `tests/unit/test_wifi_capture.py` | 12 | Pass |
| REQ-F1-03 BLE advertisement capture | `tests/unit/test_ble_capture.py` | 9 | Pass |
| REQ-F1-04 Remote ESP32 UDP ingestion | `tests/unit/test_esp32_ingest.py` | 9 | Pass |
| REQ-F1-05 PCAP session recording and rotation | `tests/unit/test_pcap_session.py` | 10 | Pass |
| NFR-PERF-01 Capture statistics and loss tracking | `tests/unit/test_capture_stats.py` | 11 | Pass |
| NFR-PERF-02 Bounded capture queue | `tests/unit/test_packet_queue.py` | 10 | Pass |
| NFR-PERF-02 Queue throughput | `tests/performance/test_packet_queue_performance.py` | 1 | Pass |
| NFR-PORT-01 Capture service runner | `tests/unit/test_capture_runner.py` | 14 | Pass |
| **Total** | | **85** | |

## Coverage (line and branch)

| File | Statements | Missed | Branches | Partial | Coverage |
| :--- | ---: | ---: | ---: | ---: | ---: |
| `src/capture/__init__.py` | 8 | 0 | 0 | 0 | 100% |
| `src/capture/__main__.py` | 3 | 0 | 0 | 0 | 100% |
| `src/capture/ble.py` | 72 | 1 | 14 | 0 | 99% |
| `src/capture/esp32.py` | 127 | 10 | 28 | 5 | 90% |
| `src/capture/ethernet.py` | 71 | 1 | 14 | 1 | 98% |
| `src/capture/packet_queue.py` | 66 | 0 | 20 | 0 | 100% |
| `src/capture/runner.py` | 110 | 0 | 26 | 0 | 100% |
| `src/capture/session.py` | 74 | 1 | 12 | 1 | 98% |
| `src/capture/stats.py` | 45 | 0 | 4 | 0 | 100% |
| `src/capture/wifi.py` | 115 | 3 | 28 | 2 | 97% |
| **Total** | **691** | **16** | **146** | **9** | **97%** |

This is above the project threshold of 85% (NFR-QA-01). The lowest file, `esp32.py` at 90%, has uncovered lines mostly in socket error handling and worker shutdown paths.

## Limits of this report

- These are unit tests. Interfaces, sockets and HCI devices are mocked, so no real traffic was captured.
- The NFR-PERF-01 loss benchmark (`scripts/capture_benchmark.py`) has not been run on a Raspberry Pi 4 yet. See `docs/Deviations.md`.
- Over-the-air checks (TC-F1-01 to TC-F1-05 in `docs/TestPlan.md`) need the Pi, a monitor-mode WiFi adapter and an ESP32 node.
