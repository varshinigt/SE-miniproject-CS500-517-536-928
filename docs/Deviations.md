# Deviations from Submitted Documents

Record any change from the submitted SRS, SAD or Test Plan here. Each owner notes their own.

| Date | Owner | Document & Section | What changed | Why |
| :--- | :--- | :--- | :--- | :--- |
| 2026-10-24 | Varshini A | SRS - F4 Live Monitoring (FR-F4-01) | Dashboard refreshes by polling the API every second instead of using a WebSocket push | Polling is simpler and reliable for the Sprint 1 demo. WebSocket push is planned for Sprint 2 (issue #6) | 
| 2026-10-24 | Varshini A | SAD - Data layer for F4 | The dashboard uses its own SQLite schema (packets, alerts) and demo seed data | The capture and detection modules are not integrated yet. The schema will be aligned with the shared model during integration | 
| 2026-10-24 | Varshini A | SRS - NFR-PERF-03 (dashboard latency) | Update latency under 1 second has not been measured yet | Measurement needs live capture input. It will be measured and reported in Sprint 2 (issue #12) | 
| 2026-10-27 | Vishal Prasath | SRS - NFR-PERF-01 (lossless capture) | Sprint 1 target is 1,000 packets per second for 60 seconds, not the 5,000 packets per second stated in the SRS | The Sprint 1 story (#30) sets the lower rate for a first measurement. The 5,000 pps target stays for the final validation | 
| 2026-10-27 | Vishal Prasath | SAD - F1 capture statistics | Dropped packets are read from the NIC counters in `/sys/class/net/<iface>/statistics` instead of libpcap statistics | Works with Scapy without extra bindings. The drop count is reported as unknown on non-Linux machines | 
| 2026-10-27 | Vishal Prasath | SRS - NFR-PERF-01 measurement | The packet loss test has not been run on the Raspberry Pi yet. `scripts/capture_benchmark.py` is ready to run there | No Pi was available during development, so the result will be added to the test report once measured | 
| 2026-10-27 | Vishal Prasath | SRS - F1 (REQ-F1-02, F1-03, F1-04) | WiFi monitor mode, BLE and ESP32 ingestion are planned for Sprint 2 (issues #31, #32, #33) | Sprint 1 focused on the Ethernet to PCAP baseline, which the other modules depend on | 
