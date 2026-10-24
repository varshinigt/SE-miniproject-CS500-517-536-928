# Deviations from Submitted Documents

Record any change from the submitted SRS, SAD or Test Plan here. Each owner notes their own.

| Date | Owner | Document & Section | What changed | Why |
| :--- | :--- | :--- | :--- | :--- |
| 2026-10-24 | Varshini A | SRS - F4 Live Monitoring (FR-F4-01) | Dashboard refreshes by polling the API every second instead of using a WebSocket push | Polling is simpler and reliable for the Sprint 1 demo. WebSocket push is planned for Sprint 2 (issue #6) | 
| 2026-10-24 | Varshini A | SAD - Data layer for F4 | The dashboard uses its own SQLite schema (packets, alerts) and demo seed data | The capture and detection modules are not integrated yet. The schema will be aligned with the shared model during integration | 
| 2026-10-24 | Varshini A | SRS - NFR-PERF-03 (dashboard latency) | Update latency under 1 second has not been measured yet | Measurement needs live capture input. It will be measured and reported in Sprint 2 (issue #12) | 
