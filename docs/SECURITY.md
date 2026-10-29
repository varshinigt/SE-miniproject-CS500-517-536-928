# Security & Static Analysis Architecture (SEC-01, SEC-02)
**Pocket Packet Sniffer (Version 1.0)**<br>
**Security Lead:** Ritu Ravish<br>
**Course:** Software Engineering (UE24CS341A) — PES University

---

## 1. Overview
The Pocket Packet Sniffer processes raw, untrusted network frames from promiscuous Ethernet, monitor-mode WiFi, and Bluetooth Low Energy interfaces. Operating at the boundary of hostile network environments requires rigorous software security controls:
1. **Automated Static Application Security Testing (SAST):** Scans codebase for vulnerabilities (insecure deserialization, hardcoded secrets, shell injections, unsafe randomness) using **Bandit**.
2. **Quality & Security Gate (SonarQube):** Continuously measures code smells, security hotspots, cognitive complexity, and test coverage.
3. **Resilient Packet Processing & Fuzz Hardening (SEC-02):** Strict schema validation on incoming `NormalizedRecord` objects, boundary checks on timestamps, ports, and payload lengths, and isolated rule execution ensuring no single malformed frame halts the inspection pipeline.

---

## 2. Bandit SAST Configuration & Execution

### 2.1 Configuration (`.bandit`)
The project utilizes a centralized `.bandit` configuration file at repository root:
* **Target Scanned:** `src/` (all production source code across capture, parser, detection, storage, and dashboard).
* **Excluded Directories:** `tests/`, `demo/`, `scripts/`.
* **Ignored Checks:** `B101` (assert statements in test harnesses).

### 2.2 Running Bandit Locally
Developers can execute Bandit locally prior to raising Pull Requests:
```bash
# Run Bandit with configuration file
bandit -r src -c .bandit

# Alternatively via Python module
python -m bandit -r src -c .bandit
```

### 2.3 Bandit Security Policy & Remediation
* **Severity Threshold:** High and Medium severity findings block CI build execution.
* **Common Vulnerability Patterns:**
  * *B311 (Pseudo-random number generator):* Use `secrets.SystemRandom` for cryptographic tokens, session IDs, and security salts instead of default `random`.
  * *B608 (SQL Injection):* Use parameterized queries (`?` in SQLite) rather than f-string formatted SQL queries.
  * *B105/B106 (Hardcoded Passwords):* Pass credentials via environment variables or secure configuration files.

---

## 3. SonarQube Scanner Integration

### 3.1 Configuration (`sonar-project.properties`)
SonarQube is configured via `sonar-project.properties`:
* **Project Key:** `pocket-packet-sniffer`
* **Sources:** `src`
* **Tests:** `tests`
* **Coverage Report:** `coverage.xml` (generated via `pytest --cov=src --cov-report=xml`)
* **Python Target Version:** `3.11`

### 3.2 Running SonarQube Scanner
```bash
# Generate test coverage report
pytest --cov=src --cov-branch --cov-report=xml

# Run SonarScanner (in CI or local environment)
sonar-scanner -Dsonar.login=<SONARQUBE_TOKEN>
```

---

## 4. Packet Input Hardening & Fuzz Resilience (SEC-02)

### 4.1 Validation Layers (`DetectionEngine.validate_record`)
All packet records ingested by `DetectionEngine` undergo boundary verification before being dispatched to detection rules:
* **Type Safety:** Rejects non-`NormalizedRecord` objects.
* **Timestamp Sanitation:** Drops `NaN`, `+Inf`, `-Inf`, negative timestamps, and far-future epoch values (> year 2096).
* **String Bounds:** Limits interface names to <= 64 characters and link types to <= 32 characters.
* **Port Boundaries:** Validates `0 <= port <= 65535`.
* **Payload Length Limits:** Enforces `0 <= payload_len <= 1,048,576` bytes.

### 4.2 Error Containment & Logging
* If an individual rule encounters an unhandled runtime error, the engine catches the exception, logs it safely without exposing sensitive raw payload bytes, and proceeds to evaluate remaining detectors and subsequent packets.
* Engine tracks operational health metrics via `engine.get_stats()`:
  * `total_processed`: Count of successfully validated records.
  * `malformed_dropped`: Count of rejected malformed or fuzzed records.
  * `total_alerts`: Cumulative alerts emitted.
