"""
Build 02_STP_Pocket_Packet_Sniffer.docx following PES University Software Test Plan Specification
"""

import os
import sys
from docx import Document
from docx.shared import Inches, Pt, RGBColor
from docx.enum.text import WD_ALIGN_PARAGRAPH

sys.path.insert(0, os.path.abspath("."))
from scripts.docx_helpers import add_header_block, style_table, DELIVERABLES_DIR

def build_stp_document():
    doc = Document()

    for s in doc.sections:
        s.top_margin = Inches(0.8)
        s.bottom_margin = Inches(0.8)
        s.left_margin = Inches(0.8)
        s.right_margin = Inches(0.8)

    add_header_block(
        doc,
        title="Software Test Plan (STP)",
        subtitle="Pocket Packet Sniffer — Multi-Interface Testing Strategy and Verification Specification",
        doc_ref="Document ID: PPS-STP-V1.0"
    )

    def add_h1(text):
        h = doc.add_paragraph()
        h.paragraph_format.space_before = Pt(14)
        h.paragraph_format.space_after = Pt(4)
        r = h.add_run(text)
        r.font.name = "Arial"
        r.font.size = Pt(14)
        r.font.bold = True
        r.font.color.rgb = RGBColor(26, 35, 126)

    def add_h2(text):
        h = doc.add_paragraph()
        h.paragraph_format.space_before = Pt(10)
        h.paragraph_format.space_after = Pt(3)
        r = h.add_run(text)
        r.font.name = "Arial"
        r.font.size = Pt(11.5)
        r.font.bold = True
        r.font.color.rgb = RGBColor(13, 71, 161)

    def add_p(text):
        p = doc.add_paragraph()
        p.paragraph_format.space_after = Pt(4)
        r = p.add_run(text)
        r.font.size = Pt(9.5)
        return p

    def add_bullet(bold_prefix, text):
        p = doc.add_paragraph(style='List Bullet')
        p.paragraph_format.space_after = Pt(2)
        r1 = p.add_run(bold_prefix)
        r1.font.bold = True
        r1.font.size = Pt(9.5)
        r2 = p.add_run(text)
        r2.font.size = Pt(9.5)

    # 1. Introduction
    add_h1("1. Introduction")
    add_h2("1.1 Purpose")
    add_p("This Software Test Plan defines how Pocket Packet Sniffer (PPS v1.0) will be verified against the Software Requirements Specification (PPS-SRS-V1.0). It establishes test scope, test levels, execution environments, security validation procedures, case management, defect tracking, and release entry/exit criteria.")
    add_h2("1.2 Scope")
    add_p("Testing encompasses all four functional subsystems: F1 Multi-Interface Capture, F2 Protocol Parsing, Normalization and Zeek Ingestion, F3 Pluggable Threat Detection and Alerting, and F4 Live Dashboard, API, Inventory and Export. It also covers performance throughput, portability on Raspberry Pi, and static security analysis.")
    add_h2("1.3 References and Definitions")
    add_bullet("PPS-SRS-V1.0: ", "Software Requirements Specification for Pocket Packet Sniffer.")
    add_bullet("PCAP: ", "Standard libpcap network packet capture format.")
    add_bullet("SAST: ", "Static Application Security Testing (Bandit / SonarQube).")
    add_bullet("RTM: ", "Requirements Traceability Matrix.")

    # 2. Test Items
    add_h1("2. Test Items")
    add_bullet("F1 Capture Components: ", "Promiscuous Ethernet, WiFi monitor mode with channel hopping, BLE advertisement ingestion, ESP32 UDP receiver, and PCAP rotation manager.")
    add_bullet("F2 Parsing & Storage Components: ", "Multi-layer L2-L7 protocol dissectors, Unified schema normalizer, Zeek connection log ingester, and SQLite WAL database layer.")
    add_bullet("F3 Detection Components: ", "Pluggable BaseDetector framework, sliding-window state trackers, rules for ARP spoofing, TCP/UDP port scans, WiFi deauth floods, Rogue APs, and BLE flood detection.")
    add_bullet("F4 Monitoring Components: ", "FastAPI REST endpoints, live WebSocket hub, web UI packet table, alert feed, device inventory, and PCAP/CSV/JSON export facilities.")
    add_bullet("DevOps & CI Pipeline: ", "Automated GitHub Actions workflow, Bandit security scans, SonarQube quality gate, and Docker Pi deployment scripts.")

    # 3. Features to be Tested
    add_h1("3. Features to be Tested")
    add_p("Table 3.1 itemizes functional and non-functional requirement areas targeted for formal test verification:")
    t_feat = doc.add_table(rows=8, cols=3)
    t_feat_data = [
        ["Subsystem / Area", "SRS Requirements Covered", "Verification Focus & Objectives"],
        ["Capture Subsystem", "REQ-F1-01 to REQ-F1-05", "Promiscuous capture, channel hopping, BLE/ESP32 ingestion, PCAP rotation."],
        ["Parsing & Storage", "REQ-F2-01 to REQ-F2-05", "Protocol field extraction, unified normalization, Zeek logs, indexed SQLite schema."],
        ["Threat Detection", "REQ-F3-01 to REQ-F3-10", "Attack injection tests, sliding-window thresholds, BaseDetector plugins, alert evidence."],
        ["Dashboard & API", "REQ-F4-01 to REQ-F4-05", "REST CRUD operations, WebSocket live updates, device inventory lookup, export formats."],
        ["Performance", "NFR-PERF-01 to NFR-PERF-03", "5,000 pkts/sec load, parser queue <= 10,000 depth, dashboard update latency <= 2.0s."],
        ["Security Validation", "SEC-01 to SEC-04", "Bandit SAST, SonarQube scans, pip-audit CVE check, malformed packet fuzzing."],
        ["Usability & Portability", "NFR-USE-01, NFR-PORT-01, NFR-QA-01", "Mobile layout (375px), Raspberry Pi Docker/systemd autostart, >= 85% code coverage."],
    ]
    for r_idx, row in enumerate(t_feat_data):
        for c_idx, val in enumerate(row):
            t_feat.cell(r_idx, c_idx).text = val
    style_table(t_feat, header_bg="1A237E", alt_bg="F1F5F9")
    doc.add_paragraph().paragraph_format.space_after = Pt(6)

    # 4. Features Not to be Tested
    add_h1("4. Features Not to be Tested")
    add_bullet("Hardware Firmware Flashing: ", "Physical ESP32 flashing over UART is considered an external prerequisite.")
    add_bullet("Wireless Hardware Radio Frequency: ", "Physical antenna gain and RF attenuation are assumed nominal.")
    add_bullet("Third-Party Kernel Modules: ", "Underlying Linux kernel network drivers are trusted without kernel modification.")

    # 5. Test Approach and Strategy
    add_h1("5. Test Approach and Strategy")
    add_h2("5.1 Levels of Testing")
    add_bullet("Unit Testing (UT): ", "Conducted using Python unittest / pytest. Validates individual classes, detectors, and parsers in isolation with mock synthetic packets.")
    add_bullet("Integration Testing (IT): ", "Validates data contracts across boundaries: Capture -> Parser -> Detection -> Storage -> Dashboard API.")
    add_bullet("System Testing (ST): ", "End-to-end execution on Raspberry Pi 4 hardware, replaying attack PCAP files and verifying live alerts and dashboard rendering.")

    add_h2("5.2 Entry and Exit Criteria")
    add_bullet("Entry Criteria: ", "Code compiles and passes linting; unit test suite executes cleanly on local branch before PR creation.")
    add_bullet("Exit Criteria: ", "100% of planned test cases executed; 0 high-severity open defects; >= 85% line and branch test coverage achieved; Bandit SAST clean.")

    add_h2("5.3 Security Validation (Lead: Ritu Ravish)")
    add_bullet("Static Analysis: ", "Automated Bandit scan executed on every commit to flag insecure deserialization, hardcoded credentials, and shell injection risks.")
    add_bullet("Dependency Auditing: ", "`pip-audit` checks all third-party libraries in requirements.txt against the National Vulnerability Database (NVD).")
    add_bullet("Malformed Input Fuzzing: ", "Truncated, corrupted, and oversized packet frames injected into the parser and detection pipeline to confirm zero crash denial-of-service.")

    # 6. Test Environment
    add_h1("6. Test Environment")
    t_env = doc.add_table(rows=7, cols=2)
    t_env_data = [
        ["Environment Attribute", "Planned Configuration & Tools"],
        ["Target Hardware", "Raspberry Pi 4 Model B (4GB RAM) + NodeMCU ESP32-WROOM-32"],
        ["Operating System", "Debian 12 Bookworm (Linux 6.1+ 64-bit ARM)"],
        ["Execution Stack", "Python 3.11+, SQLite 3, Zeek 5.0+, Docker 24+"],
        ["Test Harness Tools", "pytest, pytest-cov, unittest, Bandit, pip-audit"],
        ["Synthetic Attack Data", "Curated attack PCAPs (ARP poison, SYN scan, Deauth burst, BLE flood)"],
        ["Client Browsers", "Chromium, Firefox, Safari (Mobile & Desktop Viewports)"],
    ]
    for r_idx, row in enumerate(t_env_data):
        for c_idx, val in enumerate(row):
            t_env.cell(r_idx, c_idx).text = val
    style_table(t_env, header_bg="1A237E", alt_bg="F1F5F9")
    doc.add_paragraph().paragraph_format.space_after = Pt(6)

    # 7. Test Schedule
    add_h1("7. Test Schedule and Milestones")
    t_sched = doc.add_table(rows=7, cols=3)
    t_sched_data = [
        ["Milestone", "Exit Criteria & Verification Deliverable", "Owner"],
        ["T1 — Test Design", "Reviewed test cases and attack fixtures mapped to SRS IDs", "Tejaswini (QA Lead) + All"],
        ["T2 — Environment Readiness", "Pi 4 hardware, WiFi monitor dongle, and dependencies verified", "Vishal (DevOps Lead)"],
        ["T3 — Module Verification", "Unit test output with >= 85% coverage on local branches", "Each Feature Owner"],
        ["T4 — Integration & System", "End-to-end PCAP replay, live WebSocket feed, and alert verification", "QA Lead + Feature Owners"],
        ["T5 — Security & Hardening", "Bandit/SonarQube reports, pip-audit log, and fuzzed packet pass", "Ritu (Security Lead) + Vishal"],
        ["T6 — Final Demo Sign-off", "1-min and 2-min demo videos recorded; Test Plan sign-off completed", "Whole Team / Evaluator"],
    ]
    for r_idx, row in enumerate(t_sched_data):
        for c_idx, val in enumerate(row):
            t_sched.cell(r_idx, c_idx).text = val
    style_table(t_sched, header_bg="1A237E", alt_bg="F1F5F9")
    doc.add_paragraph().paragraph_format.space_after = Pt(6)

    # 8. Roles and Responsibilities
    add_h1("8. Roles and Responsibilities")
    t_roles = doc.add_table(rows=5, cols=3)
    t_roles_data = [
        ["Role", "Assigned Team Member", "Primary Testing Responsibility"],
        ["QA Lead", "Tejaswini R Pujar", "Test strategy, execution tracking, defect management, and STP consolidation."],
        ["DevOps Lead", "Vishal Prasath", "CI/CD automation, Docker environment, and capture performance tests."],
        ["Security Lead", "Ritu Ravish", "Bandit SAST, SonarQube pipeline, dependency auditing, and fuzzing resilience."],
        ["Scrum Master", "Varshini A", "Requirements traceability, sprint test tracking, and usability verification."],
    ]
    for r_idx, row in enumerate(t_roles_data):
        for c_idx, val in enumerate(row):
            t_roles.cell(r_idx, c_idx).text = val
    style_table(t_roles, header_bg="1A237E", alt_bg="F1F5F9")
    doc.add_paragraph().paragraph_format.space_after = Pt(6)

    # 9. Approvals
    add_h1("9. Approvals and Sign-Off")
    t_app = doc.add_table(rows=5, cols=3)
    t_app_data = [
        ["Role", "Team Member Name", "Signature / Status"],
        ["QA Lead", "Tejaswini R Pujar", "Approved (Baseline V1.0)"],
        ["DevOps Lead", "Vishal Prasath", "Approved (Baseline V1.0)"],
        ["Security Lead", "Ritu Ravish", "Approved (Baseline V1.0)"],
        ["Scrum Master", "Varshini A", "Approved (Baseline V1.0)"],
    ]
    for r_idx, row in enumerate(t_app_data):
        for c_idx, val in enumerate(row):
            t_app.cell(r_idx, c_idx).text = val
    style_table(t_app, header_bg="1A237E", alt_bg="F1F5F9")
    doc.add_paragraph().paragraph_format.space_after = Pt(6)

    out_file = os.path.join(DELIVERABLES_DIR, "02_STP_Pocket_Packet_Sniffer.docx")
    doc.save(out_file)
    print("02_STP generated successfully at:", out_file)

if __name__ == "__main__":
    build_stp_document()
