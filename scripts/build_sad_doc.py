"""
Build 03_SAD_Pocket_Packet_Sniffer.docx following PES University SAD Template
Embeds Component Diagram and 2 UML Sequence Diagrams
"""

import os
import sys
from docx import Document
from docx.shared import Inches, Pt, RGBColor
from docx.enum.text import WD_ALIGN_PARAGRAPH

sys.path.insert(0, os.path.abspath("."))
from scripts.docx_helpers import add_header_block, style_table, DELIVERABLES_DIR, DIAG_DIR

def build_sad_document():
    doc = Document()

    for s in doc.sections:
        s.top_margin = Inches(0.8)
        s.bottom_margin = Inches(0.8)
        s.left_margin = Inches(0.8)
        s.right_margin = Inches(0.8)

    add_header_block(
        doc,
        title="Software Architecture and Design Specification (SAD)",
        subtitle="Pocket Packet Sniffer — System Architecture, Component Models, and Detailed Design",
        doc_ref="Document ID: PPS-SAD-V1.0"
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

    def add_h3(text):
        h = doc.add_paragraph()
        h.paragraph_format.space_before = Pt(6)
        h.paragraph_format.space_after = Pt(2)
        r = h.add_run(text)
        r.font.name = "Arial"
        r.font.size = Pt(10.5)
        r.font.bold = True
        r.font.color.rgb = RGBColor(38, 50, 56)

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

    def add_img(img_name, caption):
        img_p = os.path.join(DIAG_DIR, img_name)
        if os.path.exists(img_p):
            p = doc.add_paragraph()
            p.alignment = WD_ALIGN_PARAGRAPH.CENTER
            p.paragraph_format.space_before = Pt(8)
            p.add_run().add_picture(img_p, width=Inches(6.2))
            c = doc.add_paragraph()
            c.alignment = WD_ALIGN_PARAGRAPH.CENTER
            c.paragraph_format.space_after = Pt(10)
            rc = c.add_run(caption)
            rc.font.size = Pt(9)
            rc.font.italic = True
            rc.font.color.rgb = RGBColor(80, 80, 80)

    # 1. Introduction
    add_h1("1. Introduction")
    add_h2("1.1 Purpose")
    add_p("This document specifies the software architecture and detailed design for the Pocket Packet Sniffer (PPS v1.0). It defines subsystem decomposition, inter-module communication protocols, architectural patterns, UML component diagrams, sequence flows, API contracts, database schema, and security controls.")
    add_h2("1.2 Scope")
    add_p("The architecture encompasses four collaborating functional subsystems: Multi-Interface Packet Capture (F1), Protocol Parsing & Zeek Integration (F2), Threat & Anomaly Detection (F3), and Live Monitoring, Device Inventory & Reporting (F4).")
    add_h2("1.3 Audience")
    add_p("This specification is intended for the development team, QA engineers, security leads, course evaluators, and system maintainers implementing the Raspberry Pi appliance.")
    add_h2("1.4 Definitions and Acronyms")
    add_bullet("PPS: ", "Pocket Packet Sniffer edge intrusion detection appliance.")
    add_bullet("IPC: ", "Inter-Process Communication via Python asyncio queues and shared database.")
    add_bullet("OUI: ", "Organizationally Unique Identifier for MAC vendor resolution.")
    add_bullet("SAST: ", "Static Application Security Testing (Bandit / SonarQube).")

    # 2. Document Overview
    add_h1("2. Document Overview")
    add_p("This document provides architectural and design models adhering to IEEE standard specifications for Software Architecture and Design Description (SADD). It traces directly to requirements defined in PPS-SRS-V1.0 and verification specifications in PPS-STP-V1.0.")

    # 3. Architecture
    add_h1("3. Architecture")
    add_h2("3.1 Goals and Constraints")
    add_bullet("Near Real-Time Analytics: ", "End-to-end packet processing and alert generation within <= 2.0 seconds.")
    add_bullet("Bounded Resource Footprint: ", "Safe execution on a 4GB Raspberry Pi 4 Model B with <= 5,000 packets/sec throughput without unbounded memory growth.")
    add_bullet("Extensibility (Open/Closed Principle): ", "Pluggable BaseDetector interface permitting independent threat rules without modifying engine core.")
    add_bullet("Platform Constraints: ", "Requires Linux CAP_NET_RAW / CAP_NET_ADMIN capabilities for promiscuous Ethernet and 802.11 monitor mode.")

    add_h2("3.2 Stakeholders and Concerns")
    add_bullet("Security Analyst: ", "Comprehensive threat visibility, accurate alert timestamps, evidence forensics, and PCAP export.")
    add_bullet("DevOps Engineer: ", "Reproducible containerized deployment on ARM64 Linux, CI/CD pipeline stability.")
    add_bullet("QA / Test Lead: ", "Modular decoupled interfaces with verifiable entry/exit contracts enabling >85% branch coverage.")

    add_h2("3.3 UML Component Diagram")
    add_p("Figure 3.1 illustrates the structural decomposition of the Pocket Packet Sniffer into cooperating components, data repositories, and external physical network boundaries.")
    add_img("component_diagram.png", "Figure 3.1: Pocket Packet Sniffer UML Component Architecture Diagram")

    add_h2("3.4 Component Descriptions")
    add_bullet("F1 Capture Component (`src/capture`): ", "Interacts with OS network adapters (eth0, wlan0mon, hci0) and opens a UDP socket (port 5555) for ESP32 frames. Manages PCAP file rotation upon reaching size/time limits.")
    add_bullet("F2 Parser Component (`src/parser`): ", "Decodes L2-L7 protocols into strongly-typed NormalizedRecord data classes. Ingests Zeek connection logs and persists normalized records into SQLite tables.")
    add_bullet("F3 Detection Engine (`src/detection`): ", "Central coordinator executing pluggable BaseDetector rules over the streaming records. Maintains in-memory sliding windows to detect ARP spoofing, port sweeps, WiFi deauth floods, and BLE flooding.")
    add_bullet("F4 Dashboard Component (`src/dashboard`): ", "FastAPI web server exposing REST endpoints for querying packets and alerts, alongside a WebSocket hub broadcasting live stats and alerts to mobile/desktop browsers.")
    add_bullet("Database Component: ", "SQLite relational store configured with Write-Ahead Logging (WAL) mode for concurrent read/write transactions.")

    add_h2("3.5 Chosen Architecture Pattern and Rationale")
    add_p("The system adopts a hybrid **Pipes-and-Filters** and **Microkernel (Pluggable)** architecture pattern:")
    add_bullet("Pipes-and-Filters: ", "Packet data naturally moves as a linear pipeline: Physical Frame -> Raw Capture Filter -> Dissection & Normalization Filter -> Threat Inspection Filter -> Storage & WebSocket Dispatch.")
    add_bullet("Microkernel Pattern: ", "The Detection Engine core serves as a microkernel, while threat detectors (ArpSpoofDetector, PortScanDetector, WifiDeauthDetector) act as isolated plugins inheriting from BaseDetector. This prevents single-detector failures from crashing the engine.")

    add_h2("3.6 Technology Stack and Data Stores")
    # Table of Tech Stack
    t_stack = doc.add_table(rows=6, cols=3)
    t_stack_data = [
        ["Layer / Subsystem", "Technology / Framework", "Purpose / Rationale"],
        ["Edge Hardware", "Raspberry Pi 4 Model B + ESP32", "Low-cost, portable multi-interface capture platform"],
        ["Language & Core", "Python 3.11+, Scapy 2.5", "High-level networking libraries and asynchronous event loops"],
        ["Network Telemetry", "Zeek Network Monitor 5.0+", "Stateful connection tracking and protocol log generation"],
        ["Embedded Storage", "SQLite 3 (WAL Mode)", "Zero-configuration serverless ACID database on flash storage"],
        ["API & Web Server", "FastAPI, Uvicorn, WebSockets", "High-performance asynchronous REST and real-time push"],
    ]
    for r_idx, row in enumerate(t_stack_data):
        for c_idx, val in enumerate(row):
            t_stack.cell(r_idx, c_idx).text = val
    style_table(t_stack, header_bg="1A237E", alt_bg="F1F5F9")
    doc.add_paragraph().paragraph_format.space_after = Pt(6)

    add_h2("3.7 Requirements Traceability")
    add_p("Table 3.2 maps each architectural subsystem to the functional requirements defined in the SRS:")
    t_trace = doc.add_table(rows=5, cols=3)
    t_trace_data = [
        ["Architectural Subsystem", "SRS Requirements Covered", "Key Design Deliverable"],
        ["Capture Subsystem (F1)", "REQ-F1-01 to REQ-F1-05, NFR-PERF-01", "Raw socket workers, monitor hopping, PCAP rotator"],
        ["Parser Subsystem (F2)", "REQ-F2-01 to REQ-F2-05, NFR-PERF-02", "Dissector registry, NormalizedRecord, SQLite WAL writer"],
        ["Detection Engine (F3)", "REQ-F3-01 to REQ-F3-10, SEC-01 to 04", "DetectionEngine, BaseDetector, sliding window queues"],
        ["Dashboard & API (F4)", "REQ-F4-01 to REQ-F4-05, NFR-USE-01", "FastAPI endpoints, WebSocket broadcaster, HTML5 UI"],
    ]
    for r_idx, row in enumerate(t_trace_data):
        for c_idx, val in enumerate(row):
            t_trace.cell(r_idx, c_idx).text = val
    style_table(t_trace, header_bg="1A237E", alt_bg="F1F5F9")
    doc.add_paragraph().paragraph_format.space_after = Pt(6)

    add_h2("3.8 Security Architecture")
    add_bullet("Principle of Least Privilege: ", "Root privileges are dropped immediately after raw sockets are opened by capture workers.")
    add_bullet("Defensive Exception Boundaries: ", "Every detector rule wraps execution in try/except blocks to guarantee that malformed or fuzzed packets cannot destabilize the pipeline.")
    add_bullet("Static Code Hardening: ", "Automated CI/CD integration with Bandit and SonarQube enforcing zero high/critical SAST findings.")
    add_bullet("Alert Immutability: ", "Alert records inserted into SQLite are read-only and timestamped using UTC epoch floats for forensic integrity.")

    # 4. Detailed Design
    add_h1("4. Detailed Design")
    add_h2("4.1 Design Overview")
    add_p("The detailed design specifies message interactions between subsystems, REST API endpoint definitions, SQLite relational table schemas, and error recovery policies.")

    add_h2("4.2 UML Sequence Diagrams")
    add_h3("4.2.1 Sequence Diagram 1: Real-Time Threat Detection & Alert Dispatch")
    add_p("Figure 4.1 details the asynchronous execution path from raw frame receipt to live WebSocket notification on the client browser:")
    add_img("sequence_detection.png", "Figure 4.1: Real-Time Threat Detection & Alert Dispatch Sequence Diagram")

    add_h3("4.2.2 Sequence Diagram 2: Historical Search, Filtering & Session Export")
    add_p("Figure 4.2 details the workflow for parameterized search and PCAP/CSV/JSON session export from the web dashboard:")
    add_img("sequence_export.png", "Figure 4.2: Search, Filtering & Session Export Sequence Diagram")

    add_h2("4.3 API Design")
    add_p("The dashboard backend exposes standard REST endpoints and a real-time WebSocket connection:")
    t_api = doc.add_table(rows=6, cols=4)
    t_api_data = [
        ["Method", "Endpoint", "Parameters / Body", "Description / Response"],
        ["GET", "/api/health", "None", "Returns 200 OK with CPU, memory, and interface status"],
        ["GET", "/api/packets", "limit, offset, interface, protocol", "Paginated list of normalized packet records from SQLite"],
        ["GET", "/api/alerts", "severity, threat_type, limit", "Returns recent alert objects with evidence dictionaries"],
        ["GET", "/api/devices", "limit, offset", "Returns active device inventory with MAC OUI vendor info"],
        ["GET", "/api/export", "format (pcap/csv/json), filter query", "Streams downloadable file containing matching traffic"],
    ]
    for r_idx, row in enumerate(t_api_data):
        for c_idx, val in enumerate(row):
            t_api.cell(r_idx, c_idx).text = val
    style_table(t_api, header_bg="1A237E", alt_bg="F1F5F9")
    doc.add_paragraph().paragraph_format.space_after = Pt(6)

    add_h2("4.4 Error Handling and Fault Tolerance")
    add_bullet("Packet Ingestion Faults: ", "Malformed or truncated frames are discarded with an error log counter; parsing never throws unhandled exceptions.")
    add_bullet("Database Lock Contention: ", "SQLite WAL mode with a 5000ms busy timeout ensures concurrent web reads never block ingestion writes.")
    add_bullet("Sliding Window Memory Caps: ", "In-memory deque structures automatically evict entries older than window expiration thresholds to prevent memory leakage.")

    add_h2("4.5 Database Design (SQLite Schema)")
    add_p("The relational persistence model comprises four primary tables: `packets`, `connections`, `devices`, and `alerts`:")
    t_db = doc.add_table(rows=5, cols=3)
    t_db_data = [
        ["Table Name", "Key Columns", "Indexes"],
        ["`packets`", "id (PK), timestamp, interface, src_mac, dst_mac, src_ip, dst_ip, protocol, length", "INDEX(timestamp), INDEX(src_ip, dst_ip)"],
        ["`connections`", "uid (PK), start_time, proto, orig_h, orig_p, resp_h, resp_p, duration, state", "INDEX(orig_h), INDEX(resp_h)"],
        ["`devices`", "mac (PK), vendor, hostname, link_type, first_seen, last_seen, packet_count", "INDEX(mac), INDEX(last_seen)"],
        ["`alerts`", "alert_id (PK), timestamp, threat_type, severity, title, evidence_json, mitigation", "INDEX(timestamp), INDEX(severity)"],
    ]
    for r_idx, row in enumerate(t_db_data):
        for c_idx, val in enumerate(row):
            t_db.cell(r_idx, c_idx).text = val
    style_table(t_db, header_bg="1A237E", alt_bg="F1F5F9")
    doc.add_paragraph().paragraph_format.space_after = Pt(6)

    # 5. Appendices
    add_h1("5. Appendices")
    add_h2("5.1 References")
    add_p("1. IEEE Std 1016-2009: Standard for Information Technology — Systems Design — Software Design Descriptions.\n"
          "2. Gamma et al.: Design Patterns: Elements of Reusable Object-Oriented Software (Strategy Pattern).\n"
          "3. Martin, Robert C.: Clean Architecture: A Craftsman's Guide to Software Structure and Design.")

    out_file = os.path.join(DELIVERABLES_DIR, "03_SAD_Pocket_Packet_Sniffer.docx")
    doc.save(out_file)
    print("03_SAD generated successfully at:", out_file)

if __name__ == "__main__":
    build_sad_document()
