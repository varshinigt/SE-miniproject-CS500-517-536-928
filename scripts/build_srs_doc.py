"""
Build 01_SRS_Pocket_Packet_Sniffer.docx from docs/SRS.md with embedded UML Use Case Diagram
"""

import os
import sys
import re

sys.path.insert(0, os.path.abspath("."))
from docx import Document
from docx.shared import Inches, Pt, RGBColor
from docx.enum.text import WD_ALIGN_PARAGRAPH
from scripts.docx_helpers import add_header_block, style_table, DELIVERABLES_DIR, DIAG_DIR

def build_srs_document():
    doc = Document()

    # Page Margins
    for section in doc.sections:
        section.top_margin = Inches(0.8)
        section.bottom_margin = Inches(0.8)
        section.left_margin = Inches(0.8)
        section.right_margin = Inches(0.8)

    add_header_block(
        doc,
        title="Software Requirements Specification (SRS)",
        subtitle="Pocket Packet Sniffer — Multi-Interface Network Inspection & Intrusion Detection",
        doc_ref="Document ID: PPS-SRS-V1.0"
    )

    with open(r"d:\Software_Engineering_MiniProject\SE-miniproject-CS500-517-536-928\docs\SRS.md", "r", encoding="utf-8") as f:
        content = f.read()

    lines = content.split("\n")
    i = 0
    in_mermaid = False
    in_table = False
    table_rows = []

    def flush_table():
        nonlocal table_rows
        if not table_rows:
            return
        num_cols = len(table_rows[0])
        t = doc.add_table(rows=len(table_rows), cols=num_cols)
        for r_idx, row_data in enumerate(table_rows):
            for c_idx, cell_value in enumerate(row_data):
                if c_idx < num_cols:
                    t.cell(r_idx, c_idx).text = cell_value.strip()
        style_table(t, header_bg="1A237E", alt_bg="F1F5F9")
        doc.add_paragraph().paragraph_format.space_after = Pt(6)
        table_rows = []

    while i < len(lines):
        line = lines[i]

        # Check for mermaid block
        if line.strip().startswith("```mermaid"):
            in_mermaid = True
            i += 1
            continue
        elif in_mermaid:
            if line.strip().startswith("```"):
                in_mermaid = False
                # Insert generated Use Case Diagram image!
                img_path = os.path.join(DIAG_DIR, "use_case_diagram.png")
                if os.path.exists(img_path):
                    doc.add_paragraph().paragraph_format.space_before = Pt(6)
                    p_img = doc.add_paragraph()
                    p_img.alignment = WD_ALIGN_PARAGRAPH.CENTER
                    p_img.add_run().add_picture(img_path, width=Inches(6.2))
                    p_cap = doc.add_paragraph()
                    p_cap.alignment = WD_ALIGN_PARAGRAPH.CENTER
                    r_cap = p_cap.add_run("Figure 4.1: UML Use Case Diagram for Pocket Packet Sniffer")
                    r_cap.font.size = Pt(9)
                    r_cap.font.italic = True
                    r_cap.font.color.rgb = RGBColor(80, 80, 80)
            i += 1
            continue

        # Skip normal code blocks or intro metadata header
        if line.strip().startswith("```") or line.strip() == "---":
            i += 1
            continue

        # Table row check
        if line.strip().startswith("|") and line.strip().endswith("|"):
            cells = [c.strip() for c in line.strip()[1:-1].split("|")]
            # Ignore separator line like |---|---|
            if not all(re.match(r"^:?-+:?$", c) for c in cells if c):
                table_rows.append(cells)
            i += 1
            continue
        else:
            if table_rows:
                flush_table()

        # Headings
        if line.startswith("# "):
            # Skip top title since add_header_block handled it
            i += 1
            continue
        elif line.startswith("## "):
            h = doc.add_paragraph()
            h.paragraph_format.space_before = Pt(14)
            h.paragraph_format.space_after = Pt(4)
            r = h.add_run(line[3:].strip())
            r.font.name = "Arial"
            r.font.size = Pt(14)
            r.font.bold = True
            r.font.color.rgb = RGBColor(26, 35, 126)
        elif line.startswith("### "):
            h = doc.add_paragraph()
            h.paragraph_format.space_before = Pt(10)
            h.paragraph_format.space_after = Pt(3)
            r = h.add_run(line[4:].strip())
            r.font.name = "Arial"
            r.font.size = Pt(11.5)
            r.font.bold = True
            r.font.color.rgb = RGBColor(13, 71, 161)
        elif line.startswith("#### "):
            h = doc.add_paragraph()
            h.paragraph_format.space_before = Pt(6)
            h.paragraph_format.space_after = Pt(2)
            r = h.add_run(line[5:].strip())
            r.font.name = "Arial"
            r.font.size = Pt(10.5)
            r.font.bold = True
            r.font.color.rgb = RGBColor(38, 50, 56)
        elif line.strip().startswith("* ") or line.strip().startswith("- "):
            p = doc.add_paragraph(style='List Bullet')
            p.paragraph_format.space_after = Pt(2)
            # Parse bold text
            text = line.strip()[2:]
            parts = re.split(r"(\*\*.*?\*\*)", text)
            for part in parts:
                if part.startswith("**") and part.endswith("**"):
                    r = p.add_run(part[2:-2])
                    r.font.bold = True
                else:
                    r = p.add_run(part)
                r.font.size = Pt(9.5)
        elif re.match(r"^\d+\.\s", line.strip()):
            p = doc.add_paragraph(style='List Number')
            p.paragraph_format.space_after = Pt(2)
            text = re.sub(r"^\d+\.\s", "", line.strip())
            parts = re.split(r"(\*\*.*?\*\*)", text)
            for part in parts:
                if part.startswith("**") and part.endswith("**"):
                    r = p.add_run(part[2:-2])
                    r.font.bold = True
                else:
                    r = p.add_run(part)
                r.font.size = Pt(9.5)
        elif line.strip():
            p = doc.add_paragraph()
            p.paragraph_format.space_after = Pt(4)
            parts = re.split(r"(\*\*.*?\*\*)", line.strip())
            for part in parts:
                if part.startswith("**") and part.endswith("**"):
                    r = p.add_run(part[2:-2])
                    r.font.bold = True
                else:
                    r = p.add_run(part)
                r.font.size = Pt(9.5)

        i += 1

    if table_rows:
        flush_table()

    out_file = os.path.join(DELIVERABLES_DIR, "01_SRS_Pocket_Packet_Sniffer.docx")
    doc.save(out_file)
    print("01_SRS generated successfully at:", out_file)

if __name__ == "__main__":
    build_srs_document()
