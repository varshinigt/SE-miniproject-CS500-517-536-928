"""
Builder script to generate all 4 Phase-1 Deliverables as valid, styled Microsoft Word (.docx) documents:
1. 01_SRS_Pocket_Packet_Sniffer.docx
2. 02_STP_Pocket_Packet_Sniffer.docx
3. 03_SAD_Pocket_Packet_Sniffer.docx
4. 04_Test_Cases_Pocket_Packet_Sniffer.docx
"""

import os
from docx import Document
from docx.shared import Inches, Pt, RGBColor
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.enum.table import WD_TABLE_ALIGNMENT
from docx.oxml import OxmlElement
from docx.oxml.ns import qn

DELIVERABLES_DIR = r"d:\Software_Engineering_MiniProject\SE-miniproject-CS500-517-536-928\phase-1-deliverables"
DIAG_DIR = os.path.join(DELIVERABLES_DIR, "diagrams")

def set_cell_background(cell, fill_hex):
    tcPr = cell._tc.get_or_add_tcPr()
    shd = OxmlElement('w:shd')
    shd.set(qn('w:val'), 'clear')
    shd.set(qn('w:color'), 'auto')
    shd.set(qn('w:fill'), fill_hex)
    tcPr.append(shd)

def set_cell_margins(cell, top=100, bottom=100, left=150, right=150):
    tcPr = cell._tc.get_or_add_tcPr()
    tcMar = OxmlElement('w:tcMar')
    for m, val in [('top', top), ('bottom', bottom), ('left', left), ('right', right)]:
        node = OxmlElement(f'w:{m}')
        node.set(qn('w:w'), str(val))
        node.set(qn('w:type'), 'dxa')
        tcMar.append(node)
    tcPr.append(tcMar)

def style_table(table, header_bg="1A237E", alt_bg="F5F5F5"):
    table.alignment = WD_TABLE_ALIGNMENT.CENTER
    for i, row in enumerate(table.rows):
        for cell in row.cells:
            set_cell_margins(cell, top=120, bottom=120, left=180, right=180)
            if i == 0:
                set_cell_background(cell, header_bg)
                for p in cell.paragraphs:
                    p.alignment = WD_ALIGN_PARAGRAPH.LEFT
                    for run in p.runs:
                        run.font.bold = True
                        run.font.color.rgb = RGBColor(255, 255, 255)
                        run.font.size = Pt(9.5)
            else:
                if i % 2 == 1:
                    set_cell_background(cell, "FFFFFF")
                else:
                    set_cell_background(cell, alt_bg)
                for p in cell.paragraphs:
                    for run in p.runs:
                        run.font.size = Pt(9)

def add_header_block(doc, title, subtitle, doc_ref):
    title_p = doc.add_paragraph()
    title_p.paragraph_format.space_before = Pt(0)
    title_p.paragraph_format.space_after = Pt(4)
    run_title = title_p.add_run(title)
    run_title.font.name = "Arial"
    run_title.font.size = Pt(22)
    run_title.font.bold = True
    run_title.font.color.rgb = RGBColor(26, 35, 126) # Dark Navy

    sub_p = doc.add_paragraph()
    sub_p.paragraph_format.space_after = Pt(2)
    run_sub = sub_p.add_run(subtitle)
    run_sub.font.name = "Arial"
    run_sub.font.size = Pt(13)
    run_sub.font.bold = True
    run_sub.font.color.rgb = RGBColor(69, 90, 100)

    meta_p = doc.add_paragraph()
    meta_p.paragraph_format.space_after = Pt(16)
    run_meta = meta_p.add_run(
        f"{doc_ref} | Course: Software Engineering (UE24CS341A) — PES University\n"
        f"Team Members: Ritu Ravish (PES1UG24CS928), Vishal Prasath (PES1UG24CS536), "
        f"Tejaswini R Pujar (PES1UG24CS500), Varshini A (PES1UG24CS517)\n"
        f"Date: October 2026 | Status: Final Submission Baseline"
    )
    run_meta.font.size = Pt(9.5)
    run_meta.font.italic = True
    run_meta.font.color.rgb = RGBColor(97, 97, 97)

    # Horizontal divider
    divider = doc.add_paragraph()
    divider.paragraph_format.space_after = Pt(14)
    pBrd = OxmlElement('w:pBrd')
    bottom = OxmlElement('w:bottom')
    bottom.set(qn('w:val'), 'single')
    bottom.set(qn('w:sz'), '12')
    bottom.set(qn('w:space'), '1')
    bottom.set(qn('w:color'), '1A237E')
    pBrd.append(bottom)
    divider._p.get_or_add_pPr().append(pBrd)

print("Helper definitions loaded successfully.")
