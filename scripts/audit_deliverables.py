"""
Audit script to verify all 4 Phase 1 Deliverables
"""

import glob
import os
import zipfile
import xml.etree.ElementTree as ET

files = sorted(glob.glob(r"d:\Software_Engineering_MiniProject\SE-miniproject-CS500-517-536-928\phase-1-deliverables\*.docx"))
print("="*75)
print("PHASE-1 DELIVERABLES INTEGRITY AUDIT")
print("="*75)

for f in files:
    size = os.path.getsize(f)
    print(f"\n[FILE]: {os.path.basename(f)} ({size:,} bytes)")
    try:
        with zipfile.ZipFile(f) as z:
            tree = ET.fromstring(z.read("word/document.xml"))
            tables = len(tree.findall(".//{http://schemas.openxmlformats.org/wordprocessingml/2006/main}tbl"))
            images = len(tree.findall(".//{http://schemas.openxmlformats.org/drawingml/2006/main}blip"))
            paragraphs = []
            for p in tree.iter("{http://schemas.openxmlformats.org/wordprocessingml/2006/main}p"):
                t = "".join(n.text for n in p.iter("{http://schemas.openxmlformats.org/wordprocessingml/2006/main}t") if n.text)
                if t.strip():
                    paragraphs.append(t.strip())
            print(f"  Status: VALID DOCX")
            print(f"  Paragraphs: {len(paragraphs)} | Tables: {tables} | Embedded Images: {images}")
            print(f"  Title: {paragraphs[0]}")
            if len(paragraphs) > 1:
                print(f"  Subtitle: {paragraphs[1]}")
    except Exception as e:
        print(f"  Status: INVALID / CORRUPTED ({e})")

print("\n" + "="*75)
diag_files = sorted(glob.glob(r"d:\Software_Engineering_MiniProject\SE-miniproject-CS500-517-536-928\phase-1-deliverables\diagrams\*.png"))
print("DIAGRAM ASSETS IN phase-1-deliverables/diagrams:")
for df in diag_files:
    print(f"  - {os.path.basename(df)} ({os.path.getsize(df):,} bytes)")
print("="*75)
