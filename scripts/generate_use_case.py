"""
Generate High-Quality Textbook UML Use Case Diagram matching the reference specification
Features:
- System boundary with rounded box and title badge
- Stick-figure Actors (Network Administrator, Security Analyst)
- Orthogonal actor association lines
- 4 Primary Use Cases (UC-01 to UC-04)
- 8 Subordinate Included Use Cases
- Clean dashed arrows with «include» stereotypes
- Bottom legend
"""

import matplotlib.pyplot as plt
import matplotlib.patches as patches
from matplotlib.patches import Ellipse, FancyBboxPatch
import numpy as np
import os

def draw_actor(ax, x, y, label):
    # Head
    head = plt.Circle((x, y + 0.38), 0.14, color="#1D4A7A", fill=False, lw=2.2)
    ax.add_patch(head)
    # Body
    ax.plot([x, x], [y + 0.24, y - 0.15], color="#1D4A7A", lw=2.2)
    # Arms
    ax.plot([x - 0.26, x + 0.26], [y + 0.10, y + 0.10], color="#1D4A7A", lw=2.2)
    # Legs
    ax.plot([x, x - 0.20], [y - 0.15, y - 0.45], color="#1D4A7A", lw=2.2)
    ax.plot([x, x + 0.20], [y - 0.15, y - 0.45], color="#1D4A7A", lw=2.2)
    # Label
    ax.text(x, y - 0.65, label, ha="center", va="top", fontsize=9.5, fontweight="bold", color="#0D2E5C", linespacing=1.2)

def draw_oval(ax, x, y, w, h, text, is_primary=True):
    # Oval background patch
    edge_col = "#1D4A7A" if is_primary else "#3D6E99"
    fill_col = "#FFFFFF"
    ellipse = Ellipse((x, y), w, h, facecolor=fill_col, edgecolor=edge_col, lw=1.8 if is_primary else 1.4)
    ax.add_patch(ellipse)
    font_weight = "bold" if is_primary else "normal"
    font_size = 9.0 if is_primary else 8.2
    font_col = "#0D2E5C" if is_primary else "#1A365D"
    ax.text(x, y, text, ha="center", va="center", fontsize=font_size, fontweight=font_weight, color=font_col, linespacing=1.15)

def draw_include_arrow(ax, x1, y1, x2, y2):
    ax.annotate(
        "", xy=(x2, y2), xytext=(x1, y1),
        arrowprops=dict(arrowstyle="->", linestyle="--", color="#7895B2", lw=1.5, mutation_scale=12)
    )
    mx = (x1 + x2) / 2
    my = (y1 + y2) / 2
    ax.text(mx, my + 0.08, "«include»", ha="center", va="center", fontsize=7.2, color="#5B7692", fontstyle="italic")

def generate_textbook_use_case():
    fig, ax = plt.subplots(figsize=(13.5, 9.2), dpi=250)
    ax.set_xlim(0, 14.5)
    ax.set_ylim(0, 10.2)
    ax.axis("off")

    # Title
    ax.text(7.25, 9.85, "POCKET PACKET SNIFFER — UML USE CASE DIAGRAM", ha="center", va="center",
            fontsize=15, fontweight="bold", color="#0B2B54")

    # System Boundary Box
    bx, by, bw, bh = 2.4, 0.75, 11.6, 8.7
    sys_box = FancyBboxPatch(
        (bx, by), bw, bh, boxstyle="round,pad=0.2,rounding_size=0.35",
        facecolor="#F2F7FC", edgecolor="#1D4A7A", lw=2.2
    )
    ax.add_patch(sys_box)

    # System Title Badge
    ax.add_patch(patches.Rectangle((bx + 2.8, by + bh - 0.15), 4.6, 0.32, facecolor="#F2F7FC", edgecolor="none"))
    ax.text(bx + 5.1, by + bh, "Pocket Packet Sniffer System", ha="center", va="center",
            fontsize=11.5, fontweight="bold", color="#0B2B54")

    # Actors
    admin_x, admin_y = 0.95, 6.9
    analyst_x, analyst_y = 0.95, 3.2
    draw_actor(ax, admin_x, admin_y, "Network\nAdministrator")
    draw_actor(ax, analyst_x, analyst_y, "Security\nAnalyst")

    # Primary Use Cases (Left Column)
    p_x = 5.3
    p_w, p_h = 3.6, 0.72
    primary_ucs = [
        {"id": "UC-01", "name": "UC-01  Capture Network Traffic", "y": 8.1},
        {"id": "UC-02", "name": "UC-02  Analyze Traffic & Detect Threats", "y": 5.9},
        {"id": "UC-03", "name": "UC-03  Monitor Network & Devices", "y": 3.8},
        {"id": "UC-04", "name": "UC-04  Investigate & Export Records", "y": 1.7},
    ]

    for uc in primary_ucs:
        draw_oval(ax, p_x, uc["y"], p_w, p_h, uc["name"], is_primary=True)

    # Subordinate Included Use Cases (Right Column)
    s_x = 11.0
    s_w, s_h = 3.3, 0.62
    sub_ucs = {
        "s1": {"text": "Capture Ethernet, Wi-Fi, BLE\n& ESP32 probe frames", "y": 8.3, "p_idx": 0},
        "s2": {"text": "Decode & normalize packets", "y": 7.0, "p_idx": 1},
        "s3": {"text": "Enrich records with Zeek", "y": 6.1, "p_idx": 1},
        "s4": {"text": "Apply pluggable detection rules", "y": 5.2, "p_idx": 1},
        "s5": {"text": "Create and store alerts", "y": 4.3, "p_idx": 1},
        "s6": {"text": "Update device inventory", "y": 3.4, "p_idx": 2},
        "s7": {"text": "Search and filter history", "y": 2.3, "p_idx": 3},
        "s8": {"text": "Export PCAP / CSV / JSON", "y": 1.3, "p_idx": 3},
    }

    for k, sub in sub_ucs.items():
        draw_oval(ax, s_x, sub["y"], s_w, s_h, sub["text"], is_primary=False)
        p_uc = primary_ucs[sub["p_idx"]]
        # Draw include arrow from right perimeter of primary to left perimeter of sub
        x1 = p_x + p_w / 2
        y1 = p_uc["y"]
        x2 = s_x - s_w / 2
        y2 = sub["y"]
        draw_include_arrow(ax, x1, y1, x2, y2)

    # Actor Associations (Orthogonal routing)
    line_col = "#2B4C7E"

    # Network Administrator lines -> UC-01, UC-02, UC-03
    bus1_x = 1.95
    # From admin to bus
    ax.plot([admin_x + 0.35, bus1_x], [admin_y, admin_y], color=line_col, lw=1.5)
    # Vertical trunk
    ax.plot([bus1_x, bus1_x], [3.8, 8.1], color=line_col, lw=1.5)
    # Branches to ovals
    ax.plot([bus1_x, p_x - p_w / 2], [8.1, 8.1], color=line_col, lw=1.5)
    ax.plot([bus1_x, p_x - p_w / 2], [5.9, 5.9], color=line_col, lw=1.5)
    ax.plot([bus1_x, p_x - p_w / 2], [3.8, 3.8], color=line_col, lw=1.5)

    # Security Analyst lines -> UC-01, UC-02, UC-03, UC-04
    bus2_x = 2.15
    # From analyst to bus
    ax.plot([analyst_x + 0.35, bus2_x], [analyst_y, analyst_y], color=line_col, lw=1.5)
    # Vertical trunk
    ax.plot([bus2_x, bus2_x], [1.7, 7.95], color=line_col, lw=1.5)
    # Branches to ovals
    ax.plot([bus2_x, p_x - p_w / 2], [7.95, 7.95], color=line_col, lw=1.5)
    ax.plot([bus2_x, p_x - p_w / 2], [5.8, 5.8], color=line_col, lw=1.5)
    ax.plot([bus2_x, p_x - p_w / 2], [3.7, 3.7], color=line_col, lw=1.5)
    ax.plot([bus2_x, p_x - p_w / 2], [1.7, 1.7], color=line_col, lw=1.5)

    # Legend at bottom
    leg_y = 0.95
    ax.plot([3.2, 4.0], [leg_y, leg_y], color=line_col, lw=1.5)
    ax.text(4.15, leg_y, "Actor association", ha="left", va="center", fontsize=8.0, color="#1D3E66")

    ax.annotate("", xy=(8.0, leg_y), xytext=(7.1, leg_y),
                arrowprops=dict(arrowstyle="->", linestyle="--", color="#7895B2", lw=1.5, mutation_scale=10))
    ax.text(8.15, leg_y, "«include» — required supporting behaviour", ha="left", va="center", fontsize=8.0, color="#1D3E66")

    plt.tight_layout()
    out_img = r"d:\Software_Engineering_MiniProject\SE-miniproject-CS500-517-536-928\phase-1-deliverables\diagrams\use_case_diagram.png"
    plt.savefig(out_img, dpi=250, bbox_inches="tight")
    plt.close()
    print("New Use Case Diagram saved successfully to:", out_img)

if __name__ == "__main__":
    generate_textbook_use_case()
