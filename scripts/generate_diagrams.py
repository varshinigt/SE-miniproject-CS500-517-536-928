"""
Generate UML Diagrams for Pocket Packet Sniffer Architecture
1. Component Diagram (component_diagram.png)
2. Sequence Diagram: Real-Time Threat Detection & Alerting (sequence_detection.png)
"""

import matplotlib.pyplot as plt
import matplotlib.patches as patches
import os

os.makedirs(r"d:\Software_Engineering_MiniProject\SE-miniproject-CS500-517-536-928\phase-1-deliverables\diagrams", exist_ok=True)
diag_dir = r"d:\Software_Engineering_MiniProject\SE-miniproject-CS500-517-536-928\phase-1-deliverables\diagrams"

def generate_component_diagram():
    fig, ax = plt.subplots(figsize=(14, 8), dpi=200)
    ax.set_xlim(0, 14)
    ax.set_ylim(0, 8.5)
    ax.axis("off")

    plt.title("Pocket Packet Sniffer - UML Component Architecture Diagram", fontsize=16, fontweight="bold", pad=20)

    # Subsystems (components)
    components = [
        {"name": "F1: Capture Subsystem\n(Promiscuous eth0, WiFi wlan0mon,\nBLE hci0, ESP32 UDP Listener)", "x": 0.5, "y": 4.5, "w": 3.8, "h": 2.5, "color": "#E3F2FD"},
        {"name": "F2: Parser & Normalizer Subsystem\n(L2-L7 Dissectors, Unified Schema,\nZeek Log Ingestion)", "x": 5.1, "y": 4.5, "w": 3.8, "h": 2.5, "color": "#E8F5E9"},
        {"name": "F3: Detection Engine Subsystem\n(Pluggable BaseDetector, Sliding Windows,\nRules: ARP, PortScan, Deauth, RogueAP, BLE)", "x": 9.7, "y": 4.5, "w": 3.8, "h": 2.5, "color": "#FFF3E0"},
        {"name": "Storage Subsystem\n(SQLite Database: packets, conns,\nsessions, alerts, devices)", "x": 5.1, "y": 0.8, "w": 3.8, "h": 2.2, "color": "#F3E5F5"},
        {"name": "F4: Dashboard & API Subsystem\n(FastAPI/REST, WebSockets, Live Feed,\nDevice Inventory, Export PCAP/CSV)", "x": 9.7, "y": 0.8, "w": 3.8, "h": 2.2, "color": "#EDE7F6"},
    ]

    for comp in components:
        rect = patches.FancyBboxPatch(
            (comp["x"], comp["y"]), comp["w"], comp["h"],
            boxstyle="round,pad=0.2", facecolor=comp["color"], edgecolor="#333333", linewidth=1.5
        )
        ax.add_patch(rect)
        # Small component icon in top-right corner
        ax.add_patch(patches.Rectangle((comp["x"] + comp["w"] - 0.5, comp["y"] + comp["h"] - 0.4), 0.35, 0.25, facecolor="#ffffff", edgecolor="#333333", lw=1))
        ax.add_patch(patches.Rectangle((comp["x"] + comp["w"] - 0.55, comp["y"] + comp["h"] - 0.35), 0.15, 0.06, facecolor="#ffffff", edgecolor="#333333", lw=1))
        ax.add_patch(patches.Rectangle((comp["x"] + comp["w"] - 0.55, comp["y"] + comp["h"] - 0.25), 0.15, 0.06, facecolor="#ffffff", edgecolor="#333333", lw=1))

        ax.text(comp["x"] + comp["w"]/2, comp["y"] + comp["h"]/2, comp["name"],
                ha="center", va="center", fontsize=9.5, fontweight="semibold", color="#111111")

    # Connectors / Arrows
    def draw_arrow(x1, y1, x2, y2, label=""):
        ax.annotate("", xy=(x2, y2), xytext=(x1, y1),
                    arrowprops=dict(arrowstyle="->", color="#1A237E", lw=2, mutation_scale=15))
        if label:
            mx, my = (x1 + x2)/2, (y1 + y2)/2 + 0.18
            ax.text(mx, my, label, ha="center", va="center", fontsize=8.5, fontweight="bold", color="#1A237E",
                    bbox=dict(boxstyle="round,pad=0.15", facecolor="#ffffff", edgecolor="#BDBDBD", lw=0.8))

    draw_arrow(4.3, 5.75, 5.1, 5.75, "Raw Frames / PCAP")
    draw_arrow(8.9, 5.75, 9.7, 5.75, "NormalizedRecord")
    draw_arrow(7.0, 4.5, 7.0, 3.0, "Persist Packets")
    draw_arrow(11.6, 4.5, 11.6, 3.0, "Alert Events")
    draw_arrow(8.9, 1.9, 9.7, 1.9, "Historical Queries")

    # Outer Hardware Environment Box
    env_rect = patches.Rectangle((0.2, 0.3), 13.6, 7.4, fill=False, edgecolor="#78909C", linestyle="--", linewidth=1.5)
    ax.add_patch(env_rect)
    ax.text(0.4, 7.45, "Execution Node: Raspberry Pi 4 Model B (Linux / Docker Environment)", fontsize=9, fontstyle="italic", color="#455A64")

    plt.tight_layout()
    out_path = os.path.join(diag_dir, "component_diagram.png")
    plt.savefig(out_path, dpi=200, bbox_inches="tight")
    plt.close()
    print("Component diagram saved to:", out_path)

def generate_sequence_detection():
    fig, ax = plt.subplots(figsize=(15, 8.5), dpi=200)
    ax.set_xlim(0, 15)
    ax.set_ylim(0, 10)
    ax.axis("off")

    plt.title("UML Sequence Diagram: Real-Time Threat Detection & Alert Dispatch", fontsize=15, fontweight="bold", pad=20)

    lifelines = [
        {"name": "Traffic Source\n(Eth/WiFi/BLE)", "x": 1.5},
        {"name": "F1: Capture\nEngine", "x": 3.8},
        {"name": "F2: Protocol\nParser", "x": 6.2},
        {"name": "F3: Detection\nEngine", "x": 8.8},
        {"name": "F3: Pluggable\nRules", "x": 11.0},
        {"name": "F4: Dashboard\n& Storage", "x": 13.5},
    ]

    top_y = 8.6
    bot_y = 0.8

    for line in lifelines:
        # Box
        rect = patches.FancyBboxPatch(
            (line["x"] - 0.9, top_y), 1.8, 0.8,
            boxstyle="square,pad=0.1", facecolor="#E1F5FE", edgecolor="#0277BD", lw=1.5
        )
        ax.add_patch(rect)
        ax.text(line["x"], top_y + 0.4, line["name"], ha="center", va="center", fontsize=9, fontweight="bold")
        # Vertical dashed line
        ax.plot([line["x"], line["x"]], [top_y, bot_y], linestyle="--", color="#78909C", lw=1.2)

    messages = [
        (1.5, 3.8, 8.0, "1: Transmit frame / packet burst", False),
        (3.8, 6.2, 7.3, "2: Stream raw bytes / pcap slice", False),
        (6.2, 6.2, 6.6, "3: Dissect L2-L7 & normalize schema", True),
        (6.2, 8.8, 5.9, "4: Dispatch NormalizedRecord", False),
        (8.8, 11.0, 5.2, "5: Evaluate active rule pipeline (ARP/Scan/Deauth)", False),
        (11.0, 11.0, 4.5, "6: Breached threshold? Generate Alert(severity, evidence)", True),
        (11.0, 8.8, 3.8, "7: Return [Alert] instance", False),
        (8.8, 13.5, 3.1, "8: Publish Alert to WebSocket feed & SQLite", False),
        (13.5, 13.5, 2.4, "9: Push real-time alert toast & notification banner", True),
        (13.5, 1.5, 1.7, "10: Log security alert with mitigation guidance", False),
    ]

    for x1, x2, y, msg, self_call in messages:
        if self_call:
            ax.plot([x1, x1 + 0.6, x1 + 0.6, x1], [y + 0.25, y + 0.25, y - 0.1, y - 0.1], color="#283593", lw=1.5)
            ax.annotate("", xy=(x1, y - 0.1), xytext=(x1 + 0.1, y - 0.1),
                        arrowprops=dict(arrowstyle="->", color="#283593", lw=1.5, mutation_scale=10))
            ax.text(x1 + 0.7, y + 0.08, msg, ha="left", va="center", fontsize=8.5, color="#1A237E", fontweight="semibold")
        else:
            is_return = "Return" in msg or "Log" in msg
            style = "->"
            ls = "--" if is_return else "-"
            color = "#D84315" if ("Alert" in msg or "Breached" in msg) else "#1565C0"
            ax.annotate("", xy=(x2, y), xytext=(x1, y),
                        arrowprops=dict(arrowstyle=style, linestyle=ls, color=color, lw=1.6, mutation_scale=12))
            mx = (x1 + x2) / 2
            ax.text(mx, y + 0.16, msg, ha="center", va="center", fontsize=8.5, color=color, fontweight="semibold",
                    bbox=dict(boxstyle="round,pad=0.1", facecolor="#ffffff", edgecolor="#CFD8DC", lw=0.6))

    plt.tight_layout()
    out_path = os.path.join(diag_dir, "sequence_detection.png")
    plt.savefig(out_path, dpi=200, bbox_inches="tight")
    plt.close()
    print("Sequence diagram saved to:", out_path)

if __name__ == "__main__":
    generate_component_diagram()
    generate_sequence_detection()
