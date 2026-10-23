"""Demo data generator for the dashboard.

Until the capture and parser modules are merged, this fills the SQLite
database with sample packets and alerts so the dashboard can be demoed.

Usage:
    python -m src.dashboard.seed          # one-off sample data
    python -m src.dashboard.seed --live   # add a new packet every second
"""
import argparse
import random
import time

from . import db

PROTOCOLS = ["TCP", "UDP", "DNS", "ARP", "ICMP"]
HOSTS = ["192.168.1.10", "192.168.1.23", "192.168.1.45", "192.168.1.1", "8.8.8.8", "142.250.77.46"]
SAMPLE_ALERTS = [
    ("high", "ARP spoofing", "Conflicting IP-MAC binding for 192.168.1.1"),
    ("medium", "Port scan", "Host 192.168.1.45 probed 40 ports in 5 seconds"),
    ("low", "DNS anomaly", "Unusual NXDOMAIN rate from 192.168.1.23"),
    ("high", "Deauth flood", "120 deauthentication frames in 10 seconds"),
]

INSERT_PACKET = "INSERT INTO packets (ts, src, dst, protocol, length, info) VALUES (?, ?, ?, ?, ?, ?)"
INSERT_ALERT = "INSERT INTO alerts (ts, severity, rule, description) VALUES (?, ?, ?, ?)"


def random_packet(now):
    protocol = random.choice(PROTOCOLS)
    src, dst = random.sample(HOSTS, 2)
    return (now, src, dst, protocol, random.randint(40, 1500), f"{protocol} sample packet")


def seed(db_path, packets=50, alerts=4):
    """Insert sample rows, spread over the last minute."""
    db.init_db(db_path)
    now = time.time()
    with db.connect(db_path) as conn:
        for i in range(packets):
            conn.execute(INSERT_PACKET, random_packet(now - (packets - i)))
        for i in range(alerts):
            severity, rule, description = SAMPLE_ALERTS[i % len(SAMPLE_ALERTS)]
            conn.execute(INSERT_ALERT, (now - (alerts - i) * 5, severity, rule, description))


def run_live(db_path, interval=1.0, alert_every=15):
    """Keep adding one packet per interval and an alert every few packets."""
    db.init_db(db_path)
    count = 0
    while True:
        now = time.time()
        with db.connect(db_path) as conn:
            conn.execute(INSERT_PACKET, random_packet(now))
            count += 1
            if count % alert_every == 0:
                severity, rule, description = random.choice(SAMPLE_ALERTS)
                conn.execute(INSERT_ALERT, (now, severity, rule, description))
        time.sleep(interval)


def main():
    parser = argparse.ArgumentParser(description="Fill the dashboard database with demo data")
    parser.add_argument("--db", default=db.DEFAULT_DB_PATH, help="SQLite file to write to")
    parser.add_argument("--live", action="store_true", help="keep adding packets until stopped")
    args = parser.parse_args()
    if args.live:
        run_live(args.db)
    else:
        seed(args.db)
        print(f"Seeded demo data into {args.db}")


if __name__ == "__main__":
    main()
