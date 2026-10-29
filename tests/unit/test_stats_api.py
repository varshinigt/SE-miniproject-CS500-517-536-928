import time


def test_stats_empty_database(client):
    body = client.get("/stats").json()

    assert body == {"window": 60, "total": 0, "by_protocol": {}}


def test_stats_counts_packets_per_protocol(client, add_packet):
    now = time.time()
    add_packet(now, protocol="TCP")
    add_packet(now, protocol="TCP")
    add_packet(now, protocol="DNS")

    body = client.get("/stats").json()

    assert body["total"] == 3
    assert body["by_protocol"] == {"TCP": 2, "DNS": 1}


def test_stats_ignores_packets_outside_window(client, add_packet):
    now = time.time()
    add_packet(now, protocol="UDP")
    add_packet(now - 3600, protocol="ARP")

    body = client.get("/stats?window=60").json()

    assert body["by_protocol"] == {"UDP": 1}


def test_stats_rejects_invalid_window(client):
    assert client.get("/stats?window=0").status_code == 422
