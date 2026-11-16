import time


def test_devices_empty_database(client):
    assert client.get("/devices").json() == []


def test_devices_aggregates_sent_and_received(client, add_packet):
    now = time.time()
    add_packet(now, src="10.0.0.1", dst="10.0.0.2", protocol="TCP", length=100)
    add_packet(now, src="10.0.0.1", dst="10.0.0.2", protocol="DNS", length=50)
    add_packet(now, src="10.0.0.2", dst="10.0.0.1", protocol="TCP", length=10)

    devices = {d["ip"]: d for d in client.get("/devices").json()}

    assert devices["10.0.0.1"]["sent"] == 2
    assert devices["10.0.0.1"]["received"] == 1
    assert devices["10.0.0.1"]["packets"] == 3
    assert devices["10.0.0.1"]["bytes"] == 160
    assert devices["10.0.0.1"]["protocols"] == ["DNS", "TCP"]
    assert devices["10.0.0.2"]["sent"] == 1
    assert devices["10.0.0.2"]["received"] == 2


def test_devices_most_recent_first_then_by_address(client, add_packet):
    now = time.time()
    add_packet(now - 30, src="10.0.0.1", dst="10.0.0.2")
    add_packet(now, src="10.0.0.3", dst="10.0.0.4")

    ips = [d["ip"] for d in client.get("/devices").json()]

    assert ips == ["10.0.0.3", "10.0.0.4", "10.0.0.1", "10.0.0.2"]


def test_devices_ignores_packets_outside_window(client, add_packet):
    now = time.time()
    add_packet(now, src="10.0.0.1", dst="10.0.0.2")
    add_packet(now - 3600, src="10.9.9.9", dst="10.9.9.8")

    ips = {d["ip"] for d in client.get("/devices?window=60").json()}

    assert ips == {"10.0.0.1", "10.0.0.2"}


def test_devices_respects_limit(client, add_packet):
    now = time.time()
    for i in range(5):
        add_packet(now - i, src=f"10.0.1.{i}", dst=f"10.0.2.{i}")

    assert len(client.get("/devices?limit=3").json()) == 3


def test_devices_rejects_invalid_limit(client):
    assert client.get("/devices?limit=0").status_code == 422
