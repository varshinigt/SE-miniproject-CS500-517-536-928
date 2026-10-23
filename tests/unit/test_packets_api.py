def test_packets_empty_list_when_no_data(client):
    response = client.get("/packets")
    assert response.status_code == 200
    assert response.json() == []


def test_packets_returned_newest_first(client, add_packet):
    add_packet(ts=100.0, info="old")
    add_packet(ts=300.0, info="newest")
    add_packet(ts=200.0, info="middle")

    infos = [p["info"] for p in client.get("/packets").json()]

    assert infos == ["newest", "middle", "old"]


def test_packets_contain_expected_fields(client, add_packet):
    add_packet(ts=1.0, src="1.1.1.1", dst="2.2.2.2", protocol="UDP", length=99, info="x")

    packet = client.get("/packets").json()[0]

    assert set(packet) == {"id", "ts", "src", "dst", "protocol", "length", "info"}
    assert packet["src"] == "1.1.1.1"
    assert packet["protocol"] == "UDP"
    assert packet["length"] == 99


def test_packets_limit_is_applied(client, add_packet):
    for i in range(10):
        add_packet(ts=float(i))

    assert len(client.get("/packets?limit=3").json()) == 3


def test_packets_default_limit_is_100(client, add_packet):
    for i in range(120):
        add_packet(ts=float(i))

    assert len(client.get("/packets").json()) == 100


def test_packets_rejects_invalid_limit(client):
    assert client.get("/packets?limit=0").status_code == 422
    assert client.get("/packets?limit=5000").status_code == 422
