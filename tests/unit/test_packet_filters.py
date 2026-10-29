import time


def _seed(add_packet):
    now = time.time()
    add_packet(now - 4, src="10.0.0.1", dst="10.0.0.2", protocol="TCP", info="HTTP GET /index")
    add_packet(now - 3, src="10.0.0.1", dst="8.8.8.8", protocol="DNS", info="query example.com")
    add_packet(now - 2, src="10.0.0.3", dst="10.0.0.1", protocol="ARP", info="who has 10.0.0.1")
    add_packet(now - 1, src="10.0.0.4", dst="10.0.0.5", protocol="UDP", info="100% load_test")


def _ids(client, query):
    return [p["protocol"] for p in client.get(f"/packets?{query}").json()]


def test_filter_by_protocol_is_case_insensitive(client, add_packet):
    _seed(add_packet)

    assert _ids(client, "protocol=dns") == ["DNS"]
    assert _ids(client, "protocol=TCP") == ["TCP"]


def test_filter_by_host_matches_source_or_destination(client, add_packet):
    _seed(add_packet)

    assert _ids(client, "host=10.0.0.1") == ["ARP", "DNS", "TCP"]


def test_search_matches_info_text(client, add_packet):
    _seed(add_packet)

    assert _ids(client, "q=example.com") == ["DNS"]


def test_search_matches_address_and_protocol(client, add_packet):
    _seed(add_packet)

    assert _ids(client, "q=8.8.8") == ["DNS"]
    assert _ids(client, "q=arp") == ["ARP"]


def test_search_treats_wildcards_literally(client, add_packet):
    _seed(add_packet)

    add_packet(time.time(), src="10.0.0.6", dst="10.0.0.7", protocol="ICMP", info="100 loadXtest")

    assert _ids(client, "q=100%25") == ["UDP"]  # "%" is not a wildcard
    assert _ids(client, "q=load_test") == ["UDP"]  # "_" is not a wildcard
    assert _ids(client, "q=%25") == ["UDP"]


def test_filters_combine(client, add_packet):
    _seed(add_packet)

    assert _ids(client, "host=10.0.0.1&protocol=tcp") == ["TCP"]
    assert _ids(client, "host=10.0.0.1&protocol=udp") == []


def test_filter_respects_limit(client, add_packet):
    _seed(add_packet)

    assert len(client.get("/packets?host=10.0.0.1&limit=2").json()) == 2


def test_search_is_safe_against_sql_injection(client, add_packet):
    _seed(add_packet)

    assert client.get("/packets?q=' OR 1=1 --").json() == []
    assert len(client.get("/packets").json()) == 4
