import csv
import io
import json
import time


def _rows(response):
    return list(csv.reader(io.StringIO(response.text)))


def test_export_packets_csv_has_header_and_rows(client, add_packet):
    now = time.time()
    add_packet(now - 1, src="10.0.0.1", dst="10.0.0.2", protocol="TCP", length=60, info="a")
    add_packet(now, src="10.0.0.3", dst="10.0.0.4", protocol="DNS", length=70, info="b")

    response = client.get("/export/packets")
    rows = _rows(response)

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/csv")
    assert 'filename="packets.csv"' in response.headers["content-disposition"]
    assert rows[0] == ["id", "ts", "src", "dst", "protocol", "length", "info"]
    assert [r[2] for r in rows[1:]] == ["10.0.0.3", "10.0.0.1"]  # newest first


def test_export_packets_json(client, add_packet):
    add_packet(time.time(), src="10.0.0.1", protocol="UDP")

    response = client.get("/export/packets?format=json")

    assert response.headers["content-type"].startswith("application/json")
    assert 'filename="packets.json"' in response.headers["content-disposition"]
    assert json.loads(response.text)[0]["protocol"] == "UDP"


def test_export_packets_uses_filters(client, add_packet):
    now = time.time()
    add_packet(now, protocol="TCP")
    add_packet(now, protocol="DNS")

    rows = _rows(client.get("/export/packets?protocol=dns"))

    assert len(rows) == 2
    assert rows[1][4] == "DNS"


def test_export_packets_empty_still_has_header(client):
    assert _rows(client.get("/export/packets")) == [
        ["id", "ts", "src", "dst", "protocol", "length", "info"]
    ]


def test_export_neutralises_spreadsheet_formulas(client, add_packet):
    add_packet(time.time(), info="=HYPERLINK(\"http://evil\")")
    add_packet(time.time(), info="+1+1")
    add_packet(time.time(), info="plain text")

    infos = sorted(r[6] for r in _rows(client.get("/export/packets"))[1:])

    assert infos == ["'+1+1", "'=HYPERLINK(\"http://evil\")", "plain text"]


def test_export_quotes_commas_and_newlines(client, add_packet):
    add_packet(time.time(), info="a,b\nc")

    assert _rows(client.get("/export/packets"))[1][6] == "a,b\nc"


def test_export_alerts_csv_and_json(client, add_alert):
    add_alert(time.time(), severity="high", rule="ARP spoofing", description="bad")

    csv_rows = _rows(client.get("/export/alerts"))
    json_rows = json.loads(client.get("/export/alerts?format=json").text)

    assert csv_rows[0] == ["id", "ts", "severity", "rule", "description"]
    assert csv_rows[1][2:] == ["high", "ARP spoofing", "bad"]
    assert json_rows[0]["rule"] == "ARP spoofing"


def test_export_rejects_unknown_format(client):
    assert client.get("/export/packets?format=xml").status_code == 422
    assert client.get("/export/alerts?format=pdf").status_code == 422
