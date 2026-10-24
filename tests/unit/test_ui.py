def test_dashboard_page_is_served(client):
    response = client.get("/")

    assert response.status_code == 200
    assert "text/html" in response.headers["content-type"]
    assert "Pocket Packet Sniffer" in response.text


def test_dashboard_page_has_packet_table(client):
    assert 'id="packet-rows"' in client.get("/").text
