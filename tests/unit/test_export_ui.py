def test_dashboard_page_has_packet_export_links(client):
    html = client.get("/").text

    assert 'id="export-packets-csv"' in html
    assert 'id="export-packets-json"' in html
    assert "/export/packets?" in html


def test_dashboard_page_has_alert_export_links(client):
    html = client.get("/").text

    assert 'href="/export/alerts?format=csv"' in html
    assert 'href="/export/alerts?format=json"' in html
