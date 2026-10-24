def test_dashboard_page_has_alert_feed(client):
    html = client.get("/").text

    assert 'id="alert-feed"' in html
    assert 'id="alert-list"' in html


def test_dashboard_page_highlights_severity(client):
    html = client.get("/").text

    for level in ("sev-high", "sev-medium", "sev-low"):
        assert level in html
