def test_dashboard_page_opens_websocket(client):
    html = client.get("/").text

    assert "new WebSocket(" in html
    assert "/ws/live?" in html


def test_dashboard_page_falls_back_to_polling(client):
    html = client.get("/").text

    assert "startPolling" in html
    assert "/alerts?limit=20" in html
    assert "reconnecting" in html


def test_dashboard_page_shows_push_status(client):
    assert "live (push)" in client.get("/").text
