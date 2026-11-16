def test_dashboard_page_has_device_inventory(client):
    html = client.get("/").text

    assert 'id="device-panel"' in html
    assert 'id="device-rows"' in html


def test_dashboard_page_fetches_devices(client):
    assert "/devices?window=300" in client.get("/").text
