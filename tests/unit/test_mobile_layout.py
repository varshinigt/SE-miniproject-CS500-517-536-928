def test_dashboard_page_scales_to_device_width(client):
    assert 'name="viewport" content="width=device-width, initial-scale=1"' in client.get("/").text


def test_dashboard_page_has_phone_breakpoint(client):
    html = client.get("/").text

    assert "@media (max-width: 600px)" in html
    assert "#alert-feed { order: -1; }" in html
    assert ".side { display: contents; }" in html


def test_dashboard_page_hides_wide_columns_on_phones(client):
    html = client.get("/").text

    assert 'id="packet-table"' in html
    assert 'id="device-table"' in html
    assert "#packet-table th:nth-child(6)" in html


def test_dashboard_page_has_touch_sized_controls(client):
    assert "min-height: 44px" in client.get("/").text
