def test_dashboard_page_has_filter_bar(client):
    html = client.get("/").text

    for element_id in ("filter-bar", "filter-protocol", "filter-host", "filter-search", "filter-clear"):
        assert f'id="{element_id}"' in html


def test_dashboard_page_sends_filters_to_api(client):
    html = client.get("/").text

    assert "params.set(\"protocol\"" in html
    assert "params.set(\"host\"" in html
    assert "params.set(\"q\"" in html
