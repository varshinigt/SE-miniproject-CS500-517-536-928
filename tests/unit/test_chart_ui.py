def test_dashboard_page_has_protocol_chart(client):
    html = client.get("/").text

    assert 'id="chart-panel"' in html
    assert 'id="protocol-chart"' in html


def test_dashboard_page_loads_chart_library_and_stats(client):
    html = client.get("/").text

    assert "Chart.js/4.4.1" in html
    assert "/stats?window=60" in html
