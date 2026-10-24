def test_alerts_empty_list_when_no_alerts(client):
    response = client.get("/alerts")
    assert response.status_code == 200
    assert response.json() == []


def test_alerts_contain_expected_fields(client, add_alert):
    add_alert(ts=5.0, severity="medium", rule="Port scan", description="40 ports")

    alert = client.get("/alerts").json()[0]

    assert set(alert) == {"id", "ts", "severity", "rule", "description"}
    assert alert["severity"] == "medium"
    assert alert["rule"] == "Port scan"


def test_alerts_returned_newest_first(client, add_alert):
    add_alert(ts=10.0, description="first")
    add_alert(ts=30.0, description="third")
    add_alert(ts=20.0, description="second")

    descriptions = [a["description"] for a in client.get("/alerts").json()]

    assert descriptions == ["third", "second", "first"]


def test_alerts_limit_is_applied(client, add_alert):
    for i in range(6):
        add_alert(ts=float(i))

    assert len(client.get("/alerts?limit=2").json()) == 2


def test_alerts_rejects_invalid_limit(client):
    assert client.get("/alerts?limit=0").status_code == 422
