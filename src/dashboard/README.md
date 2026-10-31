# Dashboard (F4)

Live web dashboard and REST API for Pocket Packet Sniffer. It reads captured
packets and alerts from the SQLite database and shows them in the browser:
live packet table, protocol chart, device inventory and alert feed, with
search, filters, CSV/JSON export and a phone-friendly layout.

## Run

```bash
pip install -r requirements-dashboard.txt
python -m src.dashboard.seed                                  # sample packets and alerts
uvicorn src.dashboard.app:create_app --factory --reload       # start the server
```

Open http://127.0.0.1:8000. For a live demo, run `python -m src.dashboard.seed --live`
in a second terminal: a new packet appears every second.

Set `PPS_DB_PATH` to use a different database file (default `data/sniffer.db`).

To open the dashboard on a phone on the same network, start the server with
`--host 0.0.0.0` and browse to `http://<computer-ip>:8000`. Only do this on a
network you own or are allowed to monitor.

## Endpoints

| Method | Path | Description |
| :--- | :--- | :--- |
| GET | `/health` | Returns `{"status": "ok"}` |
| GET | `/packets` | Latest packets, newest first. Query: `limit` (1-1000), `protocol`, `host`, `q` |
| GET | `/alerts?limit=100` | Latest alerts, newest first (limit 1-1000) |
| GET | `/stats?window=60` | Packet counts per protocol in the last `window` seconds |
| GET | `/devices?window=300&limit=50` | Hosts seen in the last `window` seconds with packet and byte counts |
| GET | `/export/packets` | Download packets as CSV or JSON: `format`, `limit`, plus the same filters as `/packets` |
| GET | `/export/alerts` | Download alerts as CSV or JSON: `format`, `limit` |
| WS | `/ws/live` | Pushes packets, alerts, stats and devices every 0.5 s; accepts the packet filters |
| GET | `/` | The dashboard page |

Packet filters: `protocol` is an exact, case-insensitive protocol name, `host` is an
exact address that is the source or destination, and `q` is free text matched in
source, destination, protocol and info. Exports neutralise cells that start with
`=`, `+`, `-` or `@` so spreadsheets do not run captured text as a formula.

If the WebSocket drops, the page falls back to polling every second and reconnects
automatically.

## Latency check (NFR-PERF-03)

With the dashboard running on the same database:

```bash
python -m src.dashboard.latency --samples 20 --report docs/Latency_Report.md
```

It writes marker packets, times how long each takes to arrive on `/ws/live`, prints
the result and exits with a non-zero code if the 95th percentile is not under 1 second.

## Tests

```bash
pytest --cov=src/dashboard --cov-branch --cov-report=term-missing
```

## Structure

- `app.py`: app factory, registers every router in `routes/` automatically
- `db.py`: SQLite connection and schema
- `queries.py`: read queries shared by the REST routes and the WebSocket stream
- `routes/`: one file per endpoint group (adding an endpoint = adding a file)
- `static/index.html`: single-page dashboard (WebSocket with polling fallback)
- `seed.py`: demo data generator
- `latency.py`: dashboard latency measurement tool
