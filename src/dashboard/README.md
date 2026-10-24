# Dashboard (F4)

Live web dashboard and REST API for Pocket Packet Sniffer. It reads captured
packets and alerts from the SQLite database and shows them in the browser.

## Run

```bash
pip install -r requirements-dashboard.txt
python -m src.dashboard.seed                                  # sample packets and alerts
uvicorn src.dashboard.app:create_app --factory --reload       # start the server
```

Open http://127.0.0.1:8000. For a live demo, run `python -m src.dashboard.seed --live`
in a second terminal: a new packet appears every second.

Set `PPS_DB_PATH` to use a different database file (default `data/sniffer.db`).

## Endpoints

| Method | Path | Description |
| :--- | :--- | :--- |
| GET | `/health` | Returns `{"status": "ok"}` |
| GET | `/packets?limit=100` | Latest packets, newest first (limit 1-1000) |
| GET | `/alerts?limit=100` | Latest alerts, newest first (limit 1-1000) |
| GET | `/` | The dashboard page |

## Tests

```bash
pytest --cov=src/dashboard --cov-branch --cov-report=term-missing
```

## Structure

- `app.py`: app factory, registers every router in `routes/` automatically
- `db.py`: SQLite connection and schema
- `routes/`: one file per endpoint group (adding an endpoint = adding a file)
- `static/index.html`: single-page dashboard (polls the API every second)
- `seed.py`: demo data generator
