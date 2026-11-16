"""FastAPI application factory for the dashboard (F4).

Every module inside ``routes/`` exposes a ``router``. They are registered
automatically, so adding a new endpoint means adding one new file.
"""
import importlib
import pkgutil
from typing import Optional

from fastapi import FastAPI

from . import db, routes


def create_app(db_path: Optional[str] = None, push_interval: float = 0.5) -> FastAPI:
    """Build the dashboard app. ``push_interval`` is the WebSocket update period in seconds."""
    app = FastAPI(title="Pocket Packet Sniffer Dashboard API")
    app.state.db_path = db_path or db.DEFAULT_DB_PATH
    app.state.push_interval = push_interval
    db.init_db(app.state.db_path)

    for module_info in pkgutil.iter_modules(routes.__path__):
        module = importlib.import_module(f"{routes.__name__}.{module_info.name}")
        app.include_router(module.router)

    return app
