"""Private payload stores must never emit SQL parameters or debug result rows."""
import logging
import os
from pathlib import Path
import ssl

from sqlalchemy.engine import make_url
from sqlalchemy.ext.asyncio import create_async_engine
from controlplane_db.session import normalize_database_url


def private_engine(url: str, name: str, *, passfile: str = "", **engine_options):
    url = normalize_database_url(url)
    if passfile:
        binding = make_url(url)
        if (not Path(passfile).is_absolute() or "PGPASSWORD" in os.environ
                or binding.drivername != "postgresql+asyncpg" or binding.password is not None
                or not binding.host or binding.host.startswith("/") or not binding.username
                or not binding.database or binding.query):
            raise ValueError("Retained data needs a password-free PostgreSQL URL and an absolute credential path")
        # asyncpg opens this file for each new connection. The host can
        # replace it atomically without exposing its identity to Gateway.
        engine_options["connect_args"] = {"passfile": passfile, "ssl": ssl.create_default_context()}

    # hide_parameters does not hide SQLAlchemy's DEBUG result-row logging.
    # Give private engines a non-propagating logger, even when the parent SQL
    # logger is DEBUG. Availability failures use the app's payload-free logs.
    logger=logging.getLogger(f'sqlalchemy.engine.Engine.{name}')
    logger.setLevel(logging.WARNING)
    logger.propagate=False
    if not any(isinstance(handler,logging.NullHandler) for handler in logger.handlers):
        logger.addHandler(logging.NullHandler())
    return create_async_engine(url, echo=False, hide_parameters=True,
                               logging_name=name, **engine_options)
