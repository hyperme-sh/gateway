"""Count-only durable markers. No prompts, generated output or private keys."""

import json
from .wire import Refusal


class Journal:
    def __init__(self, queue):
        self.queue = queue
        queue.db.execute(
            "CREATE TABLE IF NOT EXISTS trusted_requests (id TEXT PRIMARY KEY, state TEXT NOT NULL)"
        )
        queue.db.commit()

    def save(self, batch, state):
        raw = json.dumps(state, sort_keys=True, separators=(",", ":"), allow_nan=False)
        if len(raw.encode()) > 1024 * 1024:
            raise Refusal("trusted_state_oversized")
        with self.queue.db:
            if not self.queue.db.execute(
                "SELECT 1 FROM requests WHERE id=?", (batch,)
            ).fetchone():
                raise Refusal("unknown_pending_request")
            self.queue.db.execute(
                "INSERT INTO trusted_requests VALUES (?,?) ON CONFLICT(id) DO UPDATE SET state=excluded.state",
                (batch, raw),
            )

    def retired(self, batch):
        with self.queue.db:
            row = self.queue.db.execute(
                "SELECT state FROM trusted_requests WHERE id=?", (batch,)
            ).fetchone()
            if not row or not json.loads(row[0]).get("recovery"):
                raise Refusal("recovery_not_committed")
            self.queue.db.execute("DELETE FROM trusted_requests WHERE id=?", (batch,))
            self.queue.db.execute("DELETE FROM requests WHERE id=?", (batch,))
