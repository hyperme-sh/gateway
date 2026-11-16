"""Count-only durable markers. No prompts, generated output or private keys."""

import json
from .wire import Refusal

MAX_ORGANIZATION_HISTORY = 4096


class Journal:
    def __init__(self, queue):
        self.queue = queue
        queue.db.execute(
            "CREATE TABLE IF NOT EXISTS trusted_requests (id TEXT PRIMARY KEY, state TEXT NOT NULL)"
        )
        queue.db.execute(
            "CREATE TABLE IF NOT EXISTS trusted_repairs (id TEXT PRIMARY KEY, tenant TEXT NOT NULL, lease TEXT NOT NULL, state TEXT NOT NULL)"
        )
        if "organization" not in {
            r[1] for r in queue.db.execute("PRAGMA table_info(trusted_repairs)")
        }:
            queue.db.execute(
                "ALTER TABLE trusted_repairs ADD COLUMN organization TEXT NOT NULL DEFAULT ''"
            )
        queue.db.execute(
            "CREATE INDEX IF NOT EXISTS trusted_repairs_owner ON trusted_repairs(tenant,organization)"
        )
        queue.db.commit()

    def save(self, batch, state):
        raw = json.dumps(state, sort_keys=True, separators=(",", ":"), allow_nan=False)
        if len(raw.encode()) > 1024 * 1024:
            raise Refusal("trusted_state_oversized")
        with self.queue.db:
            self.queue.db.execute("BEGIN IMMEDIATE")
            owner = self.queue.db.execute(
                "SELECT tenant,organization FROM requests WHERE id=?", (batch,)
            ).fetchone()
            if owner is None or owner[0] != state["binding"]["tenant_id"]:
                raise Refusal("unknown_pending_request")
            if not self.queue.db.execute(
                "SELECT 1 FROM trusted_requests WHERE id=?", (batch,)
            ).fetchone():
                retained = self.queue.db.execute(
                    "SELECT count(*) FROM trusted_repairs WHERE tenant=? AND organization=?",
                    owner,
                ).fetchone()[0]
                active = self.queue.db.execute(
                    "SELECT count(*) FROM trusted_requests t JOIN requests r ON r.id=t.id WHERE r.tenant=? AND r.organization=?",
                    owner,
                ).fetchone()[0]
                needed = retained + active + 1 - MAX_ORGANIZATION_HISTORY
                if needed > 0:
                    # Plane retains canonical history. Reclaim only completed
                    # local copies, never pending requests or archived disputes.
                    removed = self.queue.db.execute(
                        "DELETE FROM trusted_repairs WHERE id IN (SELECT id FROM trusted_repairs WHERE tenant=? AND organization=? AND json_extract(state,'$.phase')='recovered' ORDER BY rowid LIMIT ?)",
                        (*owner, needed),
                    ).rowcount
                    if removed < needed:
                        raise Refusal("trusted_history_capacity")
            self.queue.db.execute(
                "INSERT INTO trusted_requests VALUES (?,?) ON CONFLICT(id) DO UPDATE SET state=excluded.state",
                (batch, raw),
            )

    def retired(self, batch):
        with self.queue.db:
            row = self.queue.db.execute(
                "SELECT t.state,r.organization FROM trusted_requests t JOIN requests r ON r.id=t.id WHERE t.id=?",
                (batch,),
            ).fetchone()
            if not row or not json.loads(row[0]).get("recovery"):
                raise Refusal("recovery_not_committed")
            state = json.loads(row[0])
            binding = state["binding"]
            self.queue.db.execute(
                "INSERT INTO trusted_repairs(id,tenant,lease,state,organization) VALUES (?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET state=excluded.state",
                (batch, binding["tenant_id"], binding["lease_id"], row[0], row[1]),
            )
            self.queue.db.execute("DELETE FROM trusted_requests WHERE id=?", (batch,))
            self.queue.db.execute("DELETE FROM requests WHERE id=?", (batch,))

    def load(self, tenant, lease, batch):
        row = self.queue.db.execute(
            "SELECT t.state FROM requests r LEFT JOIN trusted_requests t ON t.id=r.id "
            "WHERE r.tenant=? AND r.lease=? AND r.id=?",
            (str(tenant), str(lease), str(batch)),
        ).fetchone()
        if row is None:
            archived = self.queue.db.execute(
                "SELECT state FROM trusted_repairs WHERE tenant=? AND lease=? AND id=?",
                (str(tenant), str(lease), str(batch)),
            ).fetchone()
            if archived:
                value = json.loads(archived[0])
                value["locally_retired"] = True
                return value
            raise Refusal("unknown_pending_request")
        return json.loads(row[0]) if row[0] else None
