"""Count-only durable batches. Unknown usage blocks draining rather than guessing."""
import asyncio
import json
import os
import sqlite3
import uuid
from pathlib import Path

METERS = frozenset({'token_digest_count', 'prompt_digest_count'})
MAX_COUNT = 2**63 - 1


def selected(value):
    if not isinstance(value, (list, tuple)) or any(x not in METERS for x in value):
        raise ValueError('Invalid digest meter selection')
    return tuple(sorted(set(value)))


class Counts:
    """Parse bounded host JSON/SSE in memory; retain only the final integer count."""
    def __init__(self, streaming):
        self.streaming = streaming
        self.buffer = b''
        self.tokens = None
        self.invalid = False

    def accept(self, raw):
        try:
            data = json.loads(raw)
            if not isinstance(data, dict) or data.get('usage') is None:
                return
            value = data['usage']['total_tokens']
            if type(value) is not int or not 0 <= value <= MAX_COUNT:
                raise ValueError()
            if self.tokens is not None and self.tokens != value:
                raise ValueError()
            self.tokens = value
        except (ValueError, KeyError, TypeError):
            self.invalid = True

    def feed(self, chunk):
        if self.invalid:
            return
        self.buffer += chunk
        if len(self.buffer) > 1024 * 1024:
            self.invalid = True
            self.buffer = b''
            return
        if self.streaming:
            while b'\n' in self.buffer:
                line, self.buffer = self.buffer.split(b'\n', 1)
                self.line(line)

    def line(self, line):
        if line.startswith(b'data:') and line[5:].strip() != b'[DONE]':
            self.accept(line[5:].strip())

    def finish(self):
        if self.streaming:
            self.line(self.buffer)
        elif self.buffer:
            self.accept(self.buffer)
        self.buffer = b''
        return None if self.invalid else self.tokens


class DigestQueue:
    def __init__(self, path):
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(path)
        self.db.execute('PRAGMA synchronous=FULL')
        self.db.executescript('''
            CREATE TABLE IF NOT EXISTS requests (
                id TEXT PRIMARY KEY, tenant TEXT NOT NULL, lease TEXT NOT NULL,
                meters TEXT NOT NULL, complete INTEGER NOT NULL DEFAULT 0);
            CREATE TABLE IF NOT EXISTS batches (
                request TEXT NOT NULL REFERENCES requests(id), meter TEXT NOT NULL,
                quantity INTEGER NOT NULL, sent INTEGER NOT NULL DEFAULT 0, attempts INTEGER NOT NULL DEFAULT 0,
                PRIMARY KEY(request,meter));
            CREATE TABLE IF NOT EXISTS fences (tenant TEXT, lease TEXT, PRIMARY KEY(tenant,lease));
        ''')

        if 'attempts' not in {r[1] for r in self.db.execute('PRAGMA table_info(batches)')}:
            with self.db:
                self.db.execute('ALTER TABLE batches ADD COLUMN attempts INTEGER NOT NULL DEFAULT 0')

        if 'organization' not in {r[1] for r in self.db.execute('PRAGMA table_info(requests)')}:
            with self.db:
                self.db.execute("ALTER TABLE requests ADD COLUMN organization TEXT NOT NULL DEFAULT ''")

    def begin(self, tenant, lease, meters, *, organization=None):
        meters = selected(meters)
        if not meters:
            raise ValueError('Digest meters required')
        identifier = str(uuid.uuid4())
        with self.db:
            self.db.execute('BEGIN IMMEDIATE')
            if self.db.execute('SELECT 1 FROM fences WHERE tenant=? AND lease=?', (str(tenant), str(lease))).fetchone():
                raise ValueError('Lease is draining')
            if self.db.execute('SELECT count(*) FROM requests WHERE tenant=? AND organization=?', (str(tenant),str(organization) if organization else '')).fetchone()[0] >= 1024:
                raise ValueError('Organization digest queue is full')
            if self.db.execute('SELECT count(*) FROM requests WHERE tenant=? AND lease=?', (str(tenant),str(lease))).fetchone()[0] >= 128:
                raise ValueError('Lease digest queue is full')
            self.db.execute('INSERT INTO requests(id,tenant,lease,meters,organization) VALUES(?,?,?,?,?)',
                            (identifier, str(tenant), str(lease), json.dumps(meters), str(organization) if organization else ''))
        return identifier

    def discard_unstarted(self, identifier):
        with self.db:
            self.db.execute('DELETE FROM requests WHERE id=? AND complete=0 AND NOT EXISTS(SELECT 1 FROM batches WHERE request=?)', (identifier,identifier))

    def finish(self, identifier, tokens):
        with self.db:
            row = self.db.execute('SELECT meters,complete FROM requests WHERE id=?', (identifier,)).fetchone()
            if row is None or row[1]:
                raise ValueError('Unknown or completed count request')
            meters = json.loads(row[0])
            if 'token_digest_count' in meters and (type(tokens) is not int or not 0 <= tokens <= MAX_COUNT):
                return False
            for meter in meters:
                self.db.execute('INSERT INTO batches(request,meter,quantity) VALUES(?,?,?)',
                                (identifier, meter, tokens if meter == 'token_digest_count' else 1))
            self.db.execute('UPDATE requests SET complete=1 WHERE id=?', (identifier,))
        return True

    def fence(self, tenant, lease):
        with self.db:
            self.db.execute('INSERT OR IGNORE INTO fences VALUES(?,?)', (str(tenant), str(lease)))

    def fenced(self, tenant, lease):
        return bool(self.db.execute('SELECT 1 FROM fences WHERE tenant=? AND lease=?', (str(tenant), str(lease))).fetchone())

    def drained(self, tenant, lease):
        return not self.db.execute('''SELECT 1 FROM requests r WHERE tenant=? AND lease=?
            AND (complete=0 OR EXISTS(SELECT 1 FROM batches b WHERE b.request=r.id AND sent=0))''',
            (str(tenant), str(lease))).fetchone()

    async def flush(self, plane, *, tenant=None, lease=None):
        rows = self.db.execute('''SELECT r.id,r.tenant,r.lease,b.meter,b.quantity FROM requests r
            JOIN batches b ON b.request=r.id WHERE b.sent=0 AND (? IS NULL OR r.tenant=?)
            AND (? IS NULL OR r.lease=?) ORDER BY b.attempts,r.rowid,b.meter LIMIT 100''',
            (str(tenant) if tenant else None, str(tenant), str(lease) if lease else None, str(lease))).fetchall()
        deadline = asyncio.get_running_loop().time() + 1
        for identifier, owner, resource, meter, quantity in rows:
            if asyncio.get_running_loop().time() >= deadline:
                break
            with self.db:
                self.db.execute('UPDATE batches SET attempts=attempts+1 WHERE request=? AND meter=?', (identifier, meter))
            try:
                async with asyncio.timeout_at(deadline):
                    await plane.post_reading(uuid.UUID(owner), uuid.UUID(resource),
                                         {'meter':meter, 'quantity':quantity, 'batch_id':identifier})
            except Exception:
                continue
            with self.db:
                self.db.execute('UPDATE batches SET sent=1 WHERE request=? AND meter=?', (identifier, meter))
                if not self.db.execute('SELECT 1 FROM batches WHERE request=? AND sent=0', (identifier,)).fetchone():
                    self.db.execute('DELETE FROM batches WHERE request=?', (identifier,))
                    self.db.execute('DELETE FROM requests WHERE id=? AND complete=1', (identifier,))

    def close(self):
        self.db.close()


def configured():
    flag = os.environ.get('HYPERMESH_DIGEST_METERS_ENABLED', 'false')
    if flag not in {'true', 'false'}:
        raise ValueError('Invalid digest meter flag')
    if flag == 'false':
        return None
    path = os.environ.get('HYPERMESH_DIGEST_QUEUE_PATH')
    if not path or path == ':memory:':
        raise ValueError('Durable digest queue path required')
    return DigestQueue(path)
