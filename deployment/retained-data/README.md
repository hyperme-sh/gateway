# Gateway retained-data migrations

The history and training owner stores use separate logical PostgreSQL
databases and separate runtime roles. Gateway v0.2.0 uses unqualified model
names, so each migration installs its own tables in its database's `public`
schema.

| Migration | Database | Runtime role |
| --- | --- | --- |
| `0001-history.sql` | `gateway_history` | `gateway_history_runtime` |
| `0001-training.sql` | `gateway_training` | `gateway_training_runtime` |

The Infra database deployment path creates the dedicated databases and binds
each runtime role to its corresponding identity. The database owner applies
the initial migration to each empty database with stop-on-error enabled and
records the applied migration. Each migration runs in a transaction and checks
the destination database and runtime role before making changes.

Populate `public.tenants` with authorized tenant UUIDs from the Control Plane
tenant registry through an administrative path separate from the runtime roles.
Keep that mapping current as tenants are provisioned. The foreign keys require
a matching tenant before the application can write an account record.

Gateway sets the tenant UUID for each transaction. Row policies use that UUID
for both visibility and writes. Runtime grants cover the shipped account
closure, consent-off and deletion paths. The payload tables allow reads and
deletes only.

Container delivery uses the migrated databases as dependencies. A container
rollback retains the schema and rows. If database access must be withdrawn,
revoke the affected store's runtime access through its owning deployment path.
