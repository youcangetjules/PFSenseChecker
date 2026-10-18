# NetCheck agent notes

## Command queue

Deal with every queued command sequentially, in the order it was given.
A command that arrives while work is in progress is appended to the queue.
Do not start it until the current command is finished.

The only interruption is a direct command to **STOP** or **WAIT**, followed by an urgent directive.
Halt the queue, carry out that directive, then resume what was queued unless STOP ended the work.

Examples:

- “Fix the drop target.” Then, before that is done: “Also open a console.” Finish the drop target, then the console.
- “STOP the console. WAIT: Login is writing the password into the log.” Stop the console work and fix the password leak before anything else left in the queue.

## Records

Read `SKILLS.md` for the operator profile.

- `worklog.md` — daily update of work done. Newest day first.
- `buglog.md` — every bug seen, open or fixed. No passwords, hashes, or tokens.
- `versions.py` — SemVer (`SEMVER`) and commit sequence (`SEQUENCE`). Every commit increments `SEQUENCE` by 1 via `hooks/pre-commit`. Install that hook with `sh hooks/install` (do not set `core.hooksPath`). The product changelog stays in `pfsense_checker/version.py` and uses the same SemVer.

## Data

PostgreSQL is the main database type (`netcheck`). Do not add a second primary store.

PostgreSQL will hold:

- Topologies and non-standard data (graphs, JSONB, vendor-specific blobs, other PostgreSQL types as needed)
- *Some* time-series data (not everything; TimescaleDB only where metrics/logs justify it)
- Geo-data as vectors (PostGIS geometry/geography — points, lines, polygons — not rasters, not embedding vectors)

Schema lives in `pfsense_checker/netcheck_schema.py`. Idempotent DDL only. Parameterized SQL (`%s`). Passwords never in PostgreSQL.
