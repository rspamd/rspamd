# Multistage integration tests

These tests run only in disposable Linux containers. They configure the
container's Postfix and use deterministic DNS answers. No host mounts, mail
delivery or external network are needed while running tests.

Build with a clean checkout in `source/` and this directory in `fixture/`:

```sh
docker build -f fixture/Dockerfile -t rspamd-multistage:test .
docker run --rm --network none -e MILTER_TRANSPORT=tcp rspamd-multistage:test
docker run --rm --network none -e MILTER_TRANSPORT=unix rspamd-multistage:test
docker run --rm --network none --entrypoint python3 rspamd-multistage:test \
  -u /opt/postfix-data/failure.py
```

`test.py` covers actual Postfix SMTP replies, queue contents, repeated
transactions, recipient policy conflicts, DATA timeout, transport fallback,
observer failure, pipelining, BDAT and concurrency in self-scan and remote modes.

`configuration.py` validates the shipped disabled default, `local.d` and
`override.d` precedence, and rejection of an enabled configuration without a key.

`failure.py` routes DATA and EOM to distinct normal worker processes with the
same configuration. It verifies producer identity, scanner restart and reload
between passes, bounded observer completion and counters. Its `BENCHMARK` JSON
lines compare 120 accepted transactions at concurrency eight through the
DATA+EOM and EOM-only milter paths, including p50/p95, throughput, worker CPU,
RSS and EOM SPF/DNS counts. This is a deterministic smoke benchmark with fake
DNS, not an estimate of production throughput; timing is reported rather than
used as a machine-dependent pass threshold.

`clickhouse.py` uses a real ClickHouse server on loopback port 8123. Run the
Rspamd image with `--network container:<clickhouse-container>` and entrypoint
`python3 -u /opt/postfix-data/clickhouse.py`. The test creates fresh and populated
v12 databases, checks the v13 migration, unchanged numeric column types, DATA
availability flags, EOM values and exactly one row per terminal scan. The
frozen `schema12.sql` fixture intentionally does not follow the current schema.

`.github/workflows/ci_multistage.yml` builds and runs all three checks, pins
ClickHouse 25.8, and retains logs and benchmark output as CI artifacts.
