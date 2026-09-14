# Filtering at SMTP DATA

Multistage filtering runs audited envelope checks at the milter DATA callback,
before Postfix accepts message headers or a body. Enable it in
`local.d/multistage.conf`; the installed `multistage.conf.example` shows HELO,
ASN and SPF policies. Add an RBL policy using a symbol from that rule's
`returncodes`. Start with narrow policies and expand them after inspecting the
execution plan and observed results.

Use the same dedicated shared key (32–64 bytes), producer configuration and
maps on the proxy and every scanner. `openssl rand -hex 24` generates a suitable
key. Keep the file readable only by the service and administrators. The key
authenticates DATA requests, replies and portable records; it does not encrypt
the transport. Use the existing secure transport or a trusted network for
scanner connections. Proxy self-scan uses the same validation and replay path.

The normal configuration is disabled by default. Set `enabled = true` and a
key on every participant. The DATA `timeout` defaults to two seconds and must
be greater than zero and at most 30 seconds. It includes terminal observers.
The remote proxy allows another half-second for transport. Keep the MTA's
milter command timeout above that budget. Set `enabled = false` and reload to
disable DATA scanning and stop accepting portable records.

## Postfix

Configure the usual Rspamd milter proxy, for example in
`local.d/worker-proxy.inc`:

```ucl
bind_socket = "127.0.0.1:11332";
milter = true;
timeout = 120s;
upstream "local" {
  default = true;
  self_scan = true;
}
```

For a separate scanner, replace that upstream with one containing
`hosts = "scanner.example.org:11333"` and enable multistage on that scanner.
Keep existing worker counts, access restrictions and TLS settings appropriate
for the deployment. In Postfix `main.cf`:

```ini
smtpd_milters = inet:127.0.0.1:11332
non_smtpd_milters = $smtpd_milters
milter_protocol = 6
milter_default_action = tempfail
milter_command_timeout = 30s
milter_content_timeout = 120s
```

Unix sockets also work; use Postfix's `unix:` milter endpoint and ensure the
socket is accessible within any Postfix chroot. Non-SMTP and MTA paths that do
not provide DATA continue to scan at EOM. Validate with `rspamadm configtest`
and `postfix check`, then reload both services.

## Policy semantics and failure handling

DATA policies form a separate, final policy layer. A `reject` returns
`554 5.7.1`, and `soft reject` returns `451 4.7.1`, with the configured reason.
Reasons must be nonempty single-line text, at most 500 bytes. Only explicit
policies can reject here; a partial score cannot trigger ordinary thresholds.
If any recipient's applicable policy rejects, the whole transaction rejects.
An exemption for one recipient cannot exempt the others. Header/body settings
at EOM cannot reverse a DATA decision.

On a continuing transaction, compatible producer results and explicitly
exported state replay at each producer's normal EOM slot. Remaining checks,
including body checks, run normally. Scanner affinity is unnecessary: a
different scanner can validate the record. Authentication failure, timeout,
unavailable scanner, changed configuration/map, expired record, or failed
producer replay falls back to the ordinary EOM scan. A frozen rejection stays
final if an observer fails or times out. An aborted SMTP transaction never
carries results into the next transaction.

Key rotation currently uses one key per instance. During a rolling change,
instances with different keys fall back to EOM. Deploy scanner changes first,
then proxy changes; watch fallback counters while the fleet converges. Records
expire after five minutes, so a long delay before EOM can require a full scan.

## Inspecting eligibility and operation

`rspamadm configdump --exec-plan --json` and
`rspamadm configdump --symbol-details --json` show `required_inputs`,
`effective_inputs`, `replay_version`, `terminal_observer`, `data_candidate`
and `data_blocking_dependencies`. These fields contain no shared key.
They describe static admission; per-task settings, map readiness and a
producer's own checks can still defer execution. An EOM input inherited from
a dependency explains why an envelope rule cannot run early. Unversioned
producers cannot enter a portable checkpoint. Virtual symbols describe their
producer, and split RBL execution children appear separately in the plan.

The controller `/stat` response includes a `multistage` object. `/metrics`
exports the same counters as `rspamd_multistage_<name>_total`:

| Counters | Meaning |
| --- | --- |
| `data_started` | Proxy DATA scans started |
| `data_continued`, `data_rejected`, `data_tempfailed` | Completed proxy decisions; continued includes a usable authenticated record |
| `data_fallback` | Proxy continued without a record, including transport failure or scanner deadline |
| `data_cancelled`, `data_bypassed` | In-flight cancellation, or unsupported proxy configuration |
| `scanner_timeout` | DATA deadline reached on a scanner, including during observers |
| `record_imported`, `record_rejected` | EOM record validation outcomes; absence of a record is not a rejection |
| `producer_replayed`, `producer_fallback` | Individual recorded producers replayed or rerun after failed replay prerequisites/validation |
| `observer_error`, `observer_timeout` | Terminal DATA scans whose observers failed or exceeded the deadline |

The histogram `rspamd_multistage_data_duration_seconds` measures the proxy's
DATA wait, including observers and cancelled requests. Counters are shared
across workers in one instance and follow the existing statistics reset API.
Sum proxy and scanner metrics according to their distinct roles; a record
import does not mean every producer replayed. Compare latency and throughput
against disabled multistage using the same traffic and DNS/cache conditions.

## Terminal records and current boundaries

Early decisions enter statistics/history once. JSON records identify
`decision_stage = "data"`, completion kind, policy, recipient, event ID,
observer status and available inputs. Their score is partial. Message size,
MIME and body-dependent values are unavailable. ClickHouse keeps its existing
non-nullable `Size UInt32` and `NUrls Int32` columns: DATA rows use zero and
`HasHeaders`, `HasBody`, `HasMime` flags. Use `avgIf(Size, HasBody = 1)` when
measuring complete messages. Existing rows migrate as complete EOM records.

SPF, ASN, envelope multimap and envelope portions of split RBL rules can run
early. External relay dependencies defer affected connection checks. Mixed
RBL body work and content-dependent whitelist dependencies remain at EOM.
Multimap expressions, combined rules, Redis-key maps, external lookup maps and
content selectors are not early producers. Existing postfilters/idempotent
filters run only at EOM unless explicitly audited as terminal observers.
Custom exporter callbacks remain at EOM; ClickHouse exceptions disable its
DATA export. Greylisting and per-RCPT rejection are outside this interface.
