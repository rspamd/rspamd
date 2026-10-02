# Experimental MTA Hooks frontend

The proxy worker supports an opt-in inbound DATA / JSON profile of
draft-degennaro-mta-hooks-01. Use a dedicated HTTP proxy listener and Redis.
Native milter listeners and mirrors cannot share this worker. Nothing is enabled
in the stock configuration.

The frontend translates `no action`, greylist pass-through, reject, soft reject,
discard, quarantine, `add header`, and `rewrite subject`. It supports named
header removals (all occurrences or selected one-based occurrences), additive
headers with insertion order, and single or multiple DKIM signing results.
The proxy worker's `spam_header` setting is also used by the Hooks frontend.
Replacement Subject values affect the first surviving Subject, as in native milter.

Header-only changes use structured Hooks operations. Header indexes refer to the
MTA-visible original field sequence; additions and descending deletions are
ordered according to Hooks' set/add/delete processing order. Values may contain
folding whitespace, but a newline introducing another field is rejected.

When a scanner rewrites the body, the frontend returns a base64 `/rawMessage`
replacement containing the original field bytes, requested header edits and the
new body. Empty bodies are supported. This follows native milter semantics:
header changes must be expressed in the milter result; rewriting the scan buffer
does not by itself replace the envelope or original headers. The complete response
is validated before any edits are returned. Invalid or unsupported results return
HTTP 503, allowing the bridge's default temporary SMTP failure policy to apply.

Use a bridge version supporting raw-message replacements and folded output
headers. Early SMTP stages, outbound events, CBOR, envelope edits and per-result
milter action overrides remain outside this frontend's profile.

## Bounds and state

Messages are limited by `max_message`, capped at 25 MiB. Header-only replies are
limited to 1 MiB; body-replacement replies allow bounded base64 expansion of the
message limit. At most 256 added headers are emitted. Redis is required for shared
registration/revocation and five-minute retry deduplication; completed results
are cached, including replacements. Plan Redis memory for these response sizes.
The current ledger admits 1,024 new request IDs per credential and policy namespace
in five minutes; this is a capacity limit, not just an in-flight concurrency bound.

The expanded profile uses a separate Redis namespace from the preliminary
add-only profile. Workers should share the same profile, settings ID and spam
header. Registrations from the old profile must be recreated; the bridge handles
not-found registration recovery. No old state is deleted during startup.

## Tests

`test/functional/util/mta_hooks_test.py` runs isolated Redis and multi-worker
self-scan/upstream tests. Pass `--milter /path/to/mta-hooks-milter` to test the real
bridge, including folded DKIM signatures, duplicate removals, Subject/spam-header
actions, empty and large body replacements, failures and recovery.

`--postfix` additionally submits synthetic SMTP transactions and inspects queued
messages, including independent verification of both DKIM signatures and a
tampered-body negative control. This option is restricted to Docker and requires
Postfix and Python dkimpy. All delivery transports are deferred.

To build the disposable Linux test image, assemble a build context containing
`rspamd/` and `milter/` source directories (without their `.git` or build output),
then run:

```sh
docker build -f rspamd/test/functional/util/mta_hooks.Dockerfile -t rspamd-hooks-parity .
docker run --rm --network none rspamd-hooks-parity
```

The image compiles both actual implementations. Its runtime has no published
ports, host mounts or external network access. Test messages and queues exist
only inside the disposable container.
