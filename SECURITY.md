# Security Policy

This document explains what the Rspamd project treats as a security
vulnerability, what it treats as an ordinary bug, and how to report each.
The distinction matters: security issues are handled privately, get a
coordinated fix and an advisory, and are backported. Ordinary bugs go through
the public issue tracker and the normal release cycle. Both kinds are welcome
and both get fixed.

## Reporting a vulnerability

Do **not** open a public GitHub issue for anything you believe is a security
vulnerability.

Report it through one of these channels:

1. [GitHub private vulnerability reporting](https://github.com/rspamd/rspamd/security/advisories/new)
   (preferred).
2. Email to `vsevolod@rspamd.com`. Put `[SECURITY]` in the subject.

Include a reproducer if you have one: a message file, a crafted archive,
a network capture, or a fuzzer testcase, plus the Rspamd version and platform.
A sanitizer or fuzzer trace on its own is useful, but a reproducer gets the
issue fixed much faster.

You can expect an acknowledgement within a few working days. We will tell you
whether we agree that the issue is a security vulnerability under the model
below, and we will keep you informed while it is being fixed. We credit
reporters in the advisory and the ChangeLog unless they ask otherwise.

If you are unsure whether something is a security issue, report it privately
anyway. Moving a report to the public tracker is easy; the reverse is not.

## Supported versions

Security fixes are released for the **latest stable release series** only
(currently 4.x). Fixes land on `master` and are included in the next patch
release of the current series. Older series do not receive security
backports. If you run an older series, upgrade.

## Threat model

Rspamd is a mail filter. It sits behind an MTA, receives messages from that
MTA, and returns a verdict. Its job is to process hostile input all day long.
The threat model follows from that.

### Untrusted input

Anything that arrives in or with a message is attacker-controlled:

- MIME structure, headers, encodings, and boundaries.
- Message bodies: text, HTML, CSS, images, PDF and other documents.
- Archives (zip, rar, 7z, gz and so on), including their metadata.
- URLs, email addresses, and anything else extracted from the above.
- Data fetched *because* of a message: DNS answers used for DKIM, SPF,
  DMARC, ARC, DNSBL and URL checks; responses from external services
  configured to be queried per message.

Bugs in code that handles this input, where a crafted message or a crafted
network answer can cause memory corruption, code execution, or a crash, are
**security vulnerabilities**. This includes the MIME parser, the HTML and CSS
parsers, the archive parsers, the PDF and image parsers, the URL parser, the
language detector, the DKIM/ARC/SPF/DMARC verifiers, the DNS resolver, and
code in `contrib/` when it is reachable from message content.

### The fuzzy storage worker

The fuzzy storage worker (`fuzzy_storage`) is the one Rspamd component that
is designed to be reachable from the public Internet: the project runs public
fuzzy storages and third parties do too. Its UDP and TCP protocol, its
encryption layer, its key handling, its rate limiting, and its storage
backends process **untrusted input** from arbitrary remote peers. Bugs there
that a remote peer can trigger are **security vulnerabilities**, including
crashes and resource exhaustion, and including flaws that let a peer bypass
the encryption, forge another key's identity, or write hashes it is not
allowed to write.

### Trusted interfaces

Every other network or local interface of Rspamd is an **internal interface**
and must not be exposed to untrusted clients:

- The normal worker (the `/checkv2` and related scan endpoints).
- The controller (the web interface, `/stat`, `/learn*`, `/map*`, and the
  rest of the management API), including the password mechanism.
- The proxy worker and its milter and HTTP protocols.
- The control socket and `rspamadm control`.
- Command-line tools: `rspamc`, `rspamadm`.
- Configuration files, Lua rules and plugins, maps, and the Redis and other
  backends Rspamd is configured to talk to.

The clients of these interfaces (the MTA, the administrator, monitoring, and
other Rspamd instances in a cluster) are trusted. A client that can reach the
scan endpoint can already make Rspamd parse whatever it likes; a client with
the controller password can already reconfigure, retrain, and read everything
by design. Consequently, bugs that require the attacker to be such a client
are **not security vulnerabilities**. That includes memory safety bugs in the
HTTP server, the milter parser, the control protocol, the map loaders, or the
Lua API, when the only way to reach them is through one of these interfaces.

We still want these reports and we fix them promptly, often with the same
urgency as a security fix, because they are real bugs in real code paths. But
they go through the public issue tracker, get no advisory or CVE, and are not
backported as security fixes.

Two exceptions:

- A flaw in the controller's **authentication itself**, that is, a way for
  a client that does not know the password to pass as one that does, is a
  security vulnerability. The password is the one control that lets people
  put the controller on a network at all.
- The trusted interfaces are still part of the untrusted data path when the
  untrusted data is a message. A bug in the scan endpoint's *request* parsing
  is not a security issue; a bug that a crafted *message body* submitted over
  that endpoint triggers is.

If you have exposed the normal worker or the controller to the Internet, that
is a deployment mistake. Keep them on localhost, a Unix socket, or a private
network, protect the controller with a password and `secure_ip`, and use the
proxy worker with encryption for cross-host traffic.

## Severity guidance

How we rank an issue that is in scope:

| Impact from a crafted message or fuzzy peer | Treatment |
|---|---|
| Code execution, or memory write of any size | Critical. Fixed and released as soon as possible. |
| Reliable crash of a scanning worker or the fuzzy worker | High. A repeatable crash is a denial of service on mail flow. |
| Unbounded CPU or memory use (algorithmic complexity, decompression bombs beyond the configured limits, recursion) | Medium to high, depending on how cheap it is to trigger. |
| Verification bypass: a forged DKIM/ARC signature verifies, SPF/DMARC evaluates wrongly on attacker-chosen records | Medium to high. These results feed authentication policy downstream. |
| Read overrun that the attacker can steer or extend, and whose contents reach the attacker (in a symbol option, a returned header, a log line an attacker can read) | Low to medium. Information disclosure. |
| Read overrun of a few bytes with no reflection to the attacker | Not treated as a security issue. Fixed as a normal bug. |

On out-of-bounds reads: Rspamd processes each message in its own memory pool
and most parsers work on buffers that are followed by more of the same
message or by pool padding. A read of one or two bytes past the end of a
buffer cannot alter control flow and does not leak anything an attacker can
observe. Sanitizers report these loudly and we fix them as they come, but
they get the priority of an ordinary bug, not an advisory. If you can show
that an overrun is attacker-extensible, or that its result is reflected back
in a way you can read, report it privately and say so; that changes the
assessment.

## Not security issues

The following are ordinary bugs or feature requests and belong on the public
tracker:

- Spam that gets through, phishing that is not detected, or any other
  false negative. Detection quality is a rules problem, not a vulnerability.
  The same applies to techniques that evade a specific rule or module.
- False positives.
- Any issue that requires a change to the configuration or Lua rules to
  become reachable, or that only appears with a non-default option the
  documentation warns about.
- Any issue that requires access to a trusted interface (see above), the
  configuration, the Redis backend, or the host.
- Denial of service by volume: sending more legitimate traffic than the
  deployment can handle.
- Issues in third-party Lua plugins that are not part of this repository.
- Crashes or leaks in `rspamadm` and `rspamc` on attacker-supplied files,
  except when the same code path is also reachable from a scanned message
  (in which case report the message path).
- Issues in the project's websites, package repositories, and other
  infrastructure. Report those by email; they are not covered by this
  document.

## Disclosure

We prefer coordinated disclosure. Once we agree an issue is a security
vulnerability, we aim to release a fixed version within 90 days and usually
much faster. We ask reporters to hold details until the fix is released. We
publish a GitHub security advisory with a CVE when the fix ships, and the
release ChangeLog references it. If you plan to publish on your own schedule,
tell us the date up front so we can plan the release around it.

Fixes for security issues are committed with a `[CritFix]` tag and a plain
description of the bug; the commit is public before the advisory in the
normal case, since fixing is not the same as announcing.

## Hardening notes for operators

Rspamd is designed to be run as an unprivileged user and to keep the
untrusted parsing inside worker processes that the main process restarts on
crash. To get the most out of the model above:

- Bind the normal worker, the controller, and the proxy to localhost or a
  Unix socket, or to a private network, never to a public address.
- Set a controller password (`password` and `enable_password`) and
  restrict `secure_ip`.
- If you run a fuzzy storage, use encryption keys, keep the rate limits on,
  and grant write access (`allow_update`) only to hosts you control.
- Keep the archive and message size limits at their defaults unless you have
  a reason to raise them.
- Run the current release.
