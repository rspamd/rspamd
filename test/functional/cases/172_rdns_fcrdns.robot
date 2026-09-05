*** Settings ***
Suite Setup     Rspamd Setup
Suite Teardown  Rspamd Teardown
Library         ${RSPAMD_TESTDIR}/lib/rspamd.py
Resource        ${RSPAMD_TESTDIR}/lib/rspamd.robot
Variables       ${RSPAMD_TESTDIR}/lib/vars.py

*** Variables ***
${CONFIG}          ${RSPAMD_TESTDIR}/configs/rdns.conf
${MESSAGE}         ${RSPAMD_TESTDIR}/messages/spam_message.eml
${RSPAMD_SCOPE}    Suite
${RSPAMD_URL_TLD}  ${RSPAMD_TESTDIR}/../lua/unit/test_tld.dat
${SETTINGS}        {symbols_enabled = [RDNS_CHECK, RDNS_NONE, RDNS_DNSFAIL, RDNS_FCRDNS_FAIL, RDNS_FCRDNS_DNSFAIL, HFILTER_CHECK, HFILTER_HOSTNAME_UNKNOWN, HFILTER_HOSTNAME_1, HFILTER_HOSTNAME_2, HFILTER_HOSTNAME_3, HFILTER_HOSTNAME_4, HFILTER_HOSTNAME_5]}

*** Test Cases ***
# Harness control rather than a behaviour under test: RDNS_CHECK is a
# prefilter, so if it did not run in this suite every other case here would
# green for the wrong reason. A client with no PTR at all must reach the
# pre-existing RDNS_NONE path and be reported as an unknown hostname.
Client without a PTR record is reported unknown
  Scan File  ${MESSAGE}  IP=23.45.67.89  Settings=${SETTINGS}
  Expect Symbol  RDNS_NONE
  Expect Symbol  HFILTER_HOSTNAME_UNKNOWN

# The bug. The PTR resolves, so the fallback in rules/misc.lua adopts the
# name, but that name publishes a different address: forward-confirmed
# reverse DNS fails. HFILTER_HOSTNAME_UNKNOWN documents itself as covering
# exactly this ("PTR or FCrDNS verification failed") and must fire.
Client whose PTR fails forward confirmation is reported unknown
  Scan File  ${MESSAGE}  IP=1.2.3.4  Settings=${SETTINGS}
  Expect Symbol With Score  HFILTER_HOSTNAME_UNKNOWN  2.50
  Expect Symbol  RDNS_FCRDNS_FAIL

# The same client as seen from a real MTA. Per the milter interface a
# hostname that failed the MTA's own FCrDNS check arrives as the bracketed
# IP literal, which get_hostname() reports as nil; the fallback then runs and
# must not overwrite that verdict with an unverified name.
Bracketed IP literal from the MTA does not become a verified hostname
  Scan File  ${MESSAGE}  IP=1.2.3.4  Hostname=[1.2.3.4]  Settings=${SETTINGS}
  Expect Symbol  HFILTER_HOSTNAME_UNKNOWN
  Expect Symbol  RDNS_FCRDNS_FAIL

# Control: the PTR name publishes exactly the connecting address, so the
# hostname is verified and neither symbol may be inserted. Guards against a
# fix that simply stops trusting the fallback altogether.
Client whose PTR forward-confirms is not reported unknown
  Scan File  ${MESSAGE}  IP=5.6.7.8  Settings=${SETTINGS}
  Do Not Expect Symbol  RDNS_FCRDNS_FAIL
  Do Not Expect Symbol  HFILTER_HOSTNAME_UNKNOWN

# The A and AAAA lookups of the PTR name share one callback and complete in
# arbitrary order. Here the connecting address is in the A reply while the
# AAAA reply holds a different one, so a check that judges before both have
# returned can reject a correctly configured host.
Dual-stack PTR confirming on A is not reported unknown
  Scan File  ${MESSAGE}  IP=34.56.78.90  Settings=${SETTINGS}
  Do Not Expect Symbol  RDNS_FCRDNS_FAIL
  Do Not Expect Symbol  HFILTER_HOSTNAME_UNKNOWN

# Authoritative absence of address records is a failed verification, not a
# deferred one: the name provably does not confirm the client.
Client whose PTR name has no address records is reported unknown
  Scan File  ${MESSAGE}  IP=45.67.89.101  Settings=${SETTINGS}
  Expect Symbol  HFILTER_HOSTNAME_UNKNOWN
  Expect Symbol  RDNS_FCRDNS_FAIL

# A resolver timeout proves nothing either way. The verification result is
# unknown, so the default must not be to accuse the client; instead a
# dedicated symbol is published so a deployment enforcing
# HFILTER_HOSTNAME_UNKNOWN can soft-reject the temporary failures.
Client whose forward lookup times out is reported as a temporary failure
  Scan File  ${MESSAGE}  IP=9.9.9.9  Settings=${SETTINGS}
  Expect Symbol  RDNS_FCRDNS_DNSFAIL
  Do Not Expect Symbol  RDNS_FCRDNS_FAIL
  Do Not Expect Symbol  HFILTER_HOSTNAME_UNKNOWN

# Hostname pattern scoring must keep working for clients that verify: a
# generic/dynamic-looking PTR name still earns its weight.
Generic PTR name that forward-confirms is still scored by pattern
  Scan File  ${MESSAGE}  IP=67.89.101.23  Settings=${SETTINGS}
  Expect Symbol With Score  HFILTER_HOSTNAME_5  3.00
  Do Not Expect Symbol  HFILTER_HOSTNAME_UNKNOWN

# The deliberate consequence of the fix, pinned so it cannot change by
# accident: a name that fails verification is not used for pattern scoring
# either. This matches what already happens when the MTA does the check
# itself and passes the bracketed IP literal instead of the name.
Generic PTR name that fails forward confirmation is not scored by pattern
  Scan File  ${MESSAGE}  IP=56.78.90.12  Settings=${SETTINGS}
  Expect Symbol  HFILTER_HOSTNAME_UNKNOWN
  Do Not Expect Symbol  HFILTER_HOSTNAME_5
