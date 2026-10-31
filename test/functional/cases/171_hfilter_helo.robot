*** Settings ***
Suite Setup     Rspamd Setup
Suite Teardown  Rspamd Teardown
Library         ${RSPAMD_TESTDIR}/lib/rspamd.py
Resource        ${RSPAMD_TESTDIR}/lib/rspamd.robot
Variables       ${RSPAMD_TESTDIR}/lib/vars.py

*** Variables ***
${CONFIG}          ${RSPAMD_TESTDIR}/configs/hfilter.conf
${MESSAGE}         ${RSPAMD_TESTDIR}/messages/spam_message.eml
${RSPAMD_SCOPE}    Suite
${RSPAMD_URL_TLD}  ${RSPAMD_TESTDIR}/../lua/unit/test_tld.dat
${SETTINGS}        {symbols_enabled = [HFILTER_CHECK, HFILTER_HELO_IP_A, HFILTER_HELO_NORES_A_OR_MX, HFILTER_HELO_NORESOLVE_MX, HFILTER_HELO_NOT_FQDN, HFILTER_HELO_DNSFAIL]}

*** Test Cases ***
# HFILTER_HELO_IP_A is documented as "Helo A IP != hostname IP", so a HELO
# whose address records do not contain the connecting IP must be flagged.
HELO address not matching connecting IP is flagged
  Scan File  ${MESSAGE}  IP=5.6.7.8  Helo=mismatch.test  Settings=${SETTINGS}
  Expect Symbol With Score  HFILTER_HELO_IP_A  1.00

# Control: the connecting IP is exactly the published A record, so the symbol
# must stay silent. Guards against a fix that simply always inserts.
HELO address matching connecting IP is not flagged
  Scan File  ${MESSAGE}  IP=1.2.3.4  Helo=match.test  Settings=${SETTINGS}
  Do Not Expect Symbol  HFILTER_HELO_IP_A

# The A and AAAA lookups share one callback and complete in arbitrary order.
# Here the matching address is the AAAA one, so any check that runs before
# both lookups have returned can observe only {1.2.3.4} and flag wrongly.
Dual-stack HELO matching on AAAA is not flagged
  Scan File  ${MESSAGE}  IP=2001:db8::1  Helo=dual.test  Settings=${SETTINGS}
  Do Not Expect Symbol  HFILTER_HELO_IP_A

# Mirror of the above with the match in the A reply, so neither completion
# order is quietly favoured.
Dual-stack HELO matching on A is not flagged
  Scan File  ${MESSAGE}  IP=1.2.3.4  Helo=dual.test  Settings=${SETTINGS}
  Do Not Expect Symbol  HFILTER_HELO_IP_A

# Both families resolve and neither matches: the symbol is correct here, but
# it must be inserted once rather than once per resolver callback. The score
# assertion is the check -- a per-callback insert scores 2.00.
Dual-stack HELO matching neither family is flagged exactly once
  Scan File  ${MESSAGE}  IP=9.9.9.9  Helo=dualmiss.test  Settings=${SETTINGS}
  Expect Symbol With Score  HFILTER_HELO_IP_A  1.00

# Existing behaviour, preserved deliberately: a HELO that resolves to no
# address records at all is still flagged. Whether that should remain
# HFILTER_HELO_IP_A's job rather than HFILTER_HELO_NORES_A_OR_MX's is a
# separate scoring question, so this test pins today's behaviour.
HELO with no address records keeps being flagged
  Scan File  ${MESSAGE}  IP=1.2.3.4  Helo=noaddr.test  Settings=${SETTINGS}
  Expect Symbol With Score  HFILTER_HELO_IP_A  1.00
  Expect Symbol  HFILTER_HELO_NORES_A_OR_MX

# A timeout is not an authoritative absence: the failed A lookup could contain
# the connecting IP, so the nonmatching AAAA answer cannot prove a mismatch.
HELO with one transiently failed family is not flagged
  Scan File  ${MESSAGE}  IP=1.2.3.4  Helo=partialfail.test  Settings=${SETTINGS}
  Do Not Expect Symbol  HFILTER_HELO_IP_A

# Staying silent is right, but silence is indistinguishable from a clean
# pass. A deployment that enforces HFILTER_HELO_IP_A needs to be able to tell
# "verified, no mismatch" from "could not verify", so the transient failure
# is published as its own symbol to soft reject on.
HELO with a transiently failed family reports the DNS failure
  Scan File  ${MESSAGE}  IP=1.2.3.4  Helo=partialfail.test  Settings=${SETTINGS}
  Expect Symbol  HFILTER_HELO_DNSFAIL

# Both families time out. The two lookups share one callback, so the symbol
# must be inserted once rather than once per callback; a per-callback insert
# scores 2.00.
HELO with both families transiently failed reports the DNS failure once
  Scan File  ${MESSAGE}  IP=1.2.3.4  Helo=bothfail.test  Settings=${SETTINGS}
  Expect Symbol With Score  HFILTER_HELO_DNSFAIL  1.00

# Control: a HELO that resolves cleanly must not be reported as unverifiable.
HELO that resolves cleanly reports no DNS failure
  Scan File  ${MESSAGE}  IP=1.2.3.4  Helo=match.test  Settings=${SETTINGS}
  Do Not Expect Symbol  HFILTER_HELO_DNSFAIL

# Control: NXDOMAIN is an authoritative answer, not a failure to obtain one.
# It is already reported as HFILTER_HELO_NORES_A_OR_MX and must not also be
# reported as a DNS failure, or the soft-reject signal becomes useless.
HELO with no address records reports no DNS failure
  Scan File  ${MESSAGE}  IP=1.2.3.4  Helo=noaddr.test  Settings=${SETTINGS}
  Expect Symbol  HFILTER_HELO_NORES_A_OR_MX
  Do Not Expect Symbol  HFILTER_HELO_DNSFAIL
