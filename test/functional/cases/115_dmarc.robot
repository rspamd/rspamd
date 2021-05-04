*** Settings ***
Suite Setup     Rspamd Setup
Suite Teardown  Rspamd Teardown
Library         ${RSPAMD_TESTDIR}/lib/rspamd.py
Resource        ${RSPAMD_TESTDIR}/lib/rspamd.robot
Variables       ${RSPAMD_TESTDIR}/lib/vars.py

*** Variables ***
${CONFIG}          ${RSPAMD_TESTDIR}/configs/dmarc.conf
${RSPAMD_SCOPE}    Suite
${RSPAMD_URL_TLD}  ${RSPAMD_TESTDIR}/../../contrib/publicsuffix/effective_tld_names.dat

*** Test Cases ***
DMARC NONE PASS DKIM
  Scan File  ${RSPAMD_TESTDIR}/messages/dmarc/pass_none.eml
  Expect Symbol  DMARC_POLICY_ALLOW

DMARC NONE PASS SPF
  Scan File  ${RSPAMD_TESTDIR}/messages/dmarc/fail_none.eml
  ...  IP=8.8.4.4  From=foo@spf.cacophony.za.org
  Expect Symbol  DMARC_POLICY_ALLOW

DMARC NONE FAIL
  Scan File  ${RSPAMD_TESTDIR}/messages/dmarc/fail_none.eml
  Expect Symbol  DMARC_POLICY_SOFTFAIL

DMARC REJECT FAIL
  Scan File  ${RSPAMD_TESTDIR}/messages/dmarc/fail_reject.eml
  Expect Symbol  DMARC_POLICY_REJECT

DMARC QUARANTINE FAIL
  Scan File  ${RSPAMD_TESTDIR}/messages/dmarc/fail_quarantine.eml
  Expect Symbol  DMARC_POLICY_QUARANTINE

DMARC SP NONE FAIL
  Scan File  ${RSPAMD_TESTDIR}/messages/dmarc/subdomain_fail_none.eml
  Expect Symbol  DMARC_POLICY_SOFTFAIL

DMARC SP REJECT FAIL
  Scan File  ${RSPAMD_TESTDIR}/messages/dmarc/subdomain_fail_reject.eml
  Expect Symbol  DMARC_POLICY_REJECT

DMARC SP QUARANTINE FAIL
  Scan File  ${RSPAMD_TESTDIR}/messages/dmarc/subdomain_fail_quarantine.eml
  Expect Symbol  DMARC_POLICY_QUARANTINE

DMARC SUBDOMAIN FAIL DKIM STRICT ALIGNMENT
  Scan File  ${RSPAMD_TESTDIR}/messages/dmarc/onsubdomain_fail_alignment.eml
  Expect Symbol  DMARC_POLICY_REJECT

DMARC SUBDOMAIN PASS DKIM RELAXED ALIGNMENT
  Scan File  ${RSPAMD_TESTDIR}/messages/dmarc/onsubdomain_pass_relaxed.eml
  Expect Symbol  DMARC_POLICY_ALLOW

DMARC SUBDOMAIN PASS SPF STRICT ALIGNMENT
  Scan File  ${RSPAMD_TESTDIR}/messages/dmarc/onsubdomain_fail_alignment.eml
  ...  IP=37.48.67.26  From=foo@yo.mom.za.org
  Expect Symbol  DMARC_POLICY_ALLOW

DMARC SUBDOMAIN FAIL SPF STRICT ALIGNMENT
  Scan File  ${RSPAMD_TESTDIR}/messages/dmarc/onsubdomain_fail_alignment.eml
  ...  IP=37.48.67.26  From=foo@mom.za.org
  Expect Symbol  DMARC_POLICY_REJECT

DMARC SUBDOMAIN PASS SPF RELAXED ALIGNMENT
  Scan File  ${RSPAMD_TESTDIR}/messages/dmarc/onsubdomain_fail.eml
  ...  IP=37.48.67.26  From=foo@mom.za.org
  Expect Symbol  DMARC_POLICY_ALLOW

DMARC DNSFAIL
  Scan File  ${RSPAMD_TESTDIR}/messages/dmarc/dmarc_tmpfail.eml
  ...  IP=37.48.67.26  From=foo@mom.za.org
  Expect Symbol  DMARC_DNSFAIL

DMARC NA NXDOMAIN
  Scan File  ${RSPAMD_TESTDIR}/messages/utf.eml
  ...  IP=37.48.67.26  From=foo@mom.za.org
  Expect Symbol  DMARC_NA

DMARC PCT ZERO REJECT
  Scan File  ${RSPAMD_TESTDIR}/messages/dmarc/pct_none.eml
  ...  IP=37.48.67.26  From=foo@mom.za.org
  Expect Symbol  DMARC_POLICY_QUARANTINE

DMARC PCT ZERO SP QUARANTINE
  Scan File  ${RSPAMD_TESTDIR}/messages/dmarc/pct_none1.eml
  ...  IP=37.48.67.26  From=foo@mom.za.org
  Expect Symbol  DMARC_POLICY_SOFTFAIL
