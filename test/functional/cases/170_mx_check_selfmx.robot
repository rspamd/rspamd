*** Settings ***
Suite Setup     Mx Selfmx Setup
Suite Teardown  Mx Selfmx Teardown
Library         Process
Library         ${RSPAMD_TESTDIR}/lib/rspamd.py
Resource        ${RSPAMD_TESTDIR}/lib/rspamd.robot
Variables       ${RSPAMD_TESTDIR}/lib/vars.py

*** Variables ***
${CONFIG}          ${RSPAMD_TESTDIR}/configs/mx_check-selfmx.conf
${MESSAGE}         ${RSPAMD_TESTDIR}/messages/spam_message.eml
${REDIS_SCOPE}     Suite
${RSPAMD_SCOPE}    Suite
${RSPAMD_URL_TLD}  ${RSPAMD_TESTDIR}/../lua/unit/test_tld.dat
${SETTINGS}        {symbols_enabled = [MX_INVALID]}

*** Test Cases ***
# Regression guard for issue #6101: a domain whose MX resolves only to loopback
# (a self-MX, commonly the host's own FQDN in /etc/hosts) must classify as LOCAL
# rather than BOGON, so legitimate self-hosted mail is not penalised +8.0.
# Runs with test_mode = false (the production path); the test_mode = true configs
# treat loopback as probeable and cannot cover this.
Loopback-only MX classifies as LOCAL, not BOGON
  Scan File  ${MESSAGE}  From=test@selfmx.test  Settings=${SETTINGS}
  Expect Symbol  MX_LOCAL_ONLY
  Do Not Expect Symbol  MX_BOGON_ONLY
  Do Not Expect Symbol  MX_INVALID

*** Keywords ***
Mx Selfmx Setup
  Rspamd Redis Setup

Mx Selfmx Teardown
  Rspamd Redis Teardown
