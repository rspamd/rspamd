*** Settings ***
Suite Setup     Greylist Setup
Suite Teardown  Greylist Teardown
Library         ${RSPAMD_TESTDIR}/lib/rspamd.py
Resource        ${RSPAMD_TESTDIR}/lib/rspamd.robot
Variables       ${RSPAMD_TESTDIR}/lib/vars.py

*** Variables ***
${CONFIG}       ${RSPAMD_TESTDIR}/configs/greylist.conf
${MESSAGE}      ${RSPAMD_TESTDIR}/messages/spam_message.eml
${REDIS_SCOPE}  Suite
${RSPAMD_SCOPE}  Suite
${RSPAMD_URL_TLD}      ${RSPAMD_TESTDIR}/../lua/unit/test_tld.dat

*** Test Cases ***
GREYLIST NEW
  Scan File  ${MESSAGE}
  Expect Symbol With Option  GREYLIST  greylisted

GREYLIST EARLY
  Scan File  ${MESSAGE}
  Expect Symbol With Option  GREYLIST  greylisted

GREYLIST PASS
  Sleep  4s  Wait greylisting timeout
  Scan File  ${MESSAGE}
  Expect Symbol With Option  GREYLIST  pass

*** Keywords ***
Greylist Setup
  New Setup
  Run Redis

Greylist Teardown
  Normal Teardown
  Shutdown Process With Children  ${REDIS_PID}
  Terminate All Processes    kill=True
