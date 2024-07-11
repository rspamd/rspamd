*** Settings ***
Suite Setup     Rspamd Redis Setup
Suite Teardown  Rspamd Redis Teardown
Library         ${RSPAMD_TESTDIR}/lib/rspamd.py
Resource        ${RSPAMD_TESTDIR}/lib/rspamd.robot
Variables       ${RSPAMD_TESTDIR}/lib/vars.py

*** Variables ***
${CONFIG}               ${RSPAMD_TESTDIR}/configs/ratelimit.conf
${MESSAGE}              ${RSPAMD_TESTDIR}/messages/zip.eml
${REDIS_SCOPE}          Suite
${RSPAMD_SCOPE}         Suite
${RSPAMD_URL_TLD}       ${RSPAMD_TESTDIR}/../lua/unit/test_tld.dat
${SETTINGS_RATELIMIT}   {symbols_enabled = [RATELIMIT_CHECK, RATELIMIT_UPDATE]}

*** Keywords ***
Basic Test Scan
  [Arguments]  ${from}  ${rcpt}
  Scan File  ${MESSAGE}
  ...  From=${from}
  ...  IP=1.1.1.1
  ...  Settings=${SETTINGS_RATELIMIT}
  ...  Rcpt=${rcpt}

Basic Test
  [Arguments]  ${from}  ${rcpt}  ${howmany}
  # Should be able to send up to burst
  FOR  ${index}  IN RANGE  ${howmany}
    Basic Test Scan  ${from}  ${rcpt}
    Expect Action  no action
  END
  # Should then be ratelimited
  Basic Test Scan  ${from}  ${rcpt}
  Expect Action  soft reject
  # Should be able to send 1 message 1 second later
  Sleep  1s
  Basic Test Scan  ${from}  ${rcpt}
  Expect Action  no action
  # Ratelimited again
  Basic Test Scan  ${from}  ${rcpt}
  Expect Action  soft reject

*** Test Cases ***
RATELIMIT CHECK BUILTIN
  Basic Test  ${EMPTY}  foobar@example.net  4

RATELIMIT CHECK SELECTOR
  Basic Test  foo@example.net  special@example.net  2
