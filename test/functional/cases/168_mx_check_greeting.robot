*** Settings ***
Suite Setup     Mx Greeting Setup
Suite Teardown  Mx Greeting Teardown
Library         OperatingSystem
Library         Process
Library         ${RSPAMD_TESTDIR}/lib/rspamd.py
Resource        ${RSPAMD_TESTDIR}/lib/rspamd.robot
Variables       ${RSPAMD_TESTDIR}/lib/vars.py

*** Variables ***
${CONFIG}             ${RSPAMD_TESTDIR}/configs/mx_check-greeting.conf
${MESSAGE}            ${RSPAMD_TESTDIR}/messages/spam_message.eml
${REDIS_SCOPE}        Suite
${RSPAMD_SCOPE}       Suite
${RSPAMD_URL_TLD}     ${RSPAMD_TESTDIR}/../lua/unit/test_tld.dat
${SETTINGS}           {symbols_enabled = [MX_INVALID]}
${SINGLE_STATUS}      /tmp/dummy_smtp_greeting_single.status

*** Test Cases ***
Silent SMTP listener triggers MX_TIMEOUT_READ
  Scan File  ${MESSAGE}  From=test@silentsmtp.test  Settings=${SETTINGS}
  Expect Symbol  MX_TIMEOUT_READ

Continuation 220- without follow-up (send_quit=false) emits MX_GOOD
  # The dummy emits "220-Greeting" then holds the connection longer than
  # read_timeout without sending a second line. A regression that waits
  # for a continuation under send_quit=false would surface here as
  # MX_TIMEOUT_READ.
  Scan File  ${MESSAGE}  From=test@greetingsmtp.test  Settings=${SETTINGS}
  Expect Symbol  MX_GOOD
  Do Not Expect Symbol  MX_TIMEOUT_READ
  Sleep  0.5s
  ${status} =  Get File  ${SINGLE_STATUS}
  Should Contain  ${status}  OK_NO_QUIT

5xx greeting triggers MX_ERROR
  Scan File  ${MESSAGE}  From=test@errorsmtp.test  Settings=${SETTINGS}
  Expect Symbol  MX_ERROR

Non-SMTP line triggers MX_INVALID
  Scan File  ${MESSAGE}  From=test@messysmtp.test  Settings=${SETTINGS}
  Expect Symbol  MX_INVALID

*** Keywords ***
Start Plain Dummy
  [Arguments]  ${mode}  ${host}
  Start Process  ${RSPAMD_TESTDIR}/util/dummy_smtp.py
  ...  --port  11125  --mode  ${mode}  --host  ${host}
  ...  stderr=/tmp/dummy_smtp_${mode}.log
  ...  stdout=/tmp/dummy_smtp_${mode}.log
  Wait Until Created  /tmp/dummy_smtp_${mode}.pid  timeout=2 second

Mx Greeting Setup
  Start Plain Dummy  silent  127.0.0.1
  Start Process  ${RSPAMD_TESTDIR}/util/dummy_smtp.py
  ...  --port  11125  --mode  greeting_single  --host  127.0.0.2
  ...  --status-file  ${SINGLE_STATUS}
  ...  stderr=/tmp/dummy_smtp_greeting_single.log
  ...  stdout=/tmp/dummy_smtp_greeting_single.log
  Wait Until Created  /tmp/dummy_smtp_greeting_single.pid  timeout=2 second
  Start Plain Dummy  error   127.0.0.3
  Start Plain Dummy  messy   127.0.0.4
  Rspamd Redis Setup

Mx Greeting Teardown
  Rspamd Redis Teardown
  Terminate All Processes  kill=True
