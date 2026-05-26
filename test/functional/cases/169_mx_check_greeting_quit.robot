*** Settings ***
Suite Setup     Mx Quit Setup
Suite Teardown  Mx Quit Teardown
Library         OperatingSystem
Library         Process
Library         ${RSPAMD_TESTDIR}/lib/rspamd.py
Resource        ${RSPAMD_TESTDIR}/lib/rspamd.robot
Variables       ${RSPAMD_TESTDIR}/lib/vars.py

*** Variables ***
${CONFIG}             ${RSPAMD_TESTDIR}/configs/mx_check-greeting-quit.conf
${MESSAGE}            ${RSPAMD_TESTDIR}/messages/spam_message.eml
${REDIS_SCOPE}        Suite
${RSPAMD_SCOPE}       Suite
${RSPAMD_URL_TLD}     ${RSPAMD_TESTDIR}/../lua/unit/test_tld.dat
${SETTINGS}           {symbols_enabled = [MX_INVALID]}
${PROPER_STATUS}      /tmp/dummy_smtp_greeting_proper.status
${SLOW_STATUS}        /tmp/dummy_smtp_greeting_slow.status

*** Test Cases ***
Multi-line greeting with send_quit=true emits MX_GOOD with QUIT after final line
  Scan File  ${MESSAGE}  From=test@multigreetsmtp.test  Settings=${SETTINGS}
  Expect Symbol  MX_GOOD
  Sleep  0.5s
  ${status} =  Get File  ${PROPER_STATUS}
  Should Contain  ${status}  QUIT_AFTER_FINAL

Slow second banner line triggers MX_TIMEOUT_READ
  Scan File  ${MESSAGE}  From=test@slowsmtp.test  Settings=${SETTINGS}
  Expect Symbol  MX_TIMEOUT_READ

*** Keywords ***
Start Greeting Dummy
  [Arguments]  ${host}  ${between_wait}  ${status_file}  ${pid_suffix}
  Start Process  ${RSPAMD_TESTDIR}/util/dummy_smtp.py
  ...  --port  11125
  ...  --mode  greeting_multi
  ...  --host  ${host}
  ...  --between-wait  ${between_wait}
  ...  --status-file  ${status_file}
  ...  --pid-file  /tmp/dummy_smtp_${pid_suffix}.pid
  ...  stderr=/tmp/dummy_smtp_${pid_suffix}.log
  ...  stdout=/tmp/dummy_smtp_${pid_suffix}.log
  Wait Until Created  /tmp/dummy_smtp_${pid_suffix}.pid  timeout=2 second

Mx Quit Setup
  Start Greeting Dummy  127.0.0.6  0.2  ${PROPER_STATUS}  greeting_proper
  Start Greeting Dummy  127.0.0.5  2.0  ${SLOW_STATUS}    greeting_slow
  Rspamd Redis Setup

Mx Quit Teardown
  Rspamd Redis Teardown
  Terminate All Processes  kill=True
