*** Settings ***
Suite Setup     Rspamd Setup
Suite Teardown  Rspamd Teardown
Test Teardown   Close Pending Connections
Library         ${RSPAMD_TESTDIR}/lib/rspamd.py
Resource        ${RSPAMD_TESTDIR}/lib/rspamd.robot
Variables       ${RSPAMD_TESTDIR}/lib/vars.py

*** Variables ***
${CONFIG}          ${RSPAMD_TESTDIR}/configs/admission_limits.conf
${MESSAGE}         ${RSPAMD_TESTDIR}/messages/spam_message.eml
${RSPAMD_SCOPE}    Suite
${RSPAMD_URL_TLD}  ${RSPAMD_TESTDIR}/../lua/unit/test_tld.dat
# Matches max_tasks / max_connections in configs/admission_limits.conf
${LIMIT}           ${3}
${LIMIT_LESS_ONE}  ${2}

*** Test Cases ***
Scanner counts body-pending connections
  [Documentation]  max_tasks used to count completed requests only, so a client
  ...              that connected and then stalled did not occupy a slot. It
  ...              does now: one slot short of the limit still admits a scan,
  ...              reaching the limit refuses the next connection.
  Assert Admitted  ${RSPAMD_PORT_NORMAL}
  Open Pending Connections  ${RSPAMD_LOCAL_ADDR}  ${RSPAMD_PORT_NORMAL}  ${LIMIT_LESS_ONE}
  Assert Admitted  ${RSPAMD_PORT_NORMAL}
  Open Pending Connections  ${RSPAMD_LOCAL_ADDR}  ${RSPAMD_PORT_NORMAL}  1
  Assert Refused  ${RSPAMD_PORT_NORMAL}

Scanner releases the slots of disconnected clients
  [Documentation]  The counter must be released on the teardown path as well,
  ...              otherwise a burst of stalled clients would wedge the worker
  ...              for good.
  Open Pending Connections  ${RSPAMD_LOCAL_ADDR}  ${RSPAMD_PORT_NORMAL}  ${LIMIT}
  Assert Refused  ${RSPAMD_PORT_NORMAL}
  Close Pending Connections
  Wait Until Keyword Succeeds  20x  0.25s  Assert Admitted  ${RSPAMD_PORT_NORMAL}
  Scan File  ${MESSAGE}  From=released@example.net  Rcpt=released-rcpt@example.net
  Expect Symbol  SIMPLE_TEST

Controller counts pending connections
  Assert Admitted  ${RSPAMD_PORT_CONTROLLER}
  Open Pending Connections  ${RSPAMD_LOCAL_ADDR}  ${RSPAMD_PORT_CONTROLLER}  ${LIMIT_LESS_ONE}
  Assert Admitted  ${RSPAMD_PORT_CONTROLLER}
  Open Pending Connections  ${RSPAMD_LOCAL_ADDR}  ${RSPAMD_PORT_CONTROLLER}  1
  Assert Refused  ${RSPAMD_PORT_CONTROLLER}

Controller releases the slots of disconnected clients
  Open Pending Connections  ${RSPAMD_LOCAL_ADDR}  ${RSPAMD_PORT_CONTROLLER}  ${LIMIT}
  Assert Refused  ${RSPAMD_PORT_CONTROLLER}
  Close Pending Connections
  Wait Until Keyword Succeeds  20x  0.25s  Assert Admitted  ${RSPAMD_PORT_CONTROLLER}

Proxy counts pending connections
  Assert Admitted  ${RSPAMD_PORT_PROXY}
  Open Pending Connections  ${RSPAMD_LOCAL_ADDR}  ${RSPAMD_PORT_PROXY}  ${LIMIT_LESS_ONE}
  Assert Admitted  ${RSPAMD_PORT_PROXY}
  Open Pending Connections  ${RSPAMD_LOCAL_ADDR}  ${RSPAMD_PORT_PROXY}  1
  Assert Refused  ${RSPAMD_PORT_PROXY}

Proxy releases the slots of disconnected clients
  Open Pending Connections  ${RSPAMD_LOCAL_ADDR}  ${RSPAMD_PORT_PROXY}  ${LIMIT}
  Assert Refused  ${RSPAMD_PORT_PROXY}
  Close Pending Connections
  Wait Until Keyword Succeeds  20x  0.25s  Assert Admitted  ${RSPAMD_PORT_PROXY}
  Set Test Variable  ${RSPAMD_PORT_NORMAL}  ${RSPAMD_PORT_PROXY}
  Scan File  ${MESSAGE}  From=proxyreleased@example.net  Rcpt=proxyreleased-rcpt@example.net
  Expect Symbol  SIMPLE_TEST

*** Keywords ***
Assert Admitted
  [Arguments]  ${port}
  ${ok} =  Connection Admitted  ${RSPAMD_LOCAL_ADDR}  ${port}
  Should Be True  ${ok}  msg=connection to ${port} was refused but the limit is not reached

Assert Refused
  [Arguments]  ${port}
  ${ok} =  Connection Admitted  ${RSPAMD_LOCAL_ADDR}  ${port}
  Should Not Be True  ${ok}  msg=connection to ${port} was admitted past the configured limit
