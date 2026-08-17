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

*** Test Cases ***
Scanner counts body-pending connections
  [Documentation]  max_tasks used to count completed requests only, so a client
  ...              that connected and then stalled did not occupy a slot. It
  ...              does now: reaching the limit refuses the next connection and
  ...              one slot short of it admits again.
  Count Pending Connections  ${RSPAMD_PORT_NORMAL}

Scanner releases the slots of disconnected clients
  [Documentation]  The counter must be released on the teardown path as well,
  ...              otherwise a burst of stalled clients would wedge the worker
  ...              for good.
  Reach The Limit  ${RSPAMD_PORT_NORMAL}
  Close Pending Connections
  Wait Until Keyword Succeeds  20x  0.25s  Assert Admitted  ${RSPAMD_PORT_NORMAL}
  Scan File  ${MESSAGE}  From=released@example.net  Rcpt=released-rcpt@example.net
  Expect Symbol  SIMPLE_TEST

Controller counts pending connections
  Count Pending Connections  ${RSPAMD_PORT_CONTROLLER}

Controller releases the slots of disconnected clients
  Reach The Limit  ${RSPAMD_PORT_CONTROLLER}
  Close Pending Connections
  Wait Until Keyword Succeeds  20x  0.25s  Assert Admitted  ${RSPAMD_PORT_CONTROLLER}

Proxy counts pending connections
  Count Pending Connections  ${RSPAMD_PORT_PROXY}

Proxy releases the slots of disconnected clients
  Reach The Limit  ${RSPAMD_PORT_PROXY}
  Close Pending Connections
  Wait Until Keyword Succeeds  20x  0.25s  Assert Admitted  ${RSPAMD_PORT_PROXY}
  Set Test Variable  ${RSPAMD_PORT_NORMAL}  ${RSPAMD_PORT_PROXY}
  Scan File  ${MESSAGE}  From=proxyreleased@example.net  Rcpt=proxyreleased-rcpt@example.net
  Expect Symbol  SIMPLE_TEST

*** Keywords ***
Reach The Limit
  [Documentation]  Occupy every slot of ${port} and prove it with a refused probe.
  ...
  ...              A connection that arrives while the worker is already at its
  ...              limit is accepted and closed at once, and the client cannot
  ...              tell the difference from a connection that is waiting for its
  ...              body -- so a batch opened while the previous test's slots are
  ...              still held silently comes up short. The slots are released
  ...              when the worker's event loop gets to the disconnect, which is
  ...              not ordered against Robot running the next test.
  ...
  ...              The listen queue is FIFO, so the probe is accepted after the
  ...              whole batch and the worker has decided about every one of its
  ...              connections by the time the probe is answered: a refused
  ...              probe plus a batch that is still alive is proof that we hold
  ...              every slot ourselves. Anything else means we raced the
  ...              release of the previous slots, hence the retries.
  [Arguments]  ${port}
  Wait Until Keyword Succeeds  20x  0.25s  Fill Every Slot  ${port}

Fill Every Slot
  [Arguments]  ${port}
  Close Pending Connections
  Open Pending Connections  ${RSPAMD_LOCAL_ADDR}  ${port}  ${LIMIT}
  Assert Refused  ${port}
  ${alive} =  Pending Connections Alive
  Should Be Equal As Integers  ${alive}  ${LIMIT}
  ...  msg=${port} refused part of the batch, the slots of the previous connections are still held

Count Pending Connections
  [Documentation]  Body-pending connections are counted one by one: the limit
  ...              refuses the next connection, and freeing a single slot is
  ...              enough to admit it again.
  ...
  ...              Going the other way round -- opening one connection less
  ...              than the limit and expecting an admission -- would have to
  ...              assume that the slot of the probe sent one step earlier is
  ...              already free, which is the same unordered release as above.
  [Arguments]  ${port}
  Reach The Limit  ${port}
  Close One Pending Connection
  Wait Until Keyword Succeeds  20x  0.25s  Assert Admitted  ${port}

Assert Admitted
  [Arguments]  ${port}
  ${ok} =  Connection Admitted  ${RSPAMD_LOCAL_ADDR}  ${port}
  Should Be True  ${ok}  msg=connection to ${port} was refused but the limit is not reached

Assert Refused
  [Arguments]  ${port}
  ${ok} =  Connection Admitted  ${RSPAMD_LOCAL_ADDR}  ${port}
  Should Not Be True  ${ok}  msg=connection to ${port} was admitted past the configured limit
