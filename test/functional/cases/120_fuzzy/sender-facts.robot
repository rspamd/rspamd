*** Settings ***
Suite Setup     Fuzzy Setup Encrypted Siphash
Suite Teardown  Rspamd Redis Teardown
Resource        lib.robot

*** Variables ***
${MESSAGE}                      ${RSPAMD_TESTDIR}/messages/spam_message.eml

*** Test Cases ***
Sender Facts Are Sent For A Remote Sender
  ${extensions} =  Scan And Read Fuzzy Extensions  IP=8.8.8.8  From=foo@example.com
  Should Contain  ${extensions}  ip=8.8.8.8
  Should Contain  ${extensions}  rcpts=1
  Should Contain  ${extensions}  tls=false
  Should Contain  ${extensions}  ptr_generic=false

Extensions Are Suppressed For A Local Sender
  ${extensions} =  Scan And Read Fuzzy Extensions  IP=127.0.0.1  From=foo@example.com
  Should Contain  ${extensions}  extensions=none

Extensions Are Suppressed For An Authenticated Sender
  ${extensions} =  Scan And Read Fuzzy Extensions  IP=8.8.8.8  From=foo@example.com
  ...  User=foo@example.com
  Should Contain  ${extensions}  extensions=none

*** Keywords ***
Scan And Read Fuzzy Extensions
  [Arguments]  &{headers}
  Remove File  ${RSPAMD_TMPDIR}/fuzzy_extensions.log
  Scan File  ${MESSAGE}  &{headers}
  Wait Until Created  ${RSPAMD_TMPDIR}/fuzzy_extensions.log  timeout=10s
  ${extensions} =  Get File  ${RSPAMD_TMPDIR}/fuzzy_extensions.log
  Log  ${extensions}
  RETURN  ${extensions}
