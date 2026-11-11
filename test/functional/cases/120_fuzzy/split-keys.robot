*** Settings ***
Suite Setup     Fuzzy Setup Split Keys
Suite Teardown  Rspamd Redis Teardown
Resource        lib.robot
Library         Collections
Variables       ${RSPAMD_TESTDIR}/lib/vars.py

*** Variables ***
${CONFIG}       ${RSPAMD_TESTDIR}/configs/fuzzy-split-keys.conf

*** Test Cases ***
Fuzzy Status Pings Read And Write Storages With Separate Keys
  ${json} =  Wait Until Keyword Succeeds  10x  0.5s  Controller Fuzzy Status
  ...  ${RSPAMD_LOCAL_ADDR}  ${RSPAMD_PORT_CONTROLLER}
  ${rules} =  Get Dictionary Keys  ${json}[storages]
  Length Should Be  ${rules}  1
  ${servers} =  Set Variable  ${json}[storages][${rules}[0]][servers]
  # The deduplicated union of the read and write lists: one server each
  Length Should Be  ${servers}  2
  FOR  ${server}  IN  @{servers}
    Should Be Equal  ${server}[ok]  ${True}
    Log  ${server}
  END
