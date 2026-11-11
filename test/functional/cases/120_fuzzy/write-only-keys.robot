*** Settings ***
Suite Setup     Fuzzy Setup Write Only Keys
Suite Teardown  Rspamd Redis Teardown
Resource        lib.robot
Library         Collections
Variables       ${RSPAMD_TESTDIR}/lib/vars.py

*** Variables ***
${CONFIG}       ${RSPAMD_TESTDIR}/configs/fuzzy-write-only-keys.conf

*** Test Cases ***
Fuzzy Status Pings Write Only Rule With The Write Key
  ${json} =  Wait Until Keyword Succeeds  10x  0.5s  Controller Fuzzy Status
  ...  ${RSPAMD_LOCAL_ADDR}  ${RSPAMD_PORT_CONTROLLER}
  ${rules} =  Get Dictionary Keys  ${json}[storages]
  Length Should Be  ${rules}  1
  ${servers} =  Set Variable  ${json}[storages][${rules}[0]][servers]
  # The write-only rule aliases read_servers to write_servers, so the
  # single shared server must be pinged with the write keypair
  Length Should Be  ${servers}  1
  Should Be Equal  ${servers}[0][ok]  ${True}
