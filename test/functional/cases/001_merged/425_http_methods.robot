*** Settings ***
Library         ${RSPAMD_TESTDIR}/lib/rspamd.py
Resource        ${RSPAMD_TESTDIR}/lib/rspamd.robot
Variables       ${RSPAMD_TESTDIR}/lib/vars.py

*** Test Cases ***
Check Refuses PUT
  [Documentation]  A check command takes GET and POST only
  @{result} =  HTTP With Headers  PUT  ${RSPAMD_LOCAL_ADDR}  ${RSPAMD_PORT_NORMAL}  /checkv2  data=test
  Should Be Equal As Integers  ${result}[0]  405
  Should Be Equal  ${result}[2][Allow]  GET, POST

Check Refuses QUERY
  [Documentation]  QUERY is parsed, but a check command does not take it
  @{result} =  HTTP With Headers  QUERY  ${RSPAMD_LOCAL_ADDR}  ${RSPAMD_PORT_NORMAL}  /checkv2  data=test
  Should Be Equal As Integers  ${result}[0]  405
  Should Be Equal  ${result}[2][Allow]  GET, POST

Controller Refuses PUT
  [Documentation]  The controller takes GET, POST and OPTIONS
  @{result} =  HTTP With Headers  PUT  ${RSPAMD_LOCAL_ADDR}  ${RSPAMD_PORT_CONTROLLER}  /stat
  Should Be Equal As Integers  ${result}[0]  405
  Should Be Equal  ${result}[2][Allow]  GET, POST, OPTIONS

Controller Refuses QUERY
  @{result} =  HTTP With Headers  QUERY  ${RSPAMD_LOCAL_ADDR}  ${RSPAMD_PORT_CONTROLLER}  /stat
  Should Be Equal As Integers  ${result}[0]  405
  Should Be Equal  ${result}[2][Allow]  GET, POST, OPTIONS
