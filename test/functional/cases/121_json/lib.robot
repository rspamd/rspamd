*** Variables ***
${URL_TLD}      ${TESTDIR}/../lua/unit/test_tld.dat

*** Keywords ***
JSON Setup
  New Setup  LUA_SCRIPT=${LUA_SCRIPT}  URL_TLD=${URL_TLD}

Stat Test
  @{result} =  HTTP  GET  ${LOCAL_ADDR}  ${PORT_CONTROLLER}  /stat
  Check JSON  ${result}[1]
  Should Be Equal As Integers  ${result}[0]  200

History Test
  [Arguments]  ${rspamc_expected_result}
  ${result} =  Scan Message With Rspamc  ${MESSAGE}
  Check Rspamc  ${result}  ${rspamc_expected_result}
  @{result} =  HTTP  GET  ${LOCAL_ADDR}  ${PORT_CONTROLLER}  /history
  Check JSON  ${result}[1]
  Should Be Equal As Integers  ${result}[0]  200

Scan Test
  ${content} =  Get File  ${MESSAGE}
  @{result} =  HTTP  POST  ${LOCAL_ADDR}  ${PORT_NORMAL}  /check  ${content}
  Check JSON  ${result}[1]
  Should Be Equal As Integers  ${result}[0]  200
