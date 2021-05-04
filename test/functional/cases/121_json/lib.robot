*** Variables ***
${RSPAMD_URL_TLD}      ${RSPAMD_TESTDIR}/../lua/unit/test_tld.dat

*** Keywords ***
Stat Test
  @{result} =  HTTP  GET  ${RSPAMD_LOCAL_ADDR}  ${RSPAMD_PORT_CONTROLLER}  /stat
  Check JSON  ${result}[1]
  Should Be Equal As Integers  ${result}[0]  200

History Test
  [Arguments]  ${rspamc_expected_result}
  ${result} =  Scan Message With Rspamc  ${MESSAGE}
  Check Rspamc  ${result}  ${rspamc_expected_result}
  @{result} =  HTTP  GET  ${RSPAMD_LOCAL_ADDR}  ${RSPAMD_PORT_CONTROLLER}  /history
  Check JSON  ${result}[1]
  Should Be Equal As Integers  ${result}[0]  200

Scan Test
  ${content} =  Get File  ${MESSAGE}
  @{result} =  HTTP  POST  ${RSPAMD_LOCAL_ADDR}  ${RSPAMD_PORT_NORMAL}  /check  ${content}
  Check JSON  ${result}[1]
  Should Be Equal As Integers  ${result}[0]  200
