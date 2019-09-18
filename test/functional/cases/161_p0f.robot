*** Settings ***
Suite Setup     p0f Setup
Suite Teardown  p0f Teardown
Library         Process
Library         ${TESTDIR}/lib/rspamd.py
Resource        ${TESTDIR}/lib/rspamd.robot
Variables       ${TESTDIR}/lib/vars.py

*** Variables ***
${CONFIG}       ${TESTDIR}/configs/plugins.conf
${MESSAGE}      ${TESTDIR}/messages/spam_message.eml
${MESSAGE2}     ${TESTDIR}/messages/freemail.eml
${REDIS_SCOPE}  Suite
${RSPAMD_SCOPE}  Suite
${URL_TLD}      ${TESTDIR}/../lua/unit/test_tld.dat

*** Test Cases ***
p0f MISS
  Run Dummy p0f
  ${result} =  Scan Message With Rspamc  ${MESSAGE}  --ip  1.1.1.1
  Check Rspamc  ${result}  P0F
  Check Rspamc  ${result}  WINDOWS  inverse=1
  Check Rspamc  ${result}  P0F_FAIL  inverse=1
  Shutdown p0f

p0f HIT
  Run Dummy p0f  ${P0F_SOCKET}  windows
  ${result} =  Scan Message With Rspamc  ${MESSAGE}  --ip  1.1.1.2
  Check Rspamc  ${result}  P0F  inverse=1
  Check Rspamc  ${result}  P0F_FAIL  inverse=1
  Check Rspamc  ${result}  ETHER
  Check Rspamc  ${result}  DISTGE10
  Check Rspamc  ${result}  WINDOWS
  Shutdown p0f

p0f MISS CACHE
  Run Dummy p0f
  ${result} =  Scan Message With Rspamc  ${MESSAGE}  --ip  1.1.1.3
  Check Rspamc  ${result}  WINDOWS  inverse=1
  Shutdown p0f
  ${result} =  Scan Message With Rspamc  ${MESSAGE}  --ip  1.1.1.3
  Check Rspamc  ${result}  WINDOWS  inverse=1
  Check Rspamc  ${result}  P0F_FAIL  inverse=1

p0f HIT CACHE
  Run Dummy p0f  ${P0F_SOCKET}  windows
  ${result} =  Scan Message With Rspamc  ${MESSAGE}  --ip  1.1.1.4
  Check Rspamc  ${result}  WINDOWS
  Shutdown p0f
  ${result} =  Scan Message With Rspamc  ${MESSAGE}  --ip  1.1.1.4
  Check Rspamc  ${result}  WINDOWS
  Check Rspamc  ${result}  P0F_FAIL  inverse=1

p0f NO REDIS
  Shutdown Process With Children  ${REDIS_PID}
  Run Dummy p0f
  ${result} =  Scan Message With Rspamc  ${MESSAGE}  --ip  1.1.1.5
  Check Rspamc  ${result}  P0F
  Check Rspamc  ${result}  ETHER
  Check Rspamc  ${result}  DISTGE10
  Check Rspamc  ${result}  P0F_FAIL  inverse=1
  Shutdown p0f

p0f NO MATCH
  Run Dummy p0f  ${P0F_SOCKET}  windows  no_match
  ${result} =  Scan Message With Rspamc  ${MESSAGE}  --ip  1.1.1.6
  Check Rspamc  ${result}  P0F  inverse=1
  Check Rspamc  ${result}  WINDOWS  inverse=1
  Shutdown p0f

p0f BAD QUERY
  Run Dummy p0f  ${P0F_SOCKET}  windows  bad_query
  ${result} =  Scan Message With Rspamc  ${MESSAGE}  --ip  1.1.1.7
  Check Rspamc  ${result}  P0F_FAIL
  Check Rspamc  ${result}  Malformed Query
  Check Rspamc  ${result}  WINDOWS  inverse=1
  Shutdown p0f

p0f BAD RESPONSE
  Run Dummy p0f  ${P0F_SOCKET}  windows  bad_response
  ${result} =  Scan Message With Rspamc  ${MESSAGE}  --ip  1.1.1.8
  Check Rspamc  ${result}  P0F_FAIL
  Check Rspamc  ${result}  Malformed Response
  Check Rspamc  ${result}  WINDOWS  inverse=1
  Shutdown p0f

*** Keywords ***
p0f Setup
  ${PLUGIN_CONFIG} =  Get File  ${TESTDIR}/configs/p0f.conf
  Set Suite Variable  ${PLUGIN_CONFIG}
  Generic Setup  PLUGIN_CONFIG
  Run Redis

p0f Teardown
  Normal Teardown
  Shutdown Process With Children  ${REDIS_PID}
  Shutdown p0f
  Terminate All Processes    kill=True

Shutdown p0f
  ${p0f_pid} =  Get File if exists  /tmp/dummy_p0f.pid
  Run Keyword if  ${p0f_pid}  Shutdown Process With Children  ${p0f_pid}

Run Dummy p0f
  [Arguments]  ${socket}=${P0F_SOCKET}  ${os}=linux  ${status}=ok
  ${result} =  Start Process  ${TESTDIR}/util/dummy_p0f.py  ${socket}  ${os}  ${status}
  Wait Until Created  /tmp/dummy_p0f.pid
