*** Settings ***
Suite Setup     p0f Setup
Suite Teardown  p0f Teardown
Library         Process
Library         ${RSPAMD_TESTDIR}/lib/rspamd.py
Resource        ${RSPAMD_TESTDIR}/lib/rspamd.robot
Variables       ${RSPAMD_TESTDIR}/lib/vars.py

*** Variables ***
${CONFIG}          ${RSPAMD_TESTDIR}/configs/p0f.conf
${MESSAGE2}        ${RSPAMD_TESTDIR}/messages/freemail.eml
${MESSAGE}         ${RSPAMD_TESTDIR}/messages/spam_message.eml
${REDIS_SCOPE}     Suite
${RSPAMD_SCOPE}    Suite
${RSPAMD_URL_TLD}  ${RSPAMD_TESTDIR}/../lua/unit/test_tld.dat

*** Test Cases ***
p0f MISS
  Run Dummy p0f
  Scan File  ${MESSAGE}  IP=1.1.1.1
  Do Not Expect Symbol  P0F_FAIL
  Do Not Expect Symbol  WINDOWS
  Expect Symbol With Exact Options  P0F  Linux 3.11 and newer  link=Ethernet or modem  distance=10
  Shutdown p0f

p0f HIT
  Run Dummy p0f  ${RSPAMD_P0F_SOCKET}  windows
  Scan File  ${MESSAGE}  IP=1.1.1.2
  Do Not Expect Symbol  P0F_FAIL
  Expect Symbol With Exact Options  P0F  link=Ethernet or modem  distance=10
  Expect Symbol  WINDOWS
  Shutdown p0f

p0f MISS CACHE
  Run Dummy p0f
  Scan File  ${MESSAGE}  IP=1.1.1.3
  Do Not Expect Symbol  WINDOWS
  Shutdown p0f
  Scan File  ${MESSAGE}  IP=1.1.1.3
  Do Not Expect Symbol  WINDOWS
  Do Not Expect Symbol  P0F_FAIL

p0f HIT CACHE
  Run Dummy p0f  ${RSPAMD_P0F_SOCKET}  windows
  Scan File  ${MESSAGE}  IP=1.1.1.4
  Expect Symbol  WINDOWS
  Shutdown p0f
  Scan File  ${MESSAGE}  IP=1.1.1.4
  Expect Symbol  WINDOWS
  Do Not Expect Symbol  P0F_FAIL

p0f NO REDIS
  Shutdown Process With Children  ${REDIS_PID}
  Run Dummy p0f
  Scan File  ${MESSAGE}  IP=1.1.1.5
  Expect Symbol With Exact Options  P0F  Linux 3.11 and newer  link=Ethernet or modem  distance=10
  Do Not Expect Symbol  P0F_FAIL
  Shutdown p0f

p0f NO MATCH
  Run Dummy p0f  ${RSPAMD_P0F_SOCKET}  windows  no_match
  Scan File  ${MESSAGE}  IP=1.1.1.6
  Do Not Expect Symbol  P0F
  Do Not Expect Symbol  WINDOWS
  Shutdown p0f

p0f BAD QUERY
  Run Dummy p0f  ${RSPAMD_P0F_SOCKET}  windows  bad_query
  Scan File  ${MESSAGE}  IP=1.1.1.7
  Expect Symbol With Exact Options  P0F_FAIL  Malformed Query: /tmp/p0f.sock
  Do Not Expect Symbol  WINDOWS
  Shutdown p0f

p0f BAD RESPONSE
  Run Dummy p0f  ${RSPAMD_P0F_SOCKET}  windows  bad_response
  Scan File  ${MESSAGE}  IP=1.1.1.8
  Expect Symbol With Exact Options  P0F_FAIL  Error getting result: IO read error: connection terminated
  Do Not Expect Symbol  WINDOWS
  Shutdown p0f

*** Keywords ***
p0f Setup
  Rspamd Redis Setup

p0f Teardown
  Rspamd Redis Teardown
  Shutdown p0f
  Terminate All Processes    kill=True

Shutdown p0f
  ${p0f_pid} =  Get File if exists  /tmp/dummy_p0f.pid
  Run Keyword if  ${p0f_pid}  Shutdown Process With Children  ${p0f_pid}

Run Dummy p0f
  [Arguments]  ${socket}=${RSPAMD_P0F_SOCKET}  ${os}=linux  ${status}=ok
  ${result} =  Start Process  ${RSPAMD_TESTDIR}/util/dummy_p0f.py  ${socket}  ${os}  ${status}
  Wait Until Created  /tmp/dummy_p0f.pid
