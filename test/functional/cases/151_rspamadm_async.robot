*** Settings ***
Test Setup      Rspamadm test Setup
Test Teardown   Rspamadm test Teardown
Library         Process
Library         ${TESTDIR}/lib/rspamd.py
Resource        ${TESTDIR}/lib/rspamd.robot
Variables       ${TESTDIR}/lib/vars.py
Suite Teardown  Terminate All Processes    kill=True

*** Variables ***
${REDIS_SCOPE}   Test


*** Test Cases ***
Tcp client
  ${result} =  Run Process  ${RSPAMADM}  lua  -b  ${TESTDIR}/lua/rspamadm/test_tcp_client.lua
  Should Match Regexp  ${result.stderr}  ^$
  Should Be Equal As Integers  ${result.rc}  0
  Should Be Equal  ${result.stdout}  hello post

Redis client
  ${result} =  Run Process  ${RSPAMADM}  lua  -b  ${TESTDIR}/lua/rspamadm/test_redis_client.lua
  Should Match Regexp  ${result.stderr}  ^$
  Should Be Equal As Integers  ${result.rc}  0
  Should Be Equal  ${result.stdout}  true\thello from lua on redis

*** Keywords ***

Rspamadm test Setup
  Run Dummy Http
  Run Redis

Rspamadm test Teardown
  ${http_pid} =  Get File  /tmp/dummy_http.pid
  Shutdown Process With Children  ${http_pid}
  Remove file  /tmp/dummy_http.pid
  Shutdown Process With Children  ${REDIS_PID}

Run Dummy Http
  [Arguments]
  ${result} =  Start Process  ${TESTDIR}/util/dummy_http.py
  Wait Until Created  /tmp/dummy_http.pid
