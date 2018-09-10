*** Settings ***
Test Setup      Http Setup
Test Teardown   Http Teardown
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

*** Keywords ***

Http Setup
  Run Dummy Http

Http Teardown
  ${http_pid} =  Get File  /tmp/dummy_http.pid
  Shutdown Process With Children  ${http_pid}
  Remove file  /tmp/dummy_http.pid

Run Dummy Http
  [Arguments]
  ${result} =  Start Process  ${TESTDIR}/util/dummy_http.py
  Wait Until Created  /tmp/dummy_http.pid
