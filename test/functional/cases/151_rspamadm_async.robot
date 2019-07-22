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
${CONFIG}       ${TESTDIR}/configs/plugins.conf
${URL_TLD}      ${TESTDIR}/../lua/unit/test_tld.dat
${PLUGIN_CONFIG}

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

DNS client
  ${tmpdir} =  Prepare temp directory  ${CONFIG}
  Set test variable  ${tmpdir}
  ${result} =  Run Process  ${RSPAMADM}  --var\=CONFDIR\=${tmpdir}  lua  -b  ${TESTDIR}/lua/rspamadm/test_dns_client.lua
  Log  ${result.stdout}
  Log  ${result.stderr}
  Should Be Equal As Integers  ${result.rc}  0
  Should Be Equal  ${result.stdout}  true\tk=ed25519; p=yi50DjK5O9pqbFpNHklsv9lqaS0ArSYu02qp1S0DW1Y=
  Cleanup Temporary Directory  ${tmpdir}

*** Keywords ***

Rspamadm test Setup
  ${tmpdir} =  Make Temporary Directory
  Set Suite Variable  ${TMPDIR}  ${tmpdir}
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

Prepare temp directory
  [Arguments]  ${CONFIG}
  ${template} =  Get File  ${CONFIG}
  ${tmpdir} =  Make Temporary Directory
  ${config} =  Replace Variables  ${template}
  ${config} =  Replace Variables  ${config}
  Log  ${config}
  Create File  ${tmpdir}/rspamd.conf  ${config}
  [Return]  ${tmpdir}