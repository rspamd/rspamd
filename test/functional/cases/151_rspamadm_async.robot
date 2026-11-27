*** Settings ***
Test Setup      Rspamadm test Setup
Test Teardown   Rspamadm test Teardown
Library         Process
Library         ${RSPAMD_TESTDIR}/lib/rspamd.py
Resource        ${RSPAMD_TESTDIR}/lib/rspamd.robot
Variables       ${RSPAMD_TESTDIR}/lib/vars.py

*** Variables ***
${CONFIG}          ${RSPAMD_TESTDIR}/configs/plugins.conf
${REDIS_SCOPE}     Test
# For dummy http
${RSPAMD_SCOPE}    Test
${RSPAMD_URL_TLD}  ${RSPAMD_TESTDIR}/../lua/unit/test_tld.dat

*** Test Cases ***
#Tcp client
#  ${result} =  Run Process  ${RSPAMADM}  lua  -b  ${RSPAMD_TESTDIR}/lua/rspamadm/test_tcp_client.lua
#  Should Match Regexp  ${result.stderr}  ^$
#  Should Be Equal As Integers  ${result.rc}  0
#  Should Be Equal  ${result.stdout}  hello post

Redis client
  ${result} =  Run Process  ${RSPAMADM}  lua  -b  ${RSPAMD_TESTDIR}/lua/rspamadm/test_redis_client.lua
  Should Match Regexp  ${result.stderr}  ^$
  Should Be Equal As Integers  ${result.rc}  0
  Should Be Equal  ${result.stdout}  true\thello from lua on redis

Interpreter results after sync requests
  [Documentation]  Lines suspended by a sync HTTP request and by a sync redis
  ...              command print what they return once they are resumed
  ${input} =  Catenate  SEPARATOR=\n
  ...  http = require('rspamd_http')
  ...  redis = require('rspamd_redis')
  ...  (function() local err, resp = http.request({url = 'http://127.0.0.1:${RSPAMD_PORT_DUMMY_HTTP}/request', config = rspamd_config, ev_base = rspamadm_ev_base, session = rspamadm_session, timeout = 5}) return err, resp and resp.code, resp and resp.content end)()
  ...  (function() local ok, conn = redis.connect_sync({host = '${RSPAMD_REDIS_ADDR}:${RSPAMD_REDIS_PORT}', config = rspamd_config, ev_base = rspamadm_ev_base, session = rspamadm_session, timeout = 5}) conn:add_cmd('PING', {}) return ok, conn:exec() end)()
  ...  1, 'x'
  ${tmpdir} =  Make Temporary Directory
  Create File  ${tmpdir}/repl_sync.txt  ${input}\n
  ${result} =  Run Process  ${RSPAMADM}  lua  -b  stdin=${tmpdir}/repl_sync.txt
  Cleanup Temporary Directory  ${tmpdir}
  Should Be Equal As Integers  ${result.rc}  0  msg=${result.stderr}
  Should Be Equal  ${result.stdout}  nil\n200\nhello world\ntrue\ntrue\nPONG\n1\nx

# Broken due to tmpdir override
#DNS client
#  ${result} =  Run Process  ${RSPAMADM}  --var\=CONFDIR\=${tmpdir}  lua  -b  ${RSPAMD_TESTDIR}/lua/rspamadm/test_dns_client.lua
#  Log  ${result.stdout}
#  Log  ${result.stderr}
#  Should Be Equal As Integers  ${result.rc}  0
#  Should Be Equal  ${result.stdout}  true\tk=ed25519; p=yi50DjK5O9pqbFpNHklsv9lqaS0ArSYu02qp1S0DW1Y=
#  Cleanup Temporary Directory  ${tmpdir}

*** Keywords ***

Rspamadm test Setup
  # Make per-worker ports (RSPAMD_REDIS_PORT etc.) visible to the
  # rspamadm subprocess. Run Rspamd usually does this, but this suite
  # only spins up redis + dummy_http and the rspamadm lua client
  # script reads its target port from the env.
  Export Rspamd Variables To Environment
  Run Dummy Http
  Run Redis

Rspamadm test Teardown
  Dummy Http Teardown
  Redis Teardown

Prepare temp directory
  [Arguments]  ${CONFIG}
  ${template} =  Get File  ${CONFIG}
  ${tmpdir} =  Make Temporary Directory
  ${config} =  Replace Variables  ${template}
  ${config} =  Replace Variables  ${config}
  Log  ${config}
  Create File  ${tmpdir}/rspamd.conf  ${config}
  RETURN    ${tmpdir}
