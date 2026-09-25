*** Settings ***
Documentation   HTTP client stage timeouts: the stage before the write one (connect for
...             plain HTTP, the handshake for TLS), the write and the read stages must each
...             run with their own timeout, on a fresh and on a reused keepalive connection
Suite Setup     Http Stages Setup
Suite Teardown  Http Stages Teardown
Library         OperatingSystem
Library         Process
Library         ${RSPAMD_TESTDIR}/lib/rspamd.py
Resource        ${RSPAMD_TESTDIR}/lib/rspamd.robot
Variables       ${RSPAMD_TESTDIR}/lib/vars.py

*** Variables ***
${CONFIG}              ${RSPAMD_TESTDIR}/configs/lua_test.conf
${MESSAGE}             ${RSPAMD_TESTDIR}/messages/spam_message.eml
${RSPAMD_LUA_SCRIPT}   ${RSPAMD_TESTDIR}/lua/http_stage_timeouts.lua
${RSPAMD_SCOPE}        Suite
${RSPAMD_URL_TLD}      ${RSPAMD_TESTDIR}/../lua/unit/test_tld.dat

*** Test Cases ***
HTTP read stage outlives connect_timeout
  Fresh Request  read  http  200

HTTPS read stage outlives ssl_timeout
  Fresh Request  read  https  200

HTTP read_timeout fires
  Fresh Request  read-timeout  http  IO timeout

HTTPS read_timeout fires
  Fresh Request  read-timeout  https  IO timeout

HTTP write stage outlives connect_timeout
  Fresh Request  write  http  200

HTTPS write stage outlives ssl_timeout
  Fresh Request  write  https  200

HTTP write_timeout fires
  Fresh Request  write-timeout  http  IO timeout

HTTPS write_timeout fires
  Fresh Request  write-timeout  https  IO timeout

HTTPS ssl_timeout fires on a stalled handshake
  Fresh Request  handshake-timeout  https  ssl connection timed out

HTTP reused connection read stage outlives connect_timeout
  Reused Request  read  http  200

HTTPS reused connection read stage outlives ssl_timeout
  Reused Request  read  https  200

HTTP reused connection read_timeout fires
  Reused Request  read-timeout  http  IO timeout

HTTPS reused connection read_timeout fires
  Reused Request  read-timeout  https  IO timeout

HTTP reused connection write stage outlives connect_timeout
  Reused Request  write  http  200

HTTPS reused connection write stage outlives ssl_timeout
  Reused Request  write  https  200

HTTP reused connection write_timeout fires
  Reused Request  write-timeout  http  IO timeout

HTTPS reused connection write_timeout fires
  Reused Request  write-timeout  https  IO timeout

*** Keywords ***
Fresh Request
  [Arguments]  ${case}  ${proto}  ${expected}
  Scan File  ${MESSAGE}  Stage-Case=${case}  Stage-Proto=${proto}
  ...  Settings={symbols_enabled = [HTTP_STAGE_TIMEOUT_TEST]}
  Expect Symbol With Exact Options  HTTP_STAGE_RESULT  ${expected}

Reused Request
  [Arguments]  ${case}  ${proto}  ${expected}
  Scan File  ${MESSAGE}  Stage-Case=${case}  Stage-Proto=${proto}  Stage-Step=prime
  ...  Settings={symbols_enabled = [HTTP_STAGE_TIMEOUT_TEST]}
  Expect Symbol With Exact Options  HTTP_STAGE_RESULT  200
  Scan File  ${MESSAGE}  Stage-Case=${case}  Stage-Proto=${proto}  Stage-Step=run
  ...  Settings={symbols_enabled = [HTTP_STAGE_TIMEOUT_TEST]}
  Expect Symbol With Exact Options  HTTP_STAGE_RESULT  ${expected}
  # The run request has to be the second one on the connection the prime request opened
  ${log} =  Get File  ${HTTP_STAGES_LOG_${proto}}
  Should Contain  ${log}  tag=${case}-${proto}-run request=2

Run Dummy Http Stages
  [Arguments]  ${port}  @{extra}
  ${pid} =  Set Variable  ${RSPAMD_TMP_PREFIX}/dummy_http_stages-${port}.pid
  ${log} =  Set Variable  ${RSPAMD_TMP_PREFIX}/dummy_http_stages-${port}.log
  ${proc} =  Start Dummy Service  dummy_http_stages.py  ${pid}  ${log}
  ...  ${RSPAMD_TESTDIR}/util/dummy_http_stages.py  -pf  ${pid}  -p  ${port}  @{extra}
  Wait Until Dummy Listening  ${RSPAMD_LOCAL_ADDR}  ${port}
  RETURN  ${proc}  ${log}

Http Stages Setup
  ${proc}  ${log} =  Run Dummy Http Stages  ${RSPAMD_PORT_DUMMY_HTTP_STAGES}
  Set Suite Variable  ${HTTP_STAGES_PROC_http}  ${proc}
  Set Suite Variable  ${HTTP_STAGES_LOG_http}  ${log}
  ${proc}  ${log} =  Run Dummy Http Stages  ${RSPAMD_PORT_DUMMY_HTTPS_STAGES}
  ...  -c  ${RSPAMD_TESTDIR}/util/server.pem
  Set Suite Variable  ${HTTP_STAGES_PROC_https}  ${proc}
  Set Suite Variable  ${HTTP_STAGES_LOG_https}  ${log}
  ${proc}  ${log} =  Run Dummy Http Stages  ${RSPAMD_PORT_DUMMY_SILENT}  --silent
  Set Suite Variable  ${HTTP_STAGES_PROC_silent}  ${proc}
  Rspamd Setup

Http Stages Teardown
  Rspamd Teardown
  FOR  ${proc}  IN  ${HTTP_STAGES_PROC_http}  ${HTTP_STAGES_PROC_https}  ${HTTP_STAGES_PROC_silent}
    Terminate Process  ${proc}
    Wait For Process  ${proc}
  END
