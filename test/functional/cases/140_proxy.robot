*** Settings ***
Suite Setup     Proxy Setup
Suite Teardown  Proxy Teardown
Library         ${TESTDIR}/lib/rspamd.py
Resource        ${TESTDIR}/lib/rspamd.robot
Variables       ${TESTDIR}/lib/vars.py

*** Variables ***
${LUA_SCRIPT}    ${TESTDIR}/lua/simple.lua
${MESSAGE}       ${TESTDIR}/messages/spam_message.eml
${RSPAMD_SCOPE}  Suite
${URL_TLD}       ${TESTDIR}/../lua/unit/test_tld.dat

*** Test Cases ***
HTTP PROTOCOL
  Set Test Variable  ${PORT_NORMAL}  ${PORT_PROXY}
  Scan File  ${MESSAGE}
  Expect Symbol  SIMPLE_TEST

SPAMC
  ${result} =  Spamc  ${LOCAL_ADDR}  ${PORT_PROXY}  ${MESSAGE}
  Should Contain  ${result}  SPAMD/1.1 0 EX_OK

RSPAMC Legacy Protocol
  ${result} =  Rspamc  ${LOCAL_ADDR}  ${PORT_PROXY}  ${MESSAGE}
  Should Contain  ${result}  RSPAMD/1.3 0 EX_OK

*** Keywords ***
Proxy Setup
  # Run slave & copy variables
  Set Suite Variable  ${CONFIG}  ${TESTDIR}/configs/lua_test.conf
  New Setup  LUA_SCRIPT=${LUA_SCRIPT}  URL_TLD=${URL_TLD}
  Set Suite Variable  ${SLAVE_PID}  ${RSPAMD_PID}
  Set Suite Variable  ${SLAVE_TMPDIR}  ${TMPDIR}

  # Run proxy & copy variables
  Set Suite Variable  ${CONFIG}  ${TESTDIR}/configs/proxy.conf
  New Setup
  Set Suite Variable  ${PROXY_PID}  ${RSPAMD_PID}
  Set Suite Variable  ${PROXY_TMPDIR}  ${TMPDIR}

Proxy Teardown
  # Restore variables & run normal teardown
  Set Suite Variable  ${RSPAMD_PID}  ${PROXY_PID}
  Set Suite Variable  ${TMPDIR}  ${PROXY_TMPDIR}
  Normal Teardown
  # Do it again for slave
  Set Suite Variable  ${RSPAMD_PID}  ${SLAVE_PID}
  Set Suite Variable  ${TMPDIR}  ${SLAVE_TMPDIR}
  Normal Teardown
