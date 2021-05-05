*** Settings ***
Suite Setup     Proxy Setup
Suite Teardown  Proxy Teardown
Library         ${RSPAMD_TESTDIR}/lib/rspamd.py
Resource        ${RSPAMD_TESTDIR}/lib/rspamd.robot
Variables       ${RSPAMD_TESTDIR}/lib/vars.py

*** Variables ***
${MESSAGE}            ${RSPAMD_TESTDIR}/messages/spam_message.eml
${RSPAMD_LUA_SCRIPT}  ${RSPAMD_TESTDIR}/lua/simple.lua
${RSPAMD_SCOPE}       Suite
${RSPAMD_URL_TLD}     ${RSPAMD_TESTDIR}/../lua/unit/test_tld.dat

*** Test Cases ***
HTTP PROTOCOL
  Set Test Variable  ${RSPAMD_PORT_NORMAL}  ${RSPAMD_PORT_PROXY}
  Scan File  ${MESSAGE}
  Expect Symbol  SIMPLE_TEST

SPAMC
  ${result} =  Spamc  ${RSPAMD_LOCAL_ADDR}  ${RSPAMD_PORT_PROXY}  ${MESSAGE}
  Should Contain  ${result}  SPAMD/1.1 0 EX_OK

RSPAMC Legacy Protocol
  ${result} =  Rspamc  ${RSPAMD_LOCAL_ADDR}  ${RSPAMD_PORT_PROXY}  ${MESSAGE}
  Should Contain  ${result}  RSPAMD/1.3 0 EX_OK

*** Keywords ***
Proxy Setup
  # Run slave & copy variables
  Set Suite Variable  ${CONFIG}  ${RSPAMD_TESTDIR}/configs/lua_test.conf
  Rspamd Setup
  Set Suite Variable  ${SLAVE_PID}  ${RSPAMD_PID}
  Set Suite Variable  ${SLAVE_TMPDIR}  ${RSPAMD_TMPDIR}

  # Run proxy & copy variables
  Set Suite Variable  ${CONFIG}  ${RSPAMD_TESTDIR}/configs/proxy.conf
  Rspamd Setup
  Set Suite Variable  ${PROXY_PID}  ${RSPAMD_PID}
  Set Suite Variable  ${PROXY_TMPDIR}  ${RSPAMD_TMPDIR}

Proxy Teardown
  # Restore variables & run normal teardown
  Set Suite Variable  ${RSPAMD_PID}  ${PROXY_PID}
  Set Suite Variable  ${RSPAMD_TMPDIR}  ${PROXY_TMPDIR}
  Rspamd Teardown
  # Do it again for slave
  Set Suite Variable  ${RSPAMD_PID}  ${SLAVE_PID}
  Set Suite Variable  ${RSPAMD_TMPDIR}  ${SLAVE_TMPDIR}
  Rspamd Teardown
