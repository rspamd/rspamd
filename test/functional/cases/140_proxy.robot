*** Settings ***
Suite Setup     Proxy Setup
Suite Teardown  Proxy Teardown
Library         ${TESTDIR}/lib/rspamd.py
Resource        ${TESTDIR}/lib/rspamd.robot
Variables       ${TESTDIR}/lib/vars.py

*** Variables ***
${LUA_SCRIPT}   ${TESTDIR}/lua/simple.lua
${MESSAGE}      ${TESTDIR}/messages/spam_message.eml
${URL_TLD}      ${TESTDIR}/../lua/unit/test_tld.dat

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
  &{d} =  Run Rspamd  CONFIG=${TESTDIR}/configs/lua_test.conf
  Set Suite Variable  ${SLAVE_PID}  ${d}[RSPAMD_PID]
  Set Suite Variable  ${SLAVE_TMPDIR}  ${d}[TMPDIR]
  &{d} =  Run Rspamd  CONFIG=${TESTDIR}/configs/proxy.conf
  Set Suite Variable  ${PROXY_PID}  ${d}[RSPAMD_PID]
  Set Suite Variable  ${PROXY_TMPDIR}  ${d}[TMPDIR]

Proxy Teardown
  Shutdown Process With Children  ${PROXY_PID}
  Shutdown Process With Children  ${SLAVE_PID}
  Cleanup Temporary Directory  ${PROXY_TMPDIR}
  Cleanup Temporary Directory  ${SLAVE_TMPDIR}
