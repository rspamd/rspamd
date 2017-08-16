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
Rspamc Client
  ${result} =  Run Rspamc  -h  ${LOCAL_ADDR}:${PORT_PROXY}  -p  ${MESSAGE}
  Custom Follow Rspamd Log  ${PROXY_TMPDIR}/rspamd.log  ${PROXY_LOGPOS}  PROXY_LOGPOS  Suite
  Custom Follow Rspamd Log  ${SLAVE_TMPDIR}/rspamd.log  ${SLAVE_LOGPOS}  SLAVE_LOGPOS  Suite
  Run Keyword If  ${result.rc} != 0  Log  ${result.stderr}
  Should Contain  ${result.stdout}  SIMPLE_TEST
  Should Be Equal As Integers  ${result.rc}  0

SPAMC
  ${result} =  Spamc  ${LOCAL_ADDR}  ${PORT_PROXY}  ${MESSAGE}
  Custom Follow Rspamd Log  ${PROXY_TMPDIR}/rspamd.log  ${PROXY_LOGPOS}  PROXY_LOGPOS  Suite
  Custom Follow Rspamd Log  ${SLAVE_TMPDIR}/rspamd.log  ${SLAVE_LOGPOS}  SLAVE_LOGPOS  Suite
  Should Contain  ${result}  SIMPLE_TEST

RSPAMC Legacy Protocol
  ${result} =  Rspamc  ${LOCAL_ADDR}  ${PORT_PROXY}  ${MESSAGE}
  Custom Follow Rspamd Log  ${PROXY_TMPDIR}/rspamd.log  ${PROXY_LOGPOS}  PROXY_LOGPOS  Suite
  Custom Follow Rspamd Log  ${SLAVE_TMPDIR}/rspamd.log  ${SLAVE_LOGPOS}  SLAVE_LOGPOS  Suite
  Should Contain  ${result}  SIMPLE_TEST

*** Keywords ***
Proxy Setup
  &{d} =  Run Rspamd  CONFIG=${TESTDIR}/configs/lua_test.conf
  Set Suite Variable  ${SLAVE_LOGPOS}  &{d}[RSPAMD_LOGPOS]
  Set Suite Variable  ${SLAVE_PID}  &{d}[RSPAMD_PID]
  Set Suite Variable  ${SLAVE_TMPDIR}  &{d}[TMPDIR]
  &{d} =  Run Rspamd  CONFIG=${TESTDIR}/configs/proxy.conf
  Set Suite Variable  ${PROXY_LOGPOS}  &{d}[RSPAMD_LOGPOS]
  Set Suite Variable  ${PROXY_PID}  &{d}[RSPAMD_PID]
  Set Suite Variable  ${PROXY_TMPDIR}  &{d}[TMPDIR]

Proxy Teardown
  Shutdown Process With Children  ${PROXY_PID}
  Shutdown Process With Children  ${SLAVE_PID}
  Cleanup Temporary Directory  ${PROXY_TMPDIR}
  Cleanup Temporary Directory  ${SLAVE_TMPDIR}
