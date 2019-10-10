*** Settings ***
Test Setup      Http Setup
Test Teardown   Http Teardown
Library         Process
Library         ${TESTDIR}/lib/rspamd.py
Resource        ${TESTDIR}/lib/rspamd.robot
Variables       ${TESTDIR}/lib/vars.py

*** Variables ***
${URL_TLD}      ${TESTDIR}/../lua/unit/test_tld.dat
${CONFIG}       ${TESTDIR}/configs/lua_test.conf
${MESSAGE}      ${TESTDIR}/messages/spam_message.eml
${RSPAMD_SCOPE}  Test

*** Test Cases ***
Simple DNS request
  ${result} =  Scan Message With Rspamc  --header=to-resolve:example.com  ${MESSAGE}
  Check Rspamc  ${result}  DNS_SYNC (0.00)[93.184.216.34]
  Check Rspamc  ${result}  DNS (0.00)[93.184.216.34]

Faulty DNS request
  ${result} =  Scan Message With Rspamc  --header=to-resolve:not-resolvable.com  ${MESSAGE}
  Check Rspamc  ${result}  DNS_SYNC_ERROR (0.00)[requested record is not found]
  Check Rspamc  ${result}  DNS_ERROR (0.00)[requested record is not found]

*** Keywords ***
Lua Setup
  [Arguments]  ${LUA_SCRIPT}
  Set Suite Variable  ${LUA_SCRIPT}
  Generic Setup

Http Setup
  Lua Setup  ${TESTDIR}/lua/dns.lua

Http Teardown
  Normal Teardown
