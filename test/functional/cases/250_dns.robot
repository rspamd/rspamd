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
  Scan File  ${MESSAGE}  To-Resolve=example.com
  Expect Symbol With Exact Options  DNS_SYNC  93.184.216.34
  Expect Symbol With Exact Options  DNS  93.184.216.34

Faulty DNS request
  Scan File  ${MESSAGE}  To-Resolve=not-resolvable.com
  Expect Symbol With Exact Options  DNS_SYNC_ERROR  requested record is not found
  Expect Symbol With Exact Options  DNS_ERROR  requested record is not found

*** Keywords ***
Lua Setup
  [Arguments]  ${LUA_SCRIPT}
  Set Suite Variable  ${LUA_SCRIPT}
  Generic Setup

Http Setup
  New Setup  LUA_SCRIPT=${TESTDIR}/lua/dns.lua  URL_TLD=${URL_TLD}

Http Teardown
  Normal Teardown
