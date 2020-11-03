*** Settings ***
Test Teardown   Normal Teardown
Library         ${TESTDIR}/lib/rspamd.py
Resource        ${TESTDIR}/lib/rspamd.robot
Variables       ${TESTDIR}/lib/vars.py

*** Variables ***
${CONFIG}       ${TESTDIR}/configs/lua_test.conf
${MAP_MAP}      ${TESTDIR}/configs/maps/map.list
${MESSAGE}      ${TESTDIR}/messages/spam_message.eml
${RADIX_MAP}    ${TESTDIR}/configs/maps/ip2.list
${REGEXP_MAP}   ${TESTDIR}/configs/maps/regexp.list
${RSPAMD_SCOPE}  Test
${URL_TLD}      ${TESTDIR}/../lua/unit/test_tld.dat

*** Test Cases ***
Flags
  [Setup]  Lua Setup  ${TESTDIR}/lua/flags.lua
  Scan File  ${MESSAGE}
  ${result} =  Run Rspamc  -h  ${LOCAL_ADDR}:${PORT_CONTROLLER}  stat
  Should Contain  ${result.stdout}  Messages scanned: 0

Dependencies
  [Setup]  Lua Setup  ${TESTDIR}/lua/deps.lua
  Scan File  ${MESSAGE}
  Expect Symbol  DEP10

Pre and Post Filters
  [Setup]  Lua Setup  ${TESTDIR}/lua/prepostfilters.lua
  Scan File  ${MESSAGE}
  Expect Symbol  TEST_PRE
  Expect Symbol  TEST_POST

Recipient Parsing Sanity
  [Setup]  Lua Setup  ${TESTDIR}/lua/recipients.lua
  Scan File  ${MESSAGE}  Rcpt=rcpt1@foobar,rcpt2@foobar,rcpt3@foobar,rcpt4@foobar
  Expect Symbol With Exact Options  TEST_RCPT  rcpt1@foobar,rcpt2@foobar,rcpt3@foobar,rcpt4@foobar

TLD parts
  [Setup]  TLD Setup  ${TESTDIR}/lua/tlds.lua
  Scan File  ${MESSAGE}
  Expect Symbol With Exact Options  TEST_TLD  no worry

Hashes
  [Setup]  Lua Setup  ${TESTDIR}/lua/hashes.lua
  Scan File  ${MESSAGE}
  Expect Symbol With Exact Options  TEST_HASHES  no worry

Maps Key Values
  [Setup]  Lua Replace Setup  ${TESTDIR}/lua/maps_kv.lua
  [Teardown]  Lua Replace Teardown
  Scan File  ${MESSAGE}
  Expect Symbol With Exact Options  RADIX_KV  no worry
  Expect Symbol With Exact Options  REGEXP_KV  no worry
  Expect Symbol With Exact Options  MAP_KV  no worry

Option Order
  [Setup]  Lua Replace Setup  ${TESTDIR}/lua/option_order.lua
  [Teardown]  Lua Replace Teardown
  Scan File  ${MESSAGE}
  Expect Symbol With Exact Options  OPTION_ORDER  one  two  three  4  5  a
  Expect Symbol With Exact Options  TBL_OPTION_ORDER  one  two  three  4  5  a

Rule conditions
  [Setup]  Lua Replace Setup  ${TESTDIR}/lua/conditions.lua
  [Teardown]  Lua Replace Teardown
  Scan File  ${MESSAGE}
  Expect Symbol With Option  ANY_A  hello3
  Expect Symbol With Option  ANY_A  hello1
  Expect Symbol With Option  ANY_A  hello2

*** Keywords ***
Lua Setup
  [Arguments]  ${LUA_SCRIPT}
  Set Test Variable  ${LUA_SCRIPT}
  Generic Setup

Lua Replace Setup
  [Arguments]  ${LUA_SCRIPT_UNESC}
  ${LUA_SCRIPT} =  Make Temporary File
  ${lua} =  Get File  ${LUA_SCRIPT_UNESC}
  ${lua} =  Replace Variables  ${lua}
  Create File  ${LUA_SCRIPT}  ${lua}
  Lua Setup  ${LUA_SCRIPT}

Lua Replace Teardown
  Remove File  ${LUA_SCRIPT}
  Normal Teardown

TLD Setup
  [Arguments]  ${LUA_SCRIPT}
  Set Test Variable  ${URL_TLD}  ${TESTDIR}/../../contrib/publicsuffix/effective_tld_names.dat
  Lua Setup  ${LUA_SCRIPT}
