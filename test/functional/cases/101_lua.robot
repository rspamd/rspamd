*** Settings ***
Test Teardown   Rspamd Teardown
Library         ${RSPAMD_TESTDIR}/lib/rspamd.py
Resource        ${RSPAMD_TESTDIR}/lib/rspamd.robot
Variables       ${RSPAMD_TESTDIR}/lib/vars.py

*** Variables ***
${CONFIG}          ${RSPAMD_TESTDIR}/configs/lua_test.conf
${MAP_MAP}         ${RSPAMD_TESTDIR}/configs/maps/map.list
${MESSAGE}         ${RSPAMD_TESTDIR}/messages/spam_message.eml
${RADIX_MAP}       ${RSPAMD_TESTDIR}/configs/maps/ip2.list
${REGEXP_MAP}      ${RSPAMD_TESTDIR}/configs/maps/regexp.list
${RSPAMD_SCOPE}    Test
${RSPAMD_URL_TLD}  ${RSPAMD_TESTDIR}/../lua/unit/test_tld.dat

*** Test Cases ***
Flags
  [Setup]  Lua Setup  ${RSPAMD_TESTDIR}/lua/flags.lua
  Scan File  ${MESSAGE}
  ${result} =  Run Rspamc  -h  ${RSPAMD_LOCAL_ADDR}:${RSPAMD_PORT_CONTROLLER}  stat
  Should Contain  ${result.stdout}  Messages scanned: 0

Dependencies
  [Setup]  Lua Setup  ${RSPAMD_TESTDIR}/lua/deps.lua
  Scan File  ${MESSAGE}
  Expect Symbol  DEP10

Pre and Post Filters
  [Setup]  Lua Setup  ${RSPAMD_TESTDIR}/lua/prepostfilters.lua
  Scan File  ${MESSAGE}
  Expect Symbol  TEST_PRE
  Expect Symbol  TEST_POST

Recipient Parsing Sanity
  [Setup]  Lua Setup  ${RSPAMD_TESTDIR}/lua/recipients.lua
  Scan File  ${MESSAGE}  Rcpt=rcpt1@foobar,rcpt2@foobar,rcpt3@foobar,rcpt4@foobar
  Expect Symbol With Exact Options  TEST_RCPT  rcpt1@foobar,rcpt2@foobar,rcpt3@foobar,rcpt4@foobar

TLD parts
  [Setup]  TLD Setup  ${RSPAMD_TESTDIR}/lua/tlds.lua
  Scan File  ${MESSAGE}
  Expect Symbol With Exact Options  TEST_TLD  no worry

Hashes
  [Setup]  Lua Setup  ${RSPAMD_TESTDIR}/lua/hashes.lua
  Scan File  ${MESSAGE}
  Expect Symbol With Exact Options  TEST_HASHES  no worry

Maps Key Values
  [Setup]  Lua Replace Setup  ${RSPAMD_TESTDIR}/lua/maps_kv.lua
  [Teardown]  Lua Replace Teardown
  Scan File  ${MESSAGE}
  Expect Symbol With Exact Options  RADIX_KV  no worry
  Expect Symbol With Exact Options  REGEXP_KV  no worry
  Expect Symbol With Exact Options  MAP_KV  no worry

Option Order
  [Setup]  Lua Replace Setup  ${RSPAMD_TESTDIR}/lua/option_order.lua
  [Teardown]  Lua Replace Teardown
  Scan File  ${MESSAGE}
  Expect Symbol With Exact Options  OPTION_ORDER  one  two  three  4  5  a
  Expect Symbol With Exact Options  TBL_OPTION_ORDER  one  two  three  4  5  a

Rule conditions
  [Setup]  Lua Replace Setup  ${RSPAMD_TESTDIR}/lua/conditions.lua
  [Teardown]  Lua Replace Teardown
  Scan File  ${MESSAGE}
  Expect Symbol With Option  ANY_A  hello3
  Expect Symbol With Option  ANY_A  hello1
  Expect Symbol With Option  ANY_A  hello2

*** Keywords ***
Lua Setup
  [Arguments]  ${RSPAMD_LUA_SCRIPT}
  Set Test Variable  ${RSPAMD_LUA_SCRIPT}
  Rspamd Setup

Lua Replace Setup
  [Arguments]  ${LUA_SCRIPT_UNESC}
  ${RSPAMD_LUA_SCRIPT} =  Make Temporary File
  ${lua} =  Get File  ${LUA_SCRIPT_UNESC}
  ${lua} =  Replace Variables  ${lua}
  Create File  ${RSPAMD_LUA_SCRIPT}  ${lua}
  Lua Setup  ${RSPAMD_LUA_SCRIPT}

Lua Replace Teardown
  Remove File  ${RSPAMD_LUA_SCRIPT}
  Rspamd Teardown

TLD Setup
  [Arguments]  ${RSPAMD_LUA_SCRIPT}
  Set Test Variable  ${RSPAMD_URL_TLD}  ${RSPAMD_TESTDIR}/../../contrib/publicsuffix/effective_tld_names.dat
  Lua Setup  ${RSPAMD_LUA_SCRIPT}
