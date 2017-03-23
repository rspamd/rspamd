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
  ${result} =  Scan Message With Rspamc  ${MESSAGE}
  Follow Rspamd Log
  ${result} =  Run Rspamc  -h  ${LOCAL_ADDR}:${PORT_CONTROLLER}  stat
  Should Contain  ${result.stdout}  Messages scanned: 0

Dependencies
  [Setup]  Lua Setup  ${TESTDIR}/lua/deps.lua
  ${result} =  Scan Message With Rspamc  ${MESSAGE}
  Check Rspamc  ${result}  DEP10

Pre and Post Filters
  [Setup]  Lua Setup  ${TESTDIR}/lua/prepostfilters.lua
  ${result} =  Scan Message With Rspamc  ${MESSAGE}
  Check Rspamc  ${result}  TEST_PRE
  Should Contain  ${result.stdout}  TEST_POST

Recipient Parsing Sanity
  [Setup]  Lua Setup  ${TESTDIR}/lua/recipients.lua
  ${result} =  Scan Message With Rspamc  ${MESSAGE}  -r  rcpt1@foobar  -r  rcpt2@foobar
  ...  -r  rcpt3@foobar  -r  rcpt4@foobar
  Check Rspamc  ${result}  TEST_RCPT (1.00)[rcpt1@foobar,rcpt2@foobar,rcpt3@foobar,rcpt4@foobar]

TLD parts
  [Setup]  TLD Setup  ${TESTDIR}/lua/tlds.lua
  ${result} =  Scan Message With Rspamc  ${MESSAGE}
  Check Rspamc  ${result}  TEST_TLD (1.00)[no worry]

Hashes
  [Setup]  Lua Setup  ${TESTDIR}/lua/hashes.lua
  ${result} =  Scan Message With Rspamc  ${MESSAGE}
  Check Rspamc  ${result}  TEST_HASHES (1.00)[no worry]

Maps Key Values
  [Setup]  Lua Replace Setup  ${TESTDIR}/lua/maps_kv.lua
  [Teardown]  Lua Replace Teardown
  ${result} =  Scan Message With Rspamc  ${MESSAGE}
  Check Rspamc  ${result}  RADIX_KV (1.00)[no worry]
  Should Contain  ${result.stdout}  REGEXP_KV (1.00)[no worry]
  Should Contain  ${result.stdout}  MAP_KV (1.00)[no worry]

Option Order
  [Setup]  Lua Replace Setup  ${TESTDIR}/lua/option_order.lua
  [Teardown]  Lua Replace Teardown
  ${result} =  Scan Message With Rspamc  ${MESSAGE}
  Check Rspamc  ${result}  OPTION_ORDER (1.00)[one, two, three, 4, 5, a]
  Should Contain  ${result.stdout}  TBL_OPTION_ORDER (1.00)[one, two, three, 4, 5, a]

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
