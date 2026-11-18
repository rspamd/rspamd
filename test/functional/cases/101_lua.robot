*** Settings ***
Test Teardown   Rspamd Teardown
Library         ${RSPAMD_TESTDIR}/lib/rspamd.py
Resource        ${RSPAMD_TESTDIR}/lib/rspamd.robot
Variables       ${RSPAMD_TESTDIR}/lib/vars.py

*** Variables ***
${CONFIG}          ${RSPAMD_TESTDIR}/configs/lua_test.conf
${MESSAGE}         ${RSPAMD_TESTDIR}/messages/spam_message.eml
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

Global Config Sections
  [Setup]  Lua Setup  ${RSPAMD_TESTDIR}/lua/config_sections.lua
  Scan File  ${MESSAGE}
  Expect Symbol With Exact Options  CFGSEC_SECTIONS  alpha=alpha  beta=beta  gamma=gamma
  Expect Symbol  CFGSEC_REGEXP

Event Base Timers
  [Setup]  Lua Setup  ${RSPAMD_TESTDIR}/lua/ev_base_timer.lua
  Scan File  ${MESSAGE}
  Expect Symbol With Exact Options  EV_BASE_TIMER  fired=3  nested=1

*** Keywords ***
Lua Setup
  [Arguments]  ${RSPAMD_LUA_SCRIPT}
  Set Test Variable  ${RSPAMD_LUA_SCRIPT}
  Rspamd Setup
