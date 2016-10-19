*** Settings ***
Suite Setup     Map Reload Setup
Suite Teardown  Map Reload Teardown
Library         ${TESTDIR}/lib/rspamd.py
Resource        ${TESTDIR}/lib/rspamd.robot
Variables       ${TESTDIR}/lib/vars.py

*** Variables ***
${CONFIG}       ${TESTDIR}/configs/lua_test.conf
${MAP_WATCH_INTERVAL}  0.5s
${MESSAGE}      ${TESTDIR}/messages/spam_message.eml
${RSPAMD_SCOPE}  Suite
${URL_TLD}      ${TESTDIR}/../lua/unit/test_tld.dat

*** Test Cases ***
CHECK HIT AND MISS
  ${result} =  Scan Message With Rspamc  ${MESSAGE}
  Check Rspamc  ${result}  MAP_SET_HIT_AND_MISS (1.00)[example.com]

WRITE NEW MAP
  Sleep  1s  Wait for new time
  Create File  ${MAP_FILE}  ${MAP2}

CHECK HIT AND MISS AFTER RELOAD
  Sleep  1s  Wait for map reload
  ${result} =  Scan Message With Rspamc  ${MESSAGE}
  Check Rspamc  ${result}  MAP_SET_HIT_AND_MISS (1.00)[rspamd.com]

*** Keywords ***
Map Reload Setup
  ${MAP1} =  Get File  ${TESTDIR}/configs/maps/domains.list
  ${MAP2} =  Get File  ${TESTDIR}/configs/maps/domains.list.2
  ${MAP_FILE} =  Make Temporary File
  ${LUA_SCRIPT} =  Make Temporary File
  Set Suite Variable  ${LUA_SCRIPT}
  Set Suite Variable  ${MAP_FILE}
  Set Suite Variable  ${MAP1}
  Set Suite Variable  ${MAP2}
  ${lua} =  Get File  ${TESTDIR}/lua/mapreload.lua
  ${lua} =  Replace Variables  ${lua}
  Create File  ${LUA_SCRIPT}  ${lua}
  Create File  ${MAP_FILE}  ${MAP1}
  Generic Setup

Map Reload Teardown
  Remove File  ${MAP_FILE}
  Remove File  ${LUA_SCRIPT}
  Normal Teardown
