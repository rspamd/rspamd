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
  Scan File  ${MESSAGE}
  Expect Symbol With Score And Exact Options  MAP_SET_HIT_AND_MISS  1  example.com

WRITE NEW MAP
  ${TMP_FILE} =  Make Temporary File
  Copy File  ${TESTDIR}/configs/maps/domains.list.2  ${TMP_FILE}
  Move File  ${TMP_FILE}  ${MAP_FILE}

CHECK HIT AND MISS AFTER RELOAD
  Sleep  1s  Wait for map reload
  Scan File  ${MESSAGE}
  Expect Symbol With Score And Exact Options  MAP_SET_HIT_AND_MISS  1  rspamd.com

*** Keywords ***
Map Reload Setup
  ${MAP1} =  Get File  ${TESTDIR}/configs/maps/domains.list
  ${MAP_FILE} =  Make Temporary File
  ${LUA_SCRIPT} =  Make Temporary File
  Set Suite Variable  ${LUA_SCRIPT}
  Set Suite Variable  ${MAP_FILE}
  Set Suite Variable  ${MAP1}
  ${lua} =  Get File  ${TESTDIR}/lua/mapreload.lua
  ${lua} =  Replace Variables  ${lua}
  Create File  ${LUA_SCRIPT}  ${lua}
  Create File  ${MAP_FILE}  ${MAP1}
  New Setup  LUA_SCRIPT=${LUA_SCRIPT}  URL_TLD=${URL_TLD}

Map Reload Teardown
  Remove File  ${MAP_FILE}
  Remove File  ${LUA_SCRIPT}
  Normal Teardown
