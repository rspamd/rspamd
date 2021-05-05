*** Settings ***
Suite Setup     Map Reload Setup
Suite Teardown  Map Reload Teardown
Library         ${RSPAMD_TESTDIR}/lib/rspamd.py
Resource        ${RSPAMD_TESTDIR}/lib/rspamd.robot
Variables       ${RSPAMD_TESTDIR}/lib/vars.py

*** Variables ***
${CONFIG}              ${RSPAMD_TESTDIR}/configs/lua_test.conf
${MAP_WATCH_INTERVAL}  0.5s
${MESSAGE}             ${RSPAMD_TESTDIR}/messages/spam_message.eml
${RSPAMD_SCOPE}        Suite
${RSPAMD_URL_TLD}      ${RSPAMD_TESTDIR}/../lua/unit/test_tld.dat

*** Test Cases ***
CHECK HIT AND MISS
  Scan File  ${MESSAGE}
  Expect Symbol With Score And Exact Options  MAP_SET_HIT_AND_MISS  1  example.com

WRITE NEW MAP
  ${TMP_FILE} =  Make Temporary File
  Copy File  ${RSPAMD_TESTDIR}/configs/maps/domains.list.2  ${TMP_FILE}
  Move File  ${TMP_FILE}  ${MAP_FILE}

CHECK HIT AND MISS AFTER RELOAD
  Sleep  1s  Wait for map reload
  Scan File  ${MESSAGE}
  Expect Symbol With Score And Exact Options  MAP_SET_HIT_AND_MISS  1  rspamd.com

*** Keywords ***
Map Reload Setup
  ${MAP1} =  Get File  ${RSPAMD_TESTDIR}/configs/maps/domains.list
  ${MAP_FILE} =  Make Temporary File
  ${RSPAMD_LUA_SCRIPT} =  Make Temporary File
  Set Suite Variable  ${RSPAMD_LUA_SCRIPT}
  Set Suite Variable  ${MAP_FILE}
  Set Suite Variable  ${MAP1}
  ${lua} =  Get File  ${RSPAMD_TESTDIR}/lua/mapreload.lua
  ${lua} =  Replace Variables  ${lua}
  Create File  ${RSPAMD_LUA_SCRIPT}  ${lua}
  Create File  ${MAP_FILE}  ${MAP1}
  Rspamd Setup

Map Reload Teardown
  Remove File  ${MAP_FILE}
  Remove File  ${RSPAMD_LUA_SCRIPT}
  Rspamd Teardown
