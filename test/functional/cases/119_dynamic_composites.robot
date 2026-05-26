*** Settings ***
Suite Setup     Dynamic Composites Setup
Suite Teardown  Dynamic Composites Teardown
Library         ${RSPAMD_TESTDIR}/lib/rspamd.py
Resource        ${RSPAMD_TESTDIR}/lib/rspamd.robot
Variables       ${RSPAMD_TESTDIR}/lib/vars.py

*** Variables ***
${CONFIG}                  ${RSPAMD_TESTDIR}/configs/dynamic_composites.conf
${RSPAMD_MAP_WATCH_INTERVAL}  0.5s
${MESSAGE}                 ${RSPAMD_TESTDIR}/messages/spam_message.eml
${RSPAMD_LUA_SCRIPT}       ${RSPAMD_TESTDIR}/lua/dynamic_composites.lua
${RSPAMD_SCOPE}            Suite
${RSPAMD_URL_TLD}          ${RSPAMD_TESTDIR}/../lua/unit/test_tld.dat

*** Test Cases ***
INITIAL MAP - DYN_ONE FIRES
  Scan File  ${MESSAGE}
  Expect Symbol With Score  DYN_ONE  2.5
  Expect Symbol With Score  DYN_TWO  3.5
  Expect Symbol With Score  STATIC_COMP  1.0
  Do Not Expect Symbol  DYN_THREE

RELOAD - UPDATED SCORES AND NEW NAME
  ${TMP_FILE} =  Make Temporary File
  Copy File  ${RSPAMD_TESTDIR}/configs/maps/dynamic_composites.map.2  ${TMP_FILE}
  Move File  ${TMP_FILE}  ${RSPAMD_DYN_COMP_MAP}
  Sleep  2s  Wait for map reload
  Scan File  ${MESSAGE}
  Expect Symbol With Score  DYN_ONE  7.0
  Expect Symbol With Score  DYN_THREE  4.0
  Expect Symbol With Score  STATIC_COMP  1.0
  Do Not Expect Symbol  DYN_TWO

RELOAD - REMOVED COMPOSITE BECOMES STUB
  ${TMP_FILE} =  Make Temporary File
  Copy File  ${RSPAMD_TESTDIR}/configs/maps/dynamic_composites.map.1  ${TMP_FILE}
  Move File  ${TMP_FILE}  ${RSPAMD_DYN_COMP_MAP}
  Sleep  2s  Wait for map reload
  Scan File  ${MESSAGE}
  Expect Symbol With Score  DYN_ONE  2.5
  Expect Symbol With Score  DYN_TWO  3.5
  Do Not Expect Symbol  DYN_THREE

*** Keywords ***
Dynamic Composites Setup
  ${RSPAMD_DYN_COMP_MAP} =  Make Temporary File
  Set Suite Variable  ${RSPAMD_DYN_COMP_MAP}
  Copy File  ${RSPAMD_TESTDIR}/configs/maps/dynamic_composites.map.1  ${RSPAMD_DYN_COMP_MAP}
  Rspamd Setup

Dynamic Composites Teardown
  Remove File  ${RSPAMD_DYN_COMP_MAP}
  Rspamd Teardown
