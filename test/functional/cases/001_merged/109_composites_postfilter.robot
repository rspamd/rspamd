*** Settings ***
Library         ${RSPAMD_TESTDIR}/lib/rspamd.py
Resource        ${RSPAMD_TESTDIR}/lib/rspamd.robot
Variables       ${RSPAMD_TESTDIR}/lib/vars.py

*** Variables ***
${MESSAGE}      ${RSPAMD_TESTDIR}/messages/spam_message.eml
${RSPAMD_LUA_SCRIPT}  ${RSPAMD_TESTDIR}/lua/composites_postfilter.lua

*** Test Cases ***
Composite With Postfilter And Filter
  [Documentation]  Test that composite with postfilter + filter symbols works correctly (issue #5674)
  Scan File  ${MESSAGE}
  Expect Symbol With Score  TEST_POSTFILTER_COMPOSITE  10.0
  Do Not Expect Symbol  TEST_FILTER_SYM
  Do Not Expect Symbol  TEST_POSTFILTER_SYM
