*** Settings ***
Library         ${RSPAMD_TESTDIR}/lib/rspamd.py
Resource        ${RSPAMD_TESTDIR}/lib/rspamd.robot
Variables       ${RSPAMD_TESTDIR}/lib/vars.py

*** Variables ***
${MESSAGE}      ${RSPAMD_TESTDIR}/messages/spam_message.eml
${RSPAMD_LUA_SCRIPT}  ${RSPAMD_TESTDIR}/lua/composites_postfilter.lua
${SETTINGS_COMPOSITES_POSTFILTER}  symbols_enabled [TEST_FILTER_SYM, TEST_POSTFILTER_COMPOSITE, TEST_POSTFILTER_SYM]
${SETTINGS_COMPOSITES_FIRSTPASS}  symbols_enabled [TEST_NOSTAT_FILTER_SYM, TEST_FIRSTPASS_COMPOSITE, TEST_OBSERVE_FIRSTPASS_COMPOSITE, TEST_COMPOSITE_SEEN_IN_POSTFILTER]

*** Test Cases ***
Composite With Postfilter And Filter
  [Documentation]  Test that composite with postfilter + filter symbols works correctly (issue #5674)
  Scan File  ${MESSAGE}
  ...  Settings=${SETTINGS_COMPOSITES_POSTFILTER}
  Expect Symbol With Score  TEST_POSTFILTER_COMPOSITE  10.0
  Do Not Expect Symbol  TEST_FILTER_SYM
  Do Not Expect Symbol  TEST_POSTFILTER_SYM

Composite Of Filter Symbol Is Visible In Postfilter
  [Documentation]  Composite depending only on a filter-stage (NOSTAT) symbol must be
  ...              evaluated in the first pass and thus visible to postfilters
  Scan File  ${MESSAGE}
  ...  Settings=${SETTINGS_COMPOSITES_FIRSTPASS}
  Expect Symbol  TEST_FIRSTPASS_COMPOSITE
  Expect Symbol  TEST_COMPOSITE_SEEN_IN_POSTFILTER
