*** Settings ***
Suite Setup     Rspamd Setup
Suite Teardown  Rspamd Teardown
Library         ${RSPAMD_TESTDIR}/lib/rspamd.py
Resource        ${RSPAMD_TESTDIR}/lib/rspamd.robot
Variables       ${RSPAMD_TESTDIR}/lib/vars.py

*** Variables ***
${CONFIG}              ${RSPAMD_TESTDIR}/configs/lua_test.conf
${MESSAGE}             ${RSPAMD_TESTDIR}/messages/spam_message.eml
${RSPAMD_LUA_SCRIPT}   ${RSPAMD_TESTDIR}/lua/symcache_order.lua
${RSPAMD_SCOPE}        Suite
${RSPAMD_URL_TLD}      ${RSPAMD_TESTDIR}/../lua/unit/test_tld.dat

*** Test Cases ***
Prefilter Levels And Hoisted Filters
  Scan File  ${MESSAGE}
  # The top level prefilter finished before the medium ones started
  Expect Symbol  ORD_PRE_TOP
  Expect Symbol  ORD_PRE_MED_A
  # The filters needed by ORD_PRE_MED_B ran at the prefilter stage, before it
  Expect Symbol With Option  ORD_FILTER_DEP  before_pre
  Expect Symbol  ORD_FILTER_DEP2
  Expect Symbol  ORD_PRE_MED_B
  # The lower level prefilter saw the whole medium level done
  Expect Symbol  ORD_PRE_LOW
  # A plain filter saw all prefilters and the hoisted filters done
  Expect Symbol  ORD_FILTER_PLAIN
  Expect Symbol  ORD_FILTER_IGNORE
  Expect Symbol  ORD_FILTER_AFTER
  Do Not Expect Symbol  ORD_FILTER_BIG
  # Postfilters: lower priority first, dependencies satisfied
  Expect Symbol  ORD_POST_LOW
  Expect Symbol  ORD_POST_HIGH
  Expect Symbol  ORD_POST_WEAK
  Expect Symbol  ORD_POST_HARD

Passthrough Stops Filters But Not Hoisted Or Exempt Ones
  Scan File  ${MESSAGE}  X-Passthrough=yes
  Expect Action  soft reject
  Expect Symbol  ORD_PRE_TOP
  Expect Symbol  ORD_PRE_MED_A
  # Hoisted filters ran at the prefilter stage, before the pre-result was set
  Expect Symbol With Option  ORD_FILTER_DEP  before_pre
  Expect Symbol  ORD_FILTER_DEP2
  Expect Symbol  ORD_PRE_MED_B
  Expect Symbol  ORD_PRE_LOW
  # A pre-result from a prefilter skips the filters stage as a whole
  Do Not Expect Symbol  ORD_FILTER_PLAIN
  Do Not Expect Symbol  ORD_FILTER_AFTER
  Do Not Expect Symbol  ORD_FILTER_IGNORE
  Do Not Expect Symbol  ORD_POST_LOW
  Do Not Expect Symbol  ORD_POST_HIGH

Score Limit Skips Dependents And Cascades To Hard Dependencies
  Scan File  ${MESSAGE}  X-Limit=yes
  Expect Action  reject
  Expect Symbol  ORD_FILTER_BIG
  # Not started after the limit has been reached, so its dependents see it as skipped
  Do Not Expect Symbol  ORD_FILTER_AFTER
  # The exempt filter still runs
  Expect Symbol  ORD_FILTER_IGNORE
  Expect Symbol  ORD_POST_WEAK
  Do Not Expect Symbol  ORD_POST_HARD
  Expect Symbol  ORD_POST_LOW
  Expect Symbol  ORD_POST_HIGH
