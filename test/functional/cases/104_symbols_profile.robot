*** Settings ***
Suite Setup     Rspamd Setup
Suite Teardown  Rspamd Teardown
Library         ${RSPAMD_TESTDIR}/lib/rspamd.py
Resource        ${RSPAMD_TESTDIR}/lib/rspamd.robot
Variables       ${RSPAMD_TESTDIR}/lib/vars.py

*** Variables ***
${CONFIG}              ${RSPAMD_TESTDIR}/configs/lua_test.conf
${MESSAGE}             ${RSPAMD_TESTDIR}/messages/spam_message.eml
${RSPAMD_LUA_SCRIPT}   ${RSPAMD_TESTDIR}/lua/symbols_profile.lua
${RSPAMD_SCOPE}        Suite
${RSPAMD_URL_TLD}      ${RSPAMD_TESTDIR}/../lua/unit/test_tld.dat

*** Keywords ***
Check Selected Profile
  Expect Symbol  PROF_SYNC
  Expect Symbol  PROF_VIRT
  Expect Symbol  PROF_OTHER
  Expect Symbol With Option  PROF_REPORT  sync_ok
  Expect Symbol With Option  PROF_REPORT  async_ok
  Expect Symbol With Option  PROF_REPORT  virt_absent
  Expect Symbol With Option  PROF_REPORT  other_absent
  Expect Symbol With Option  PROF_REPORT  cond_absent
  Expect Symbol With Option  PROF_REPORT  self_absent
  Expect Symbol With Option  PROF_REPORT  arrays_equal_length
  Expect Symbol With Option  PROF_REPORT  all_superset
  Expect Symbol With Option  PROF_REPORT  all_self_absent
  Expect Symbol With Option  PROF_REPORT  min_time_hit
  Expect Symbol With Option  PROF_REPORT  min_time_miss
  Expect Symbol With Option  PROF_REPORT  bad_opts_error

Check Reply Profile
  Dictionary Should Contain Key  ${SCAN_RESULT}  profile
  ${profile} =  Set Variable  ${SCAN_RESULT}[profile]
  FOR  ${key}  IN  PROF_SYNC  PROF_CB  PROF_OTHER
    Dictionary Should Contain Key  ${profile}  ${key}
    ${value} =  Evaluate  float($profile['${key}'])
    Should Be True  ${value} >= 0
  END

*** Test Cases ***
Selected Symbols Are Timed On Every Scan
  Scan File  ${MESSAGE}
  Check Selected Profile
  Dictionary Should Not Contain Key  ${SCAN_RESULT}  profile

Profile Flag Returns All Items In The Reply
  FOR  ${i}  IN RANGE  3
    Scan File  ${MESSAGE}  Flags=profile
    Check Reply Profile
    Expect Symbol With Option  PROF_REPORT  all_other_present
    Expect Symbol With Option  PROF_REPORT  self_absent
    Expect Symbol With Option  PROF_REPORT  all_self_absent
  END

Flag Is Per Task
  Scan File  ${MESSAGE}
  Check Selected Profile
  Dictionary Should Not Contain Key  ${SCAN_RESULT}  profile
  Expect Symbol With Option  PROF_REPORT  other_absent
  Expect Symbol With Option  PROF_REPORT  all_other_absent
