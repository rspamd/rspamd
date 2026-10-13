*** Settings ***
Suite Setup     Rspamd Setup
Suite Teardown  Rspamd Teardown
Library         ${RSPAMD_TESTDIR}/lib/rspamd.py
Resource        ${RSPAMD_TESTDIR}/lib/rspamd.robot
Variables       ${RSPAMD_TESTDIR}/lib/vars.py

*** Variables ***
${CONFIG}          ${RSPAMD_TESTDIR}/configs/force_actions.conf
${MESSAGE}         ${RSPAMD_TESTDIR}/messages/url7.eml
${RSPAMD_SCOPE}    Suite
${RSPAMD_URL_TLD}  ${RSPAMD_TESTDIR}/../lua/unit/test_tld.dat

*** Test Cases ***
FORCE ACTIONS from reject to add header
  Scan File  ${MESSAGE}  Settings-Id=id_reject
  Expect Action  add header
  Expect Symbol  FORCE_ACTION_FORCE_REJECT_TO_ADD_HEADER

FORCE ACTIONS from reject to no action
  Scan File  ${MESSAGE}  Settings-Id=id_reject_no_action
  Expect Action  no action
  Expect Symbol  FORCE_ACTION_FORCE_REJECT_TO_NO_ACTION

FORCE ACTIONS from no action to reject
  Scan File  ${MESSAGE}  Settings-Id=id_no_action
  Expect Action  reject
  Expect Symbol  FORCE_ACTION_FORCE_NO_ACTION_TO_REJECT

FORCE ACTIONS from no action to add header
  Scan File  ${MESSAGE}  Settings-Id=id_no_action_to_add_header
  Expect Action  add header
  Expect Symbol  FORCE_ACTION_FORCE_NO_ACTION_TO_ADD_HEADER

FORCE ACTIONS from add header to no action
  Scan File  ${MESSAGE}  Settings-Id=id_add_header
  Expect Action  no action
  Expect Symbol  FORCE_ACTION_FORCE_ADD_HEADER_TO_NO_ACTION

FORCE ACTIONS from add header to reject
  Scan File  ${MESSAGE}  Settings-Id=id_add_header_to_reject
  Expect Action  reject
  Expect Symbol  FORCE_ACTION_FORCE_ADD_HEADER_TO_REJECT

FORCE ACTIONS with composite in expression
  [Documentation]  A composite is only resolved after the filter stage, so the
  ...  rule has to be registered as a postfilter to observe it
  Scan File  ${MESSAGE}  Settings-Id=id_composite
  Expect Action  reject
  Expect Symbol  FORCE_ACTION_FORCE_COMPOSITE_TO_REJECT

FORCE ACTIONS higher priority wins when registered first
  Scan File  ${MESSAGE}  Settings-Id=id_priority_add_header_wins
  Expect Action  add header
  Expect Symbol  FORCE_ACTION_FORCE_PRIO_A_ADD_HEADER
  Expect Symbol  FORCE_ACTION_FORCE_PRIO_A_REJECT

FORCE ACTIONS higher priority wins when registered last
  [Documentation]  Same as above with the priorities swapped, so that only the
  ...  priority and not the registration order can decide the winner
  Scan File  ${MESSAGE}  Settings-Id=id_priority_reject_wins
  Expect Action  reject
  Expect Symbol  FORCE_ACTION_FORCE_PRIO_B_ADD_HEADER
  Expect Symbol  FORCE_ACTION_FORCE_PRIO_B_REJECT

FORCE ACTIONS numeric priority on main stage
  Scan File  ${MESSAGE}  Settings-Id=id_priority_numeric
  Expect Action  reject
  Expect Symbol  FORCE_ACTION_FORCE_PRIO_C_ADD_HEADER
  Expect Symbol  FORCE_ACTION_FORCE_PRIO_C_REJECT

FORCE ACTIONS same action priorities survive a competing action
  [Documentation]  The score already selects reject, so a critical reject rule
  ...  must still record its passthrough result or a later normal rule wins
  Scan File  ${MESSAGE}  Settings-Id=id_priority_same_action
  Expect Action  reject
  Expect Symbol  FORCE_ACTION_FORCE_PRIO_D_A_LOW_REJECT
  Expect Symbol  FORCE_ACTION_FORCE_PRIO_D_B_CRITICAL_REJECT
  Expect Symbol  FORCE_ACTION_FORCE_PRIO_D_C_NORMAL_ADD_HEADER

FORCE ACTIONS default same action priority beats a low priority competitor
  [Documentation]  An implicit normal-priority reject must record its result
  ...  even when the score already selects reject
  Scan File  ${MESSAGE}  Settings-Id=id_priority_same_action_default
  Expect Action  reject
  Expect Symbol  FORCE_ACTION_FORCE_PRIO_E_A_DEFAULT_REJECT
  Expect Symbol  FORCE_ACTION_FORCE_PRIO_E_B_LOW_ADD_HEADER

FORCE ACTIONS same action result does not stop the scan
  [Documentation]  The rule has no process_all, yet the composite must still
  ...  be evaluated because the action was already selected by the score
  Scan File  ${MESSAGE}  Settings-Id=id_priority_same_action_continue
  Expect Action  reject
  Expect Symbol  FORCE_ACTION_FORCE_PRIO_F_REJECT
  Expect Symbol  FA_PRIO6_WITNESS

FORCE ACTIONS main stage rule outranks later postfilter rule
  [Documentation]  The postfilter rule runs last but has the lower priority, so
  ...  it must not override the main stage result
  Scan File  ${MESSAGE}  Settings-Id=id_priority_mixed_main_wins
  Expect Action  add header
  Expect Symbol  FORCE_ACTION_FORCE_MIX_MAIN_WINS_ADD_HEADER
  Expect Symbol  FORCE_ACTION_FORCE_MIX_MAIN_WINS_REJECT

FORCE ACTIONS postfilter rule outranks earlier main stage rule
  Scan File  ${MESSAGE}  Settings-Id=id_priority_mixed_post_wins
  Expect Action  reject
  Expect Symbol  FORCE_ACTION_FORCE_MIX_POST_WINS_ADD_HEADER
  Expect Symbol  FORCE_ACTION_FORCE_MIX_POST_WINS_REJECT

FORCE ACTIONS priority validation
  ${log} =  Get File  ${RSPAMD_TMPDIR}/rspamd.log  encoding_errors=ignore
  Should Contain  ${log}  priority -10 is out of the allowed range [0..3], adjusted to 0
  Should Contain  ${log}  priority 10 is out of the allowed range [0..3], adjusted to 3
  Should Contain  ${log}  unknown priority name "invalid"
  Should Contain  ${log}  priority 1.5 is not an integer, adjusted to 1
  Should Contain  ${log}  priority is NaN; ignored
  Should Contain  ${log}  `least` is set, so `priority` cannot outrank a non-least rule
  Scan File  ${MESSAGE}  Settings-Id=id_priority_validation
  Expect Action  reject
  Expect Symbol  FORCE_ACTION_FORCE_PRIO_RANGE_ADD_HEADER
  Expect Symbol  FORCE_ACTION_FORCE_PRIO_RANGE_REJECT
