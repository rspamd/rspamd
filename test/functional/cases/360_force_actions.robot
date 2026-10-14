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
  [Documentation]  A control for the next test: the winner also runs first
  Scan File  ${MESSAGE}  Settings-Id=id_priority_add_header_wins
  Expect Action  add header
  Expect Symbol  FORCE_ACTION_FORCE_PRIO_A_ADD_HEADER
  Expect Symbol  FORCE_ACTION_FORCE_PRIO_A_REJECT

FORCE ACTIONS higher priority wins when registered last
  [Documentation]  Same as above with the priorities swapped, so that only the
  ...  priority and not the registration order can decide the winner
  Scan File  ${MESSAGE}  Settings-Id=id_priority_reject_wins
  Expect Action  reject
  Expect Symbol With Option  FORCE_ACTION_FORCE_PRIO_B_ADD_HEADER  priority:0
  Expect Symbol With Option  FORCE_ACTION_FORCE_PRIO_B_REJECT  priority:2

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
  Dictionary Should Not Contain Key  ${SCAN_RESULT}[messages]  smtp_message

FORCE ACTIONS rule without priority outranks a low priority rule
  [Documentation]  A rule without priority is normal, so it wins over the low
  ...  rule even though the low rule runs first
  Scan File  ${MESSAGE}  Settings-Id=id_priority_default
  Expect Action  reject
  Expect Symbol  FORCE_ACTION_FORCE_PRIO_E_A_LOW_ADD_HEADER
  Expect Symbol With Exact Options  FORCE_ACTION_FORCE_PRIO_E_B_DEFAULT_REJECT  reject

FORCE ACTIONS same action result does not stop the scan
  [Documentation]  The rule has no process_all, yet the composite must still
  ...  be evaluated because the action was already selected by the score
  Scan File  ${MESSAGE}  Settings-Id=id_priority_same_action_continue
  Expect Action  reject
  Expect Symbol  FORCE_ACTION_FORCE_PRIO_F_REJECT
  Expect Symbol  FA_PRIO6_WITNESS

FORCE ACTIONS main stage rule outranks later postfilter rule
  [Documentation]  A control for the next test: the winner also runs first
  Scan File  ${MESSAGE}  Settings-Id=id_priority_mixed_main_wins
  Expect Action  add header
  Expect Symbol  FORCE_ACTION_FORCE_MIX_MAIN_WINS_ADD_HEADER
  Expect Symbol  FORCE_ACTION_FORCE_MIX_MAIN_WINS_REJECT

FORCE ACTIONS postfilter rule outranks earlier main stage rule
  [Documentation]  The low main stage rule has no process_all, yet it must not
  ...  suppress the composite of the postfilter rule
  Scan File  ${MESSAGE}  Settings-Id=id_priority_mixed_post_wins
  Expect Action  reject
  Expect Symbol  FORCE_ACTION_FORCE_MIX_POST_WINS_ADD_HEADER
  Expect Symbol  FORCE_ACTION_FORCE_MIX_POST_WINS_REJECT

FORCE ACTIONS priority validation
  ${log} =  Get File  ${RSPAMD_TMPDIR}/rspamd.log  encoding_errors=ignore
  Should Contain  ${log}  priority -10 is out of the allowed range [0..3], adjusted to 0
  # Each rule is validated once
  ${count} =  Get Count  ${log}  priority 10 is out of the allowed range [0..3], adjusted to 3
  Should Be Equal As Integers  ${count}  1
  Should Contain  ${log}  unknown priority name "invalid"
  Should Contain  ${log}  priority 1.5 is not an integer, adjusted to 1
  Should Contain  ${log}  priority is NaN; ignored
  Should Contain  ${log}  rule FORCE_PRIO_INFINITE: priority is not finite; ignored
  # UCL hands -inf over as a string, which only LuaJIT converts to a number
  Should Match Regexp  ${log}  rule FORCE_PRIO_NEG_INFINITE: (priority is not finite; ignored|unknown priority name "-inf")
  Should Contain  ${log}  `least` is set, so `priority` cannot outrank a non-least rule
  Scan File  ${MESSAGE}  Settings-Id=id_priority_validation
  Expect Action  reject
  Expect Symbol  FORCE_ACTION_FORCE_PRIO_RANGE_ADD_HEADER
  Expect Symbol  FORCE_ACTION_FORCE_PRIO_RANGE_REJECT
  Expect Symbol With Exact Options  FORCE_ACTION_FORCE_PRIO_NEG_ZERO  no action  priority:0

FORCE ACTIONS priority on another rule keeps the skip
  [Documentation]  The rule has no priority, so it skips its already selected
  ...  action and does not pin it against the later composite score
  Scan File  ${MESSAGE}  Settings-Id=id_priority_unrelated
  Expect Action  reject
  Do Not Expect Symbol  FORCE_ACTION_FORCE_UNRELATED_NO_ACTION
  Expect Symbol  FA_UNRELATED_LATE

FORCE ACTIONS low priority rule does not starve a higher one
  Scan File  ${MESSAGE}  Settings-Id=id_priority_no_starve
  Expect Action  no action
  Expect Symbol  FORCE_ACTION_FORCE_STARVE_A_LOW_REJECT
  Expect Symbol  FA_STARVE_COMPOSITE
  Expect Symbol  FORCE_ACTION_FORCE_STARVE_B_HIGH_NO_ACTION

FORCE ACTIONS composite rule runs before honor_action rules
  [Documentation]  The honor_action rule sorts first, yet it must see the
  ...  reject of the composite rule
  Scan File  ${MESSAGE}  Settings-Id=id_composite_before_honor
  Expect Action  reject
  Expect Symbol  FORCE_ACTION_FORCE_HONOR_B_COMPOSITE_REJECT
  Do Not Expect Symbol  FORCE_ACTION_FORCE_HONOR_A_ADD_HEADER

FORCE ACTIONS least result does not outrank by priority
  Scan File  ${MESSAGE}  Settings-Id=id_priority_least
  Expect Action  no action
  Expect Symbol  FORCE_ACTION_FORCE_LEAST_A_CRITICAL_REJECT
  Expect Symbol  FORCE_ACTION_FORCE_LEAST_B_LOW_NO_ACTION

FORCE ACTIONS higher priority same action keeps the reply
  Scan File  ${MESSAGE}  Settings-Id=id_priority_reply
  Expect Action  reject
  Expect Symbol  FORCE_ACTION_FORCE_REPLY_A_LOW_REJECT
  Expect Symbol With Option  FORCE_ACTION_FORCE_REPLY_B_HIGH_REJECT  priority:2
  Should Be Equal  ${SCAN_RESULT}[messages][smtp_message]  Rejected by the low rule

FORCE ACTIONS top priority rule still stops the scan
  [Documentation]  No rule outranks a critical one, so it keeps cutting the scan
  ...  short and the composite is never evaluated
  Scan File  ${MESSAGE}  Settings-Id=id_priority_top
  Expect Action  reject
  Expect Symbol  FORCE_ACTION_FORCE_TOP_CRITICAL_REJECT
  Do Not Expect Symbol  FA_TOP_WITNESS

FORCE ACTIONS reply of another action is not carried over
  Scan File  ${MESSAGE}  Settings-Id=id_priority_carry_other_action
  Expect Action  reject
  Expect Symbol  FORCE_ACTION_FORCE_CARRY_A_LEAST_ADD_HEADER
  Expect Symbol With Option  FORCE_ACTION_FORCE_CARRY_B_LOW_REJECT  priority:0
  Dictionary Should Not Contain Key  ${SCAN_RESULT}[messages]  smtp_message

FORCE ACTIONS rule without priority keeps the selected action
  [Documentation]  The score already selects reject, so the rule without
  ...  priority records nothing, yet the low rule matching later must not
  ...  override it
  Scan File  ${MESSAGE}  Settings-Id=id_priority_keep
  Expect Action  reject
  Expect Symbol With Exact Options  FORCE_ACTION_FORCE_KEEP_A_REJECT  reject
  Expect Symbol With Option  FORCE_ACTION_FORCE_KEEP_B_LOW_NO_ACTION  priority:0

FORCE ACTIONS honor_action rule does not record the selected action
  Scan File  ${MESSAGE}  Settings-Id=id_honor_no_pin
  Expect Action  no action
  Do Not Expect Symbol  FORCE_ACTION_FORCE_HONOR_PIN_NO_ACTION

FORCE ACTIONS least rule without priority stays below other least results
  Scan File  ${MESSAGE}  Settings-Id=id_least_unset
  Expect Action  reject
  Expect Symbol  FORCE_ACTION_FORCE_LEAST_UNSET_ADD_HEADER
  Expect Symbol  FA_LEAST_PROBE

FORCE ACTIONS higher priority custom action keeps the reply
  Scan File  ${MESSAGE}  Settings-Id=id_custom_reply
  Expect Action  fa_hold
  Expect Symbol  FORCE_ACTION_FORCE_CUSTOM_A_LOW_HOLD
  Expect Symbol With Option  FORCE_ACTION_FORCE_CUSTOM_B_HIGH_HOLD  priority:2
  Should Be Equal  ${SCAN_RESULT}[messages][smtp_message]  Held by the low rule

FORCE ACTIONS reply not for the SMTP client stays hidden
  Scan File  ${MESSAGE}  Settings-Id=id_note_reply
  Expect Action  reject
  Expect Symbol  FA_NOTE_PROBE
  Expect Symbol With Option  FORCE_ACTION_FORCE_NOTE_HIGH_REJECT  priority:2
  Dictionary Should Not Contain Key  ${SCAN_RESULT}[messages]  smtp_message

FORCE ACTIONS pre-result flags and action name
  [Documentation]  All flags are kept, and has_pre_result returns them along
  ...  with the name of the custom action
  Scan File  ${MESSAGE}  Settings-Id=id_pre_result_probe
  Expect Action  fa_hold
  Expect Symbol With Exact Options  FA_PRE_RESULT_PROBE  fa_hold  Internal note  fa_probe  least,no_smtp_message
  Dictionary Should Not Contain Key  ${SCAN_RESULT}[messages]  smtp_message

FORCE ACTIONS postfilter probe runs without a pre-result
  [Documentation]  A control for the next test
  Scan File  ${MESSAGE}  Settings-Id=id_stopped_probe
  Expect Symbol  FA_STOPPED_PROBE

FORCE ACTIONS composite rule result stops the later postfilters
  [Documentation]  Only the main stage rules get process_all implied: a
  ...  postfilter rule cannot starve another rule, so it still stops the
  ...  postfilters that do not ignore passthrough results, as on master
  Scan File  ${MESSAGE}  Settings-Id=id_composite_stops
  Expect Action  reject
  Expect Symbol  FORCE_ACTION_FORCE_COMPOSITE_TO_REJECT
  Do Not Expect Symbol  FA_STOPPED_PROBE

FORCE ACTIONS rule of the same rank overrides a kept action
  [Documentation]  The kept action is only recorded for a rule of a lower
  ...  rank: with equal ranks the later rule wins, as on master
  Scan File  ${MESSAGE}  Settings-Id=id_priority_tie
  Expect Action  no action
  Do Not Expect Symbol  FORCE_ACTION_FORCE_TIE_A_REJECT
  Expect Symbol  FORCE_ACTION_FORCE_TIE_B_NO_ACTION

FORCE ACTIONS lower rule of the kept action keeps its reply
  Scan File  ${MESSAGE}  Settings-Id=id_priority_keep_reply
  Expect Action  reject
  Do Not Expect Symbol  FORCE_ACTION_FORCE_KEEP_MSG_A_REJECT
  Expect Symbol With Option  FORCE_ACTION_FORCE_KEEP_MSG_B_LOW_REJECT  priority:0
  Should Be Equal  ${SCAN_RESULT}[messages][smtp_message]  Rejected by the low keeper

FORCE ACTIONS kept action does not stop the scan
  [Documentation]  Both rules run on the main stage: recording the kept action
  ...  must not suppress the composites
  Scan File  ${MESSAGE}  Settings-Id=id_priority_keep_scan
  Expect Action  reject
  Expect Symbol  FORCE_ACTION_FORCE_KEEP_SCAN_A_REJECT
  Expect Symbol With Option  FORCE_ACTION_FORCE_KEEP_SCAN_B_LOW_NO_ACTION  priority:0
  Expect Symbol  FA_KEEP_SCAN_WITNESS

FORCE ACTIONS least rule does not keep the selected action
  [Documentation]  A least rule without priority records at low, so it does
  ...  not outrank the later low least rule
  Scan File  ${MESSAGE}  Settings-Id=id_least_no_keep
  Expect Action  add header
  Do Not Expect Symbol  FORCE_ACTION_FORCE_LEAST_KEEP_A_NO_ACTION
  Expect Symbol  FORCE_ACTION_FORCE_LEAST_KEEP_B_LOW_ADD_HEADER

FORCE ACTIONS rule with a reply records the selected action
  [Documentation]  The reply is only sent with a result, so such a rule is not
  ...  skipped when the score already selects its action
  Scan File  ${MESSAGE}  Settings-Id=id_msg_same
  Expect Action  reject
  Expect Symbol  FORCE_ACTION_FORCE_MSG_SAME_REJECT
  Should Be Equal  ${SCAN_RESULT}[messages][smtp_message]  Rejected with a reason

FORCE ACTIONS kept action keeps the reply of another module
  [Documentation]  Recording the kept action outranks the reject of the probe,
  ...  so it has to keep its reply as a re-recorded action does
  Scan File  ${MESSAGE}  Settings-Id=id_priority_keep_other_reply
  Expect Action  reject
  Expect Symbol With Option  FORCE_ACTION_FORCE_KEEP_B_LOW_NO_ACTION  priority:0
  Should Be Equal  ${SCAN_RESULT}[messages][smtp_message]  Rejected by the probe

FORCE ACTIONS least rule raises a kept action
  [Documentation]  A least result only raises the action selected by the score,
  ...  as before: the kept action is not recorded for it
  Scan File  ${MESSAGE}  Settings-Id=id_least_over_kept
  Expect Action  reject
  Do Not Expect Symbol  FORCE_ACTION_FORCE_LEAST_OVER_A_ADD_HEADER
  Expect Symbol With Option  FORCE_ACTION_FORCE_LEAST_OVER_B_CRITICAL_REJECT  priority:3

FORCE ACTIONS kept action that is no longer selected is not recorded
  [Documentation]  The whitelist keeps no action, then the composite score
  ...  selects reject: the low reject rule must not bring the whitelist back
  Scan File  ${MESSAGE}  Settings-Id=id_priority_stale_keep
  Expect Action  reject
  Expect Symbol  FA_UNRELATED_LATE
  Do Not Expect Symbol  FORCE_ACTION_FORCE_UNRELATED_NO_ACTION
  Expect Symbol With Option  FORCE_ACTION_FORCE_CARRY_B_LOW_REJECT  priority:0

FORCE ACTIONS reply of the selected result is kept
  [Documentation]  A least result heads the list, yet the reply comes from the
  ...  result that selects the action
  Scan File  ${MESSAGE}  Settings-Id=id_selected_reply
  Expect Action  reject
  Expect Symbol  FA_LEAST_HEAD_PROBE
  Expect Symbol With Option  FORCE_ACTION_FORCE_SEL_B_HIGH_REJECT  priority:2
  Should Be Equal  ${SCAN_RESULT}[messages][smtp_message]  Rejected by the selected rule

FORCE ACTIONS require_action rules run by priority
  [Documentation]  The low rule sorts first, yet the high one sees the reject
  ...  before the low one changes it
  Scan File  ${MESSAGE}  Settings-Id=id_late_by_priority
  Expect Action  reject
  Expect Symbol  FORCE_ACTION_FORCE_LATE_A_ADD_HEADER
  Expect Symbol With Exact Options  FORCE_ACTION_FORCE_LATE_Z_HIGH_REJECT  reject  priority:2

FORCE ACTIONS composite rule acts before the medium postfilters
  Scan File  ${MESSAGE}  Settings-Id=id_composite_probe
  Expect Action  reject
  Expect Symbol With Exact Options  FA_ACTION_PROBE  reject

FORCE ACTIONS honor_action rule fires when its action is not selected
  [Documentation]  A control for the test that it does not record the
  ...  selected action
  Scan File  ${MESSAGE}  Settings-Id=id_honor_fires
  Expect Action  no action
  Expect Symbol With Option  FORCE_ACTION_FORCE_HONOR_PIN_NO_ACTION  priority:2

FORCE ACTIONS low least rule raises a kept action
  [Documentation]  The least rule is below the keeping rule, yet it does not
  ...  record the kept action: it only raises the action, as before
  Scan File  ${MESSAGE}  Settings-Id=id_least_low_over_kept
  Expect Action  add header
  Do Not Expect Symbol  FORCE_ACTION_FORCE_LEAST_LOW_A_NO_ACTION
  Expect Symbol With Option  FORCE_ACTION_FORCE_LEAST_LOW_B_ADD_HEADER  priority:0

FORCE ACTIONS stale kept action is replaced by a lower keeping rule
  Scan File  ${MESSAGE}  Settings-Id=id_stale_late
  Expect Action  add header
  Do Not Expect Symbol  FORCE_ACTION_FORCE_STALE_LATE_A_HIGH_NO_ACTION
  Expect Symbol With Exact Options  FORCE_ACTION_FORCE_STALE_LATE_C_ADD_HEADER  add header
  Expect Symbol With Option  FORCE_ACTION_FORCE_STALE_LATE_D_LOW_REJECT  priority:0

FORCE ACTIONS last keeping rule of the same rank is recorded
  Scan File  ${MESSAGE}  Settings-Id=id_eq_late
  Expect Action  reject
  Do Not Expect Symbol  FORCE_ACTION_FORCE_EQ_LATE_A_REJECT
  Expect Symbol With Exact Options  FORCE_ACTION_FORCE_EQ_LATE_B_NORMAL_REJECT  reject  priority:1
  Expect Symbol With Option  FORCE_ACTION_FORCE_EQ_LATE_C_LOW_ADD_HEADER  priority:0

FORCE ACTIONS require_action rule without priority runs before a low one
  Scan File  ${MESSAGE}  Settings-Id=id_late_unset_before_low
  Expect Action  no action
  Expect Symbol With Exact Options  FORCE_ACTION_FORCE_LATE2_B_NO_ACTION  no action
  Do Not Expect Symbol  FORCE_ACTION_FORCE_LATE2_A_LOW_ADD_HEADER

FORCE ACTIONS composite rules keep the name order
  [Documentation]  The low rule sorts first, so the high one keeps its reply
  Scan File  ${MESSAGE}  Settings-Id=id_composite_reply
  Expect Action  reject
  Expect Symbol  FORCE_ACTION_FORCE_COMP_REPLY_A_LOW_REJECT
  Expect Symbol With Option  FORCE_ACTION_FORCE_COMP_REPLY_B_HIGH_REJECT  priority:2
  Should Be Equal  ${SCAN_RESULT}[messages][smtp_message]  Rejected by the low composite rule

FORCE ACTIONS reply of a least result is not kept when the score decides
  [Documentation]  The least probe heads the list, yet the score selects
  ...  reject, so no reply is sent, with or without the low rule
  Scan File  ${MESSAGE}  Settings-Id=id_least_reply_score
  Expect Action  reject
  Expect Symbol  FA_LEAST_PROBE
  Expect Symbol With Option  FORCE_ACTION_FORCE_CARRY_B_LOW_REJECT  priority:0
  Dictionary Should Not Contain Key  ${SCAN_RESULT}[messages]  smtp_message

FORCE ACTIONS kept action does not take a reply not for the SMTP client
  [Documentation]  The probe rejects with an internal note: the kept reject
  ...  outranks it, so it must not send that note
  Scan File  ${MESSAGE}  Settings-Id=id_keep_note
  Expect Action  reject
  Expect Symbol  FA_NOTE_PROBE
  Expect Symbol With Exact Options  FORCE_ACTION_FORCE_KEEP_A_REJECT  reject
  Expect Symbol With Option  FORCE_ACTION_FORCE_KEEP_B_LOW_NO_ACTION  priority:0
  Dictionary Should Not Contain Key  ${SCAN_RESULT}[messages]  smtp_message
