*** Settings ***
Suite Setup     Rspamd Redis Setup
Suite Teardown  Rspamd Redis Teardown
Library         ${RSPAMD_TESTDIR}/lib/rspamd.py
Resource        ${RSPAMD_TESTDIR}/lib/rspamd.robot
Variables       ${RSPAMD_TESTDIR}/lib/vars.py

*** Variables ***
${CONFIG}               ${RSPAMD_TESTDIR}/configs/settings_merge.conf
${MESSAGE}              ${RSPAMD_TESTDIR}/messages/spam_message.eml
${RSPAMD_LUA_SCRIPT}    ${RSPAMD_TESTDIR}/lua/settings_merge.lua
${REDIS_SCOPE}          Suite
${RSPAMD_SCOPE}         Suite
${RSPAMD_URL_TLD}       ${RSPAMD_TESTDIR}/../lua/unit/test_tld.dat

*** Test Cases ***
# Basic: no settings, all symbols fire
NO SETTINGS - ALL SYMBOLS
  Scan File  ${MESSAGE}
  Expect Symbol  MERGE_TEST_BASIC
  Expect Symbol  MERGE_HARD_DEP
  Expect Symbol  MERGE_WEAK_DEP
  Expect Symbol  MERGE_GROUP_SYM
  Expect Symbol  MERGE_GROUP_SYM2
  Expect Symbol  MERGE_PRE

# Settings-ID enables only specific symbols via precomputed bitsets
SETTINGS ID - ENABLE SUBSET
  Scan File  ${MESSAGE}  Settings-Id=merge_profile
  Expect Symbol  MERGE_TEST_BASIC
  Expect Symbol  MERGE_HARD_DEP
  Expect Symbol  MERGE_WEAK_DEP
  Do Not Expect Symbol  MERGE_GROUP_SYM
  Do Not Expect Symbol  MERGE_GROUP_SYM2

# Coexistence: Settings-ID controls symbol set, inline Settings overrides actions
COEXISTENCE - SETTINGS ID AND INLINE ACTIONS
  Scan File  ${MESSAGE}  Settings-Id=merge_profile  Settings={actions {reject = 999.0}}
  Expect Symbol  MERGE_TEST_BASIC
  Expect Symbol  MERGE_HARD_DEP
  Do Not Expect Symbol  MERGE_GROUP_SYM
  Expect Required Score  999

# Coexistence: Settings-ID controls symbols, inline Settings overrides scores
COEXISTENCE - SETTINGS ID AND INLINE SCORES
  Scan File  ${MESSAGE}  Settings-Id=merge_profile  Settings={MERGE_TEST_BASIC = 7.77}
  Expect Symbol With Score  MERGE_TEST_BASIC  7.77

# Inline Settings with symbols_enabled
INLINE SETTINGS - SYMBOLS ENABLED
  Scan File  ${MESSAGE}  Settings={symbols_enabled = ["MERGE_TEST_BASIC", "MERGE_GROUP_SYM"]}
  Expect Symbol  MERGE_TEST_BASIC
  Expect Symbol  MERGE_GROUP_SYM
  Do Not Expect Symbol  MERGE_WEAK_DEP
  Do Not Expect Symbol  MERGE_HARD_DEP
  Do Not Expect Symbol  MERGE_GROUP_SYM2

# Weak dependency: disable MERGE_TEST_BASIC, weak dependent MERGE_WEAK_DEP still runs
WEAK DEP - DISABLE DEP SYMBOL
  Scan File  ${MESSAGE}  Settings={symbols_disabled = ["MERGE_TEST_BASIC"]}
  Do Not Expect Symbol  MERGE_TEST_BASIC
  Expect Symbol  MERGE_WEAK_DEP

# Hard dependency: disable MERGE_TEST_BASIC, hard dependent MERGE_HARD_DEP cascade-disabled
HARD DEP - CASCADE DISABLE
  Scan File  ${MESSAGE}  Settings={symbols_disabled = ["MERGE_TEST_BASIC"]}
  Do Not Expect Symbol  MERGE_TEST_BASIC
  Do Not Expect Symbol  MERGE_HARD_DEP

# Prefilter deps: SETTINGS_APPLY depends on SETTINGS_CHECK, both run correctly
PREFILTER DEPS WORK
  Scan File  ${MESSAGE}  Settings={symbols_enabled = ["MERGE_PRE"]}
  Expect Symbol  MERGE_PRE
  Do Not Expect Symbol  MERGE_TEST_BASIC

# Settings-ID with inline settings providing group disable override
COEXISTENCE - GROUP SYMBOLS WITH INLINE
  Scan File  ${MESSAGE}  Settings-Id=merge_group_ctl  Settings={actions {reject = 500.0}}
  Expect Symbol  MERGE_GROUP_SYM
  Expect Symbol  MERGE_GROUP_SYM2
  Expect Required Score  500

# Two layers: static rule (RULE) + redis handler (PER_USER). Custom apply keys
# are an extension point read back through task:get_settings(), so the merge
# must not drop them.
MULTI LAYER - CUSTOM KEYS SURVIVE MERGE
  Redis SET  merge_user_settings  {"mode":"outbound","shared":"from_redis"}
  Scan File  ${MESSAGE}  IP=8.8.8.8
  Expect Symbol With Option  MERGE_CUSTOM_KEYS  tenant=acme
  Expect Symbol With Option  MERGE_CUSTOM_KEYS  mode=outbound

# Same key in both layers: the higher layer (PER_USER) wins
MULTI LAYER - HIGHER LAYER WINS ON CONFLICT
  Redis SET  merge_user_settings  {"mode":"outbound","shared":"from_redis"}
  Scan File  ${MESSAGE}  IP=8.8.8.8
  Expect Symbol With Option  MERGE_CUSTOM_KEYS  shared=from_redis
  Do Not Expect Symbol With Option  MERGE_CUSTOM_KEYS  shared=from_rule

# `actions { greylist = null }` disables the action after a merge, exactly as
# it does on the single-layer path
MULTI LAYER - NULL ACTION STILL DISABLES GREYLIST
  Redis SET  merge_user_settings  {"mode":"outbound","shared":"from_redis"}
  Scan File  ${MESSAGE}  IP=8.8.8.8
  Expect Action  no action

# Single-layer baseline for the same disable
SINGLE LAYER - NULL ACTION DISABLES GREYLIST
  Scan File  ${MESSAGE}  IP=8.8.8.9
  Expect Symbol With Option  MERGE_CUSTOM_KEYS  tenant=solo
  Expect Action  no action

# Without any settings the greylist threshold is in force
NO SETTINGS - GREYLIST ACTION FIRES
  Scan File  ${MESSAGE}
  Expect Action  greylist

# A brand new custom action declared in one layer must be created after the
# merge, exactly as it is on the single-layer path
MULTI LAYER - CUSTOM ACTION IS CREATED
  Redis SET  merge_user_settings  {"mode":"outbound","shared":"from_redis"}
  Scan File  ${MESSAGE}  IP=8.8.8.10
  Expect Symbol With Option  MERGE_CUSTOM_KEYS  tenant=custom
  Expect Action  my_custom_action
