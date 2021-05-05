*** Settings ***
Suite Setup     Rspamd Setup
Suite Teardown  Rspamd Teardown
Library         ${RSPAMD_TESTDIR}/lib/rspamd.py
Resource        ${RSPAMD_TESTDIR}/lib/rspamd.robot
Variables       ${RSPAMD_TESTDIR}/lib/vars.py

*** Variables ***
${CONFIG}             ${RSPAMD_TESTDIR}/configs/composites.conf
${MESSAGE}            ${RSPAMD_TESTDIR}/messages/spam_message.eml
${RSPAMD_LUA_SCRIPT}  ${RSPAMD_TESTDIR}/lua/composites.lua
${RSPAMD_SCOPE}       Suite

*** Test Cases ***
Composites - All in One
  Scan File  ${MESSAGE}
  Expect Symbols With Scores  EXPRESSIONS=5
  ...  EXPRESSIONS_B=0
  ...  POLICY_REMOVE_WEIGHT=5
  ...  POLICY_REMOVE_WEIGHT_B=0
  ...  POLICY_FORCE_REMOVE=5.00
  ...  POLICY_FORCE_REMOVE_A=1.00
  ...  POLICY_LEAVE=5.00
  ...  POLICY_LEAVE_B=1.00
  ...  DEFAULT_POLICY_REMOVE_WEIGHT=5.00
  ...  DEFAULT_POLICY_REMOVE_WEIGHT_A=0.00
  ...  DEFAULT_POLICY_REMOVE_WEIGHT_B=0.00
  ...  DEFAULT_POLICY_REMOVE_SYMBOL=5.00
  ...  DEFAULT_POLICY_LEAVE=5.00
  ...  DEFAULT_POLICY_LEAVE_A=1.00
  ...  DEFAULT_POLICY_LEAVE_B=1.00
  ...  SYMBOL_GROUPS=5.00
  ...  POSITIVE_A=-1.00
  ...  ANY_A=-1.00
  ...  NEGATIVE_B=1.00
  Do Not Expect Symbols  DEFAULT_POLICY_REMOVE_SYMBOL_A
  ...  DEFAULT_POLICY_REMOVE_SYMBOL_B
  ...  NEGATIVE_A
  ...  POLICY_REMOVE_WEIGHT_A
  ...  POLICY_FORCE_REMOVE_B
  ...  POLICY_LEAVE_A
  Expect Score  50
  Expect Required Score To Be Null

Composites - Opts Plain
  Scan File  ${MESSAGE}  opts=sym1
  Expect Symbol With Score  SYMOPTS1  5.00
  Do Not Expect Symbol  SYMOPTS2

Composites - Opts RE Miss one
  Scan File  ${MESSAGE}  opts=sym1,foo1
  Expect Symbol With Score  SYMOPTS1  5.00
  Do Not Expect Symbol  SYMOPTS2
  Do Not Expect Symbol  SYMOPTS3

Composites - Opts RE Miss both
  Scan File  ${MESSAGE}  opts=sym2
  Do Not Expect Symbol  SYMOPTS1
  Do Not Expect Symbol  SYMOPTS2
  Do Not Expect Symbol  SYMOPTS3

Composites - Opts RE Hit
  Scan File  ${MESSAGE}  opts=foo1,sym2
  Expect Symbol With Score  SYMOPTS2  6.00
  Do Not Expect Symbol  SYMOPTS1
  Do Not Expect Symbol  SYMOPTS3

Composites - Opts RE Hit 2
  Scan File  ${MESSAGE}  opts=sym2,foo/
  Expect Symbol With Score  SYMOPTS3  6.00
  Do Not Expect Symbol  SYMOPTS2
  Do Not Expect Symbol  SYMOPTS1

Composites - Opts RE Hit 3
  Scan File  ${MESSAGE}  opts=example.com->app.link
  Expect Symbol With Score  SYMOPTS4  6.00
  Do Not Expect Symbol  SYMOPTS2
  Do Not Expect Symbol  SYMOPTS1
