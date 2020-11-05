*** Settings ***
Suite Setup     Generic Setup
Suite Teardown  Simple Teardown
Library         ${TESTDIR}/lib/rspamd.py
Resource        ${TESTDIR}/lib/rspamd.robot
Variables       ${TESTDIR}/lib/vars.py

*** Variables ***
${CONFIG}       ${TESTDIR}/configs/composites.conf
${LUA_SCRIPT}   ${TESTDIR}/lua/composites.lua
${MESSAGE}      ${TESTDIR}/messages/spam_message.eml
${RSPAMD_SCOPE}  Suite

*** Test Cases ***
Composites - All in One
  Scan File  ${MESSAGE}
  Expect Symbol With Score  EXPRESSIONS  5
  Expect Symbol With Score  EXPRESSIONS_B  0
  Expect Symbol With Score  POLICY_REMOVE_WEIGHT  5
  Expect Symbol With Score  POLICY_REMOVE_WEIGHT_B  0
  Do Not Expect Symbol  POLICY_REMOVE_WEIGHT_A
  Expect Symbol With Score  POLICY_FORCE_REMOVE  5.00
  Expect Symbol With Score  POLICY_FORCE_REMOVE_A  1.00
  Do Not Expect Symbol  POLICY_FORCE_REMOVE_B
  Expect Symbol With Score  POLICY_LEAVE  5.00
  Do Not Expect Symbol  POLICY_LEAVE_A
  Expect Symbol With Score  POLICY_LEAVE_B  1.00
  Expect Symbol With Score  DEFAULT_POLICY_REMOVE_WEIGHT  5.00
  Expect Symbol With Score  DEFAULT_POLICY_REMOVE_WEIGHT_A  0.00
  Expect Symbol With Score  DEFAULT_POLICY_REMOVE_WEIGHT_B  0.00
  Expect Symbol With Score  DEFAULT_POLICY_REMOVE_SYMBOL  5.00
  Do Not Expect Symbol  DEFAULT_POLICY_REMOVE_SYMBOL_A
  Do Not Expect Symbol  DEFAULT_POLICY_REMOVE_SYMBOL_B
  Expect Symbol With Score  DEFAULT_POLICY_LEAVE  5.00
  Expect Symbol With Score  DEFAULT_POLICY_LEAVE_A  1.00
  Expect Symbol With Score  DEFAULT_POLICY_LEAVE_B  1.00
  Expect Symbol With Score  SYMBOL_GROUPS  5.00
  Expect Symbol With Score  POSITIVE_A  -1.00
  Expect Symbol With Score  ANY_A  -1.00
  Expect Symbol With Score  NEGATIVE_B  1.00
  Do Not Expect Symbol  NEGATIVE_A
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
  Scan File  ${MESSAGE}  opts=foo/,sym2
  Expect Symbol With Score  SYMOPTS3  6.00
  Do Not Expect Symbol  SYMOPTS2
  Do Not Expect Symbol  SYMOPTS1

Composites - Opts RE Hit 3
  Scan File  ${MESSAGE}  opts=example.com->app.link
  Expect Symbol With Score  SYMOPTS4  6.00
  Do Not Expect Symbol  SYMOPTS2
  Do Not Expect Symbol  SYMOPTS1