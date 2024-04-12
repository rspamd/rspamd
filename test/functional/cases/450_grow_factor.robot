*** Settings ***
Suite Setup     Rspamd Setup
Suite Teardown  Rspamd Teardown
Library         ${RSPAMD_TESTDIR}/lib/rspamd.py
Resource        ${RSPAMD_TESTDIR}/lib/rspamd.robot
Variables       ${RSPAMD_TESTDIR}/lib/vars.py

*** Variables ***
${CONFIG}               ${RSPAMD_TESTDIR}/configs/grow_factor.conf
${HAM_MESSAGE}          ${RSPAMD_TESTDIR}/messages/ham.eml
${RSPAMD_SCOPE}         Suite
&{RESCORED_SYMBOLS}
...  SIMPLE_TEST_001=0.013067
...  SIMPLE_TEST_002=14.374194
...  SIMPLE_TEST_003=6.533724
...  SIMPLE_TEST_004=13.067449
...  SIMPLE_TEST_005=0.013067
...  SIMPLE_TEST_006=0.130674
...  SIMPLE_TEST_007=0.143741
...  SIMPLE_TEST_008=0.156809
...  SIMPLE_TEST_009=0.169876
...  SIMPLE_TEST_010=0.182944
...  SIMPLE_TEST_011=-0.010000
...  SIMPLE_TEST_012=-0.100000
...  SIMPLE_TEST_013=-10.000000

*** Test Cases ***
CHECK BASIC
  Scan File  ${HAM_MESSAGE}
  ...  Settings={groups_enabled = [simple_tests]}
  Expect Required Score  15
  Expect Symbols With Scores  &{RESCORED_SYMBOLS}

CHECK NOREJECT
  Scan File  ${HAM_MESSAGE}
  ...  Settings={actions { reject = null, "add header" = 15 }, groups_enabled = [simple_tests]}
  Expect Symbols With Scores  &{RESCORED_SYMBOLS}
