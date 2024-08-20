*** Settings ***
Suite Setup     Rspamd Setup
Suite Teardown  Rspamd Teardown
Library         ${RSPAMD_TESTDIR}/lib/grow_factor.py
Library         ${RSPAMD_TESTDIR}/lib/rspamd.py
Resource        ${RSPAMD_TESTDIR}/lib/rspamd.robot
Variables       ${RSPAMD_TESTDIR}/lib/vars.py

*** Variables ***
${CONFIG}               ${RSPAMD_TESTDIR}/configs/grow_factor.conf
${HAM_MESSAGE}          ${RSPAMD_TESTDIR}/messages/ham.eml
${RSPAMD_SCOPE}         Suite

*** Test Cases ***
CHECK BASIC
  Scan File  ${HAM_MESSAGE}
  ...  Settings={groups_enabled = [simple_tests]}
  Expect Required Score  15
  &{RESCORED_SYMBOLS} =  Apply Grow Factor  1.1  15
  Expect Symbols With Scores  &{RESCORED_SYMBOLS}

CHECK NOREJECT
  Scan File  ${HAM_MESSAGE}
  ...  Settings={actions { reject = null, "add header" = 15 }, groups_enabled = [simple_tests]}
  &{RESCORED_SYMBOLS} =  Apply Grow Factor  1.1  15
  Expect Symbols With Scores  &{RESCORED_SYMBOLS}
