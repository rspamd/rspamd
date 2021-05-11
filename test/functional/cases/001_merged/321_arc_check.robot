*** Settings ***
Library         ${RSPAMD_TESTDIR}/lib/rspamd.py
Resource        ${RSPAMD_TESTDIR}/lib/rspamd.robot
Variables       ${RSPAMD_TESTDIR}/lib/vars.py

*** Variables ***
${SETTINGS_ARC}  {symbols_enabled = [ARC_CALLBACK]}

*** Test Cases ***
ARC ALLOW CHECK
  Scan File  ${RSPAMD_TESTDIR}/messages/arcallow.eml
  ...  Settings=${SETTINGS_ARC}
  Expect Symbol  ARC_ALLOW

ARC BAD CHECK
  Scan File  ${RSPAMD_TESTDIR}/messages/arcbad.eml
  ...  Settings=${SETTINGS_ARC}
  Expect Symbol  ARC_INVALID

