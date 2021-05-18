*** Settings ***
Library         ${RSPAMD_TESTDIR}/lib/rspamd.py
Resource        ${RSPAMD_TESTDIR}/lib/rspamd.robot
Variables       ${RSPAMD_TESTDIR}/lib/vars.py

*** Variables ***
${MESSAGE}            ${RSPAMD_TESTDIR}/messages/spam_message.eml
${SETTINGS_GREYLIST}  {symbols_enabled = [GREYLIST_CHECK, GREYLIST_SAVE], symbols = [FOUR_POINTS]}

*** Test Cases ***
GREYLIST NEW
  Scan File  ${MESSAGE}
  ...  Settings=${SETTINGS_GREYLIST}
  Expect Symbol With Option  GREYLIST  greylisted

GREYLIST EARLY
  Scan File  ${MESSAGE}
  ...  Settings=${SETTINGS_GREYLIST}
  Expect Symbol With Option  GREYLIST  greylisted

GREYLIST PASS
  Sleep  4s  Wait greylisting timeout
  Scan File  ${MESSAGE}
  ...  Settings=${SETTINGS_GREYLIST}
  Expect Symbol With Option  GREYLIST  pass
