*** Settings ***
Library         ${RSPAMD_TESTDIR}/lib/rspamd.py
Resource        ${RSPAMD_TESTDIR}/lib/rspamd.robot
Variables       ${RSPAMD_TESTDIR}/lib/vars.py

*** Variables ***
${MESSAGE}              ${RSPAMD_TESTDIR}/messages/spam_message.eml
${MESSAGE2}             ${RSPAMD_TESTDIR}/messages/spam.eml
${MESSAGE3}             ${RSPAMD_TESTDIR}/messages/freemail.eml
${SETTINGS_GREYLIST}    {symbols_enabled = [GREYLIST_CHECK, GREYLIST_SAVE], symbols = [FOUR_POINTS]}
${SETTINGS_NOGREYLIST}  {symbols_enabled = [GREYLIST_CHECK, GREYLIST_SAVE], symbols = [THREE_POINTS]}
${SETTINGS_RESCORED}    {actions { greylist = 3 }, symbols_enabled = [GREYLIST_CHECK, GREYLIST_SAVE], symbols = [THREE_POINTS]}
${SETTINGS_REJECTED}    {actions { greylist = 3 }, symbols_enabled = [GREYLIST_CHECK, GREYLIST_SAVE], symbols = [TWENTY_POINTS]}

*** Test Cases ***
GREYLIST NEW
  Scan File  ${MESSAGE}
  ...  Settings=${SETTINGS_GREYLIST}
  Expect Symbol With Option  GREYLIST  greylisted
  Expect Action  soft reject

GREYLIST EARLY
  Scan File  ${MESSAGE}
  ...  Settings=${SETTINGS_GREYLIST}
  Expect Symbol With Option  GREYLIST  greylisted
  Expect Action  soft reject

GREYLIST NOT GREYLISTED
  Scan File  ${MESSAGE2}
  ...  Settings=${SETTINGS_NOGREYLIST}
  Do Not Expect Symbol  GREYLIST
  Expect Action  no action

GREYLIST REJECTED
  Scan File  ${MESSAGE3}
  ...  Settings=${SETTINGS_REJECTED}
  Do Not Expect Symbol  GREYLIST
  Expect Action  reject

GREYLIST RESCORED
  Scan File  ${MESSAGE2}
  ...  Settings=${SETTINGS_RESCORED}
  Expect Symbol With Option  GREYLIST  greylisted
  Expect Action  soft reject

GREYLIST PASS
  Sleep  4s  Wait greylisting timeout
  Scan File  ${MESSAGE}
  ...  Settings=${SETTINGS_GREYLIST}
  Expect Symbol With Option  GREYLIST  pass
  Expect Action  no action
