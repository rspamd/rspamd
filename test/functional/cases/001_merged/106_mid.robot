*** Settings ***
Library         ${RSPAMD_TESTDIR}/lib/rspamd.py
Resource        ${RSPAMD_TESTDIR}/lib/rspamd.robot
Variables       ${RSPAMD_TESTDIR}/lib/vars.py

*** Variables ***
${SETTINGS_MID}  {symbols_enabled = [DKIM_CHECK,INVALID_MSGID,INVALID_MSGID_ALLOWED,KNOWN_NO_MID,KNOWN_MID,MISSING_MID,MISSING_MID_ALLOWED]}

*** Test Cases ***
MID - invalid Message-ID
  Scan File  ${RSPAMD_TESTDIR}/messages/fws_fp.eml
  ...  Settings=${SETTINGS_MID}
  Expect Symbol With Score  INVALID_MSGID  1.70
  Do Not Expect Symbol  MISSING_MID
  Do Not Expect Symbol  INVALID_MSGID_ALLOWED

MID - invalid Message-ID allowed
  Scan File  ${RSPAMD_TESTDIR}/messages/invalid_mid_allowed.eml
  ...  Settings=${SETTINGS_MID}
  Expect Symbol With Score  INVALID_MSGID_ALLOWED  0.00
  Do Not Expect Symbol  MISSING_MID
  Do Not Expect Symbol  INVALID_MSGID

MID - missing Message-ID
  Scan File  ${RSPAMD_TESTDIR}/messages/freemail.eml
  ...  Settings=${SETTINGS_MID}
  Expect Symbol With Score  MISSING_MID  2.50
  Do Not Expect Symbol  MISSING_MID_ALLOWED
  Do Not Expect Symbol  INVALID_MSGID

MID - missing Message-ID allowed
  Scan File  ${RSPAMD_TESTDIR}/messages/dmarc/onsubdomain_pass_relaxed.eml
  ...  Settings=${SETTINGS_MID}
  Expect Symbol With Score  MISSING_MID_ALLOWED  0.00
  Do Not Expect Symbol  MISSING_MID
  Do Not Expect Symbol  INVALID_MSGID
