*** Settings ***
Suite Setup     Rspamd Setup
Suite Teardown  Rspamd Teardown
Library         ${RSPAMD_TESTDIR}/lib/rspamd.py
Resource        ${RSPAMD_TESTDIR}/lib/rspamd.robot
Variables       ${RSPAMD_TESTDIR}/lib/vars.py

*** Variables ***
${CONFIG}              ${RSPAMD_TESTDIR}/configs/mid_utf8.conf
${RSPAMD_SCOPE}        Suite
${RSPAMD_URL_TLD}      ${RSPAMD_TESTDIR}/../lua/unit/test_tld.dat
${SETTINGS_MID_UTF8}   {symbols_enabled = [INVALID_MSGID,MISSING_MID]}

*** Test Cases ***
MID UTF8 - valid EAI Message-ID is not flagged as invalid
  [Documentation]  RFC 6532: when enable_mime_utf8 is enabled, a Message-ID
  ...              with a UTF-8 internationalized domain must be accepted.
  Scan File  ${RSPAMD_TESTDIR}/messages/mid_eai_utf8.eml
  ...  Settings=${SETTINGS_MID_UTF8}
  Do Not Expect Symbol  INVALID_MSGID
  Do Not Expect Symbol  MISSING_MID

MID UTF8 - structurally broken Message-ID is still flagged
  [Documentation]  Even with enable_mime_utf8 enabled, a Message-ID that
  ...              violates structural rules (no @) must still be detected.
  Scan File  ${RSPAMD_TESTDIR}/messages/fws_fp.eml
  ...  Settings=${SETTINGS_MID_UTF8}
  Expect Symbol With Score  INVALID_MSGID  1.70
