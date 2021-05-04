*** Settings ***
Suite Setup     New Setup
Suite Teardown  Normal Teardown
Library         ${TESTDIR}/lib/rspamd.py
Resource        ${TESTDIR}/lib/rspamd.robot
Variables       ${TESTDIR}/lib/vars.py

*** Variables ***
${CONFIG}        ${TESTDIR}/configs/mid.conf
${RSPAMD_SCOPE}  Suite
${URL_TLD}       ${TESTDIR}/../lua/unit/test_tld.dat

*** Test Cases ***
MID - invalid Message-ID
  Scan File  ${TESTDIR}/messages/fws_fp.eml
  Expect Symbol With Score  INVALID_MSGID  1.70
  Do Not Expect Symbol  MISSING_MID
  Do Not Expect Symbol  INVALID_MSGID_ALLOWED

MID - invalid Message-ID allowed
  Scan File  ${TESTDIR}/messages/invalid_mid_allowed.eml
  Expect Symbol With Score  INVALID_MSGID_ALLOWED  1.00
  Do Not Expect Symbol  MISSING_MID
  Do Not Expect Symbol  INVALID_MSGID

MID - missing Message-ID
  Scan File  ${TESTDIR}/messages/freemail.eml
  Expect Symbol With Score  MISSING_MID  2.50
  Do Not Expect Symbol  MISSING_MID_ALLOWED
  Do Not Expect Symbol  INVALID_MSGID

MID - missing Message-ID allowed
  Scan File  ${TESTDIR}/messages/dmarc/onsubdomain_pass_relaxed.eml
  Expect Symbol With Score  MISSING_MID_ALLOWED  1.00
  Do Not Expect Symbol  MISSING_MID
  Do Not Expect Symbol  INVALID_MSGID
