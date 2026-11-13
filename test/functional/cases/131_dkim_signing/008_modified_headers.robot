*** Settings ***
Suite Setup     Rspamd Setup
Suite Teardown  Rspamd Teardown
Library         ${RSPAMD_TESTDIR}/lib/rspamd.py
Resource        ${RSPAMD_TESTDIR}/lib/rspamd.robot
Variables       ${RSPAMD_TESTDIR}/lib/vars.py

*** Variables ***
${CONFIG}          ${RSPAMD_TESTDIR}/configs/dkim_signing/modified_headers.conf
${MESSAGE}         ${RSPAMD_TESTDIR}/messages/dmarc/fail_none.eml
${MESSAGE_LIST_POST}  ${RSPAMD_TESTDIR}/messages/dkim_signing_list_post.eml
${REDIS_SCOPE}     Suite
${RSPAMD_SCOPE}    Suite
${RSPAMD_URL_TLD}  ${RSPAMD_TESTDIR}/../lua/unit/test_tld.dat

*** Test Cases ***
SIGN ADDED HEADER
  ${result} =  Scan Message With Rspamc  ${MESSAGE}  -u  bob@cacophony.za.org
  Check Rspamc  ${result}  DKIM-Signature:
  Should Contain  ${result.stdout}  list-subscribe
  Should Contain  ${result.stdout}  DKIM_SIGNED

MODIFIED HEADERS VERIFY AFTER DELIVERY
  [Documentation]  The replaced From and the added headers are signed as the
  ...  MTA writes them, so the delivered message verifies
  Scan File  ${MESSAGE}  User=bob@cacophony.za.org
  Expect Symbol  DKIM_SIGNED
  ${signed} =  Apply Milter Reply  ${MESSAGE}  ${RSPAMD_TMPDIR}/modified_headers.eml
  ${hlist} =  Get DKIM Signed Headers  ${signed}
  List Should Contain Value  ${hlist}  list-subscribe
  Scan File  ${signed}
  Expect Symbol  R_DKIM_ALLOW

HEADER ADDED NEXT TO EXISTING ONES VERIFIES
  [Documentation]  Adding a header the message already has twice keeps both
  ...  existing ones in the signed set
  Scan File  ${MESSAGE_LIST_POST}  User=bob@cacophony.za.org
  Expect Symbol  DKIM_SIGNED
  ${signed} =  Apply Milter Reply  ${MESSAGE_LIST_POST}  ${RSPAMD_TMPDIR}/list_post.eml
  ${hlist} =  Get DKIM Signed Headers  ${signed}
  # Three List-Post headers and one more to oversign
  ${count} =  Count Values In List  ${hlist}  list-post
  Should Be Equal As Integers  ${count}  4
  Scan File  ${signed}
  Expect Symbol  R_DKIM_ALLOW
