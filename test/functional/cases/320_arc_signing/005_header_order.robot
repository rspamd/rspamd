*** Settings ***
Suite Setup     Rspamd Setup
Suite Teardown  Rspamd Teardown
Library         Collections
Library         ${RSPAMD_TESTDIR}/lib/rspamd.py
Resource        ${RSPAMD_TESTDIR}/lib/rspamd.robot
Variables       ${RSPAMD_TESTDIR}/lib/vars.py

*** Variables ***
${CONFIG}          ${RSPAMD_TESTDIR}/configs/arc_signing/simple.conf
${MESSAGE}         ${RSPAMD_TESTDIR}/messages/dmarc/fail_none.eml
${REDIS_SCOPE}     Suite
${RSPAMD_SCOPE}    Suite
${RSPAMD_URL_TLD}  ${RSPAMD_TESTDIR}/../lua/unit/test_tld.dat
@{EXPECTED_ARC_ORDER}    ARC-Authentication-Results    ARC-Message-Signature    ARC-Seal

*** Test Cases ***
ARC SET MILTER HEADER ORDER
  # arc.lua passes an explicit `order` list to lua_mime.modify_headers. The
  # milter add_headers block must be emitted in that order
  # (ARC-Authentication-Results, ARC-Message-Signature, ARC-Seal): a milter
  # inserts each header at index 1, so this emission order makes the final
  # message read ARC-Seal, ARC-Message-Signature, ARC-Authentication-Results
  # top to bottom. Without an explicit order the headers were serialised in
  # arbitrary hash order (issue #6045).
  Scan File  ${MESSAGE}  User=bob@cacophony.za.org
  Expect Symbol  ARC_SIGNED
  ${arc_order} =  Arc Add Headers Order
  Should Be Equal  ${arc_order}  ${EXPECTED_ARC_ORDER}

ARC SET HEADER ORDER IS DETERMINISTIC
  # The ARC header order must not depend on hash iteration order: repeated
  # scans of the same message must yield an identical layout.
  Scan File  ${MESSAGE}  User=bob@cacophony.za.org
  ${first} =  Arc Add Headers Order
  Scan File  ${MESSAGE}  User=bob@cacophony.za.org
  ${second} =  Arc Add Headers Order
  Should Be Equal  ${first}  ${second}

*** Keywords ***
Arc Add Headers Order
  # ARC header field names, in the order they appear in the milter add_headers block
  Dictionary Should Contain Key  ${SCAN_RESULT}  milter
  ...  msg=milter block was not present in protocol response
  Dictionary Should Contain Key  ${SCAN_RESULT}[milter]  add_headers
  ...  msg=add_headers block was not present in protocol response
  ${keys} =  Get Dictionary Keys  ${SCAN_RESULT}[milter][add_headers]  sort_keys=${False}
  ${arc} =  Create List
  FOR  ${k}  IN  @{keys}
    ${is_arc} =  Run Keyword And Return Status  Should Start With  ${k}  ARC-
    IF  ${is_arc}
      Append To List  ${arc}  ${k}
    END
  END
  RETURN  ${arc}
