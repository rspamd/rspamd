*** Settings ***
Library         ${RSPAMD_TESTDIR}/lib/rspamd.py
Resource        ${RSPAMD_TESTDIR}/lib/rspamd.robot
Variables       ${RSPAMD_TESTDIR}/lib/vars.py

*** Variables ***
${GTUBE}               ${RSPAMD_TESTDIR}/messages/gtube.eml
${SETTINGS_NOSYMBOLS}  {symbols_enabled = []}

*** Test Cases ***
GTUBE via checkv3
  [Documentation]  Basic /checkv3 scan, expect GTUBE symbol
  Scan File V3  ${GTUBE}  Settings=${SETTINGS_NOSYMBOLS}
  Expect Symbol  GTUBE

checkv3 with metadata from and rcpt
  [Documentation]  Set from and rcpt in metadata JSON, verify they are applied
  &{meta} =  Create Dictionary  from=sender@example.com  rcpt=rcpt@example.com
  Scan File V3  ${GTUBE}  metadata=${meta}  Settings=${SETTINGS_NOSYMBOLS}
  Expect Symbol  GTUBE

checkv3 with settings_id
  [Documentation]  Pass settings_id in metadata, verify settings are applied
  &{meta} =  Create Dictionary  settings_id=id_test
  Scan File V3  ${GTUBE}  metadata=${meta}
  Expect Symbol  GTUBE

checkv3 missing metadata part
  [Documentation]  Send only message part without metadata, expect HTTP 400
  ${status} =  Scan File V3 Single Part  message  test message body
  Should Be Equal As Integers  ${status}  400

checkv3 missing message part
  [Documentation]  Send only metadata part without message, expect HTTP 400
  ${status} =  Scan File V3 Single Part  metadata  {}  application/json
  Should Be Equal As Integers  ${status}  400

checkv3 malformed boundary
  [Documentation]  Send body with wrong boundary, expect HTTP 400
  Scan File V3 Expect Error  ${GTUBE}  400
  ...  content_type_override=multipart/form-data; boundary=wrong-boundary-does-not-match
