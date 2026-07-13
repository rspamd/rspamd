*** Settings ***
Library         ${RSPAMD_TESTDIR}/lib/rspamd.py
Resource        ${RSPAMD_TESTDIR}/lib/rspamd.robot
Variables       ${RSPAMD_TESTDIR}/lib/vars.py

*** Variables ***
${GTUBE}               ${RSPAMD_TESTDIR}/messages/gtube.eml
${MESSAGE}             ${RSPAMD_TESTDIR}/messages/spam_message.eml
${ALT_RELATED}         ${RSPAMD_TESTDIR}/messages/alternative-related.eml
${MIXED_RELATED_HTML}  ${RSPAMD_TESTDIR}/messages/mixed-related-html-only.eml
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

checkv3 inline metadata.settings injects symbol
  [Documentation]  Inline metadata.settings must run apply_settings_side_effects
  ...              so settings.symbols actually fires (issue #5999).
  ...              GTUBE is a hard bypass and skips SETTINGS_CHECK, so use a
  ...              normal message that goes through the full prefilter chain.
  ${settings_obj} =  Evaluate  {"symbols": ["INLINE_V3_TEST"]}
  &{meta} =  Create Dictionary  settings=${settings_obj}
  Scan File V3  ${MESSAGE}  metadata=${meta}
  Expect Symbol  INLINE_V3_TEST

checkv3 missing metadata part
  [Documentation]  Send only message part without metadata, expect HTTP 500 (400 error mapped to 5xx)
  ${status} =  Scan File V3 Single Part  message  test message body
  Should Be Equal As Integers  ${status}  500

checkv3 missing message part
  [Documentation]  Send only metadata part without message, expect HTTP 500 (400 error mapped to 5xx)
  ${status} =  Scan File V3 Single Part  metadata  {}  application/json
  Should Be Equal As Integers  ${status}  500

checkv3 multipart/alternative MIME message
  [Documentation]  Message with own MIME boundaries (multipart/alternative) must parse correctly
  Scan File V3  ${ALT_RELATED}
  ...  Settings={symbols_enabled = [R_PARTS_DIFFER]}
  Expect Symbol  R_PARTS_DIFFER

checkv3 multipart/mixed MIME message
  [Documentation]  Message with multipart/mixed MIME structure and attachments
  Scan File V3  ${MIXED_RELATED_HTML}
  ...  Settings={symbols_enabled = [MIME_HTML_ONLY]}
  Expect Symbol  MIME_HTML_ONLY

checkv3 malformed boundary
  [Documentation]  Send body with wrong boundary, expect HTTP 500 (400 error mapped to 5xx)
  Scan File V3 Expect Error  ${GTUBE}  500
  ...  content_type_override=multipart/form-data; boundary=wrong-boundary-does-not-match

checkv3 via rspamc with zstd compression
  [Documentation]  Scan via rspamc --protocol-v3 (zstd compression enabled by default)
  ${result} =  Run Rspamc  -p  -h  ${RSPAMD_LOCAL_ADDR}:${RSPAMD_PORT_NORMAL}  --protocol-v3
  ...  --settings=${SETTINGS_NOSYMBOLS}  ${GTUBE}
  Check Rspamc  ${result}  GTUBE (

checkv3 via rspamc encrypted
  [Documentation]  Scan via rspamc --protocol-v3 with httpcrypt encryption
  ${result} =  Run Rspamc  -p  -h  ${RSPAMD_LOCAL_ADDR}:${RSPAMD_PORT_NORMAL}  --protocol-v3
  ...  --key  ${RSPAMD_KEY_PUB1}  --settings=${SETTINGS_NOSYMBOLS}  ${GTUBE}
  Check Rspamc  ${result}  GTUBE (

checkv3 via rspamc with msgpack metadata
  [Documentation]  Scan via rspamc --protocol-v3 --msgpack (msgpack metadata and response)
  ${result} =  Run Rspamc  -p  -h  ${RSPAMD_LOCAL_ADDR}:${RSPAMD_PORT_NORMAL}  --protocol-v3
  ...  --msgpack  --settings=${SETTINGS_NOSYMBOLS}  ${GTUBE}
  Check Rspamc  ${result}  GTUBE (

checkv3 via rspamc encrypted with msgpack
  [Documentation]  Scan via rspamc --protocol-v3 --msgpack --key (encrypted + msgpack)
  ${result} =  Run Rspamc  -p  -h  ${RSPAMD_LOCAL_ADDR}:${RSPAMD_PORT_NORMAL}  --protocol-v3
  ...  --msgpack  --key  ${RSPAMD_KEY_PUB1}  --settings=${SETTINGS_NOSYMBOLS}  ${GTUBE}
  Check Rspamc  ${result}  GTUBE (

checkv3 custom metadata header via get_request_header
  [Documentation]  Custom field in the metadata "headers" sub-object is retrievable via task:get_request_header
  &{V3_HDRS} =  Create Dictionary  X-V3-Custom=hello-from-meta
  &{V3_META} =  Create Dictionary  headers=${V3_HDRS}
  Scan File V3  ${MESSAGE}  metadata=${V3_META}
  Expect Symbol With Option  TEST_V3_META_HEADER  hello-from-meta

checkv3 metadata fields via get_metadata and get_metadata_field
  [Documentation]  Arbitrary top-level metadata fields are readable via task:get_metadata()/get_metadata_field()
  &{V3_META} =  Create Dictionary  custom_field=meta-value-42
  Scan File V3  ${MESSAGE}  metadata=${V3_META}
  Expect Symbol With Option  TEST_V3_META_FIELD  meta-value-42
  Expect Symbol With Option  TEST_V3_META_FIELD_LOOKUP  meta-value-42

checkv3 via rspamc with metadata-header
  [Documentation]  rspamc --metadata-header injects a metadata header retrievable via task:get_request_header
  ${result} =  Run Rspamc  -p  -h  ${RSPAMD_LOCAL_ADDR}:${RSPAMD_PORT_NORMAL}  --protocol-v3
  ...  --metadata-header=X-V3-Custom=from-rspamc  ${MESSAGE}
  Check Rspamc  ${result}  TEST_V3_META_HEADER (

checkv3 content negotiation on normal worker
  [Documentation]  Accept / Accept-Encoding content negotiation for /checkv3
  ...              against the normal scan worker.
  Run V3 Negotiation Checks  ${RSPAMD_PORT_NORMAL}

checkv3 content negotiation on controller
  [Documentation]  Same negotiation contract must hold on the controller endpoint.
  Run V3 Negotiation Checks  ${RSPAMD_PORT_CONTROLLER}

*** Keywords ***
Run V3 Negotiation Checks
  [Arguments]  ${port}
  # 1. No Accept -> multipart/form-data default, Vary advertised, result usable
  &{r} =  Scan File V3 Negotiated  ${GTUBE}  port=${port}  Settings=${SETTINGS_NOSYMBOLS}
  Should Be Equal As Integers  ${r}[status]  200
  Should Start With  ${r}[content_type]  multipart/form-data
  Should Contain  ${r}[vary]  Accept
  Should Contain  ${r}[vary]  Accept-Encoding
  Expect Symbol  GTUBE

  # 2. Accept: application/json -> single JSON body, no multipart parts
  &{r} =  Scan File V3 Negotiated  ${GTUBE}  accept=application/json  port=${port}
  ...  Settings=${SETTINGS_NOSYMBOLS}
  Should Be Equal As Integers  ${r}[status]  200
  Should Start With  ${r}[content_type]  application/json
  Should Be Equal  ${r}[parser]  json
  Should Be Empty  ${r}[parts]
  Expect Symbol  GTUBE

  # 3. Accept: application/msgpack -> single msgpack body
  &{r} =  Scan File V3 Negotiated  ${GTUBE}  accept=application/msgpack  port=${port}
  ...  Settings=${SETTINGS_NOSYMBOLS}
  Should Be Equal As Integers  ${r}[status]  200
  Should Start With  ${r}[content_type]  application/msgpack
  Should Be Equal  ${r}[parser]  msgpack
  Expect Symbol  GTUBE

  # 4. Accept: message/rfc822 -> multipart/mixed, parseable as MIME
  &{r} =  Scan File V3 Negotiated  ${GTUBE}  accept=message/rfc822  port=${port}
  ...  Settings=${SETTINGS_NOSYMBOLS}
  Should Be Equal As Integers  ${r}[status]  200
  Should Start With  ${r}[content_type]  multipart/mixed
  Should Be Equal  ${r}[parser]  mime
  Should Start With  ${r}[result_ctype]  application/json
  Expect Symbol  GTUBE

  # 5. Accept: multipart/form-data -> parseable by an HTTP multipart parser
  &{r} =  Scan File V3 Negotiated  ${GTUBE}  accept=multipart/form-data  port=${port}
  ...  Settings=${SETTINGS_NOSYMBOLS}
  Should Be Equal As Integers  ${r}[status]  200
  Should Start With  ${r}[content_type]  multipart/form-data
  Should Be Equal  ${r}[parser]  form-data
  Expect Symbol  GTUBE

  # 6. msgpack metadata, no Accept -> multipart default, result part mirrors input (msgpack)
  &{meta6} =  Create Dictionary  from=sender@example.com
  &{r} =  Scan File V3 Negotiated  ${GTUBE}  metadata=${meta6}  metadata_format=msgpack
  ...  port=${port}  Settings=${SETTINGS_NOSYMBOLS}
  Should Be Equal As Integers  ${r}[status]  200
  Should Start With  ${r}[content_type]  multipart/form-data
  Should Start With  ${r}[result_ctype]  application/msgpack
  Expect Symbol  GTUBE

  # 7. Accept names only unsupported types -> 406 Not Acceptable
  &{r} =  Scan File V3 Negotiated  ${GTUBE}  accept=application/xml  port=${port}
  ...  Settings=${SETTINGS_NOSYMBOLS}
  Should Be Equal As Integers  ${r}[status]  406

  # 8. Accept-Encoding: zstd -> parts carry Content-Encoding: zstd
  &{r} =  Scan File V3 Negotiated  ${GTUBE}  accept=multipart/form-data
  ...  accept_encoding=zstd  port=${port}  Settings=${SETTINGS_NOSYMBOLS}
  Should Be Equal As Integers  ${r}[status]  200
  Should Contain  ${r}[part_encodings]  zstd

  # 8b. No Accept-Encoding -> identity (uncompressed)
  &{r} =  Scan File V3 Negotiated  ${GTUBE}  accept=multipart/form-data  port=${port}
  ...  Settings=${SETTINGS_NOSYMBOLS}
  Should Be Equal As Integers  ${r}[status]  200
  Should Be Empty  ${r}[part_encodings]
