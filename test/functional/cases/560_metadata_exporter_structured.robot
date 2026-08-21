*** Settings ***
Test Setup      Metadata Exporter Structured Setup
Test Teardown   Metadata Exporter Structured Teardown
Library         Process
Library         OperatingSystem
Library         ${RSPAMD_TESTDIR}/lib/rspamd.py
Resource        ${RSPAMD_TESTDIR}/lib/rspamd.robot
Variables       ${RSPAMD_TESTDIR}/lib/vars.py

*** Variables ***
${CONFIG}              ${RSPAMD_TESTDIR}/configs/metadata_exporter_structured.conf
${MESSAGE}             ${RSPAMD_TESTDIR}/messages/spam_message.eml
${ATTACHMENT_MESSAGE}  ${RSPAMD_TESTDIR}/messages/zip.eml
${RSPAMD_LUA_SCRIPT}   ${RSPAMD_TESTDIR}/lua/metadata_exporter_structured.lua
${RSPAMD_SCOPE}        Suite
${RSPAMD_URL_TLD}      ${RSPAMD_TESTDIR}/../lua/unit/test_tld.dat
${REDIS_SCOPE}         Suite
${SMTP_STATUS}         ${RSPAMD_TMP_PREFIX}/metadata_exporter_smtp.status
${SMTP_PID}            ${RSPAMD_TMP_PREFIX}/metadata_exporter_smtp.pid

*** Test Cases ***
Structured export to Redis stream - UUID v7 and metadata
  [Documentation]  Export structured metadata to Redis stream, decode msgpack and verify UUID v7 format
  # Scan message - triggers default selector
  Scan File  ${MESSAGE}
  ...  Settings={symbols_enabled = []}

  # Wait for async export to complete
  Sleep  1s

  # Read and decode msgpack from Redis stream
  ${data} =  Redis Stream Read Msgpack  ${RSPAMD_REDIS_ADDR}  ${RSPAMD_REDIS_PORT}  test:structured
  Log  ${data}

  # Validate required fields and UUID v7 format
  Validate Structured Metadata  ${data}  uuid,ip,score,action

Structured export with zstd compression
  [Documentation]  Export with zstd compression on content fields
  Scan File  ${MESSAGE}
  ...  Settings={symbols_enabled = []}

  # Wait for async export
  Sleep  1s

  # Read from zstd stream
  ${data} =  Redis Stream Read Msgpack  ${RSPAMD_REDIS_ADDR}  ${RSPAMD_REDIS_PORT}  test:structured_zstd
  Log  ${data}

  # Validate required fields
  Validate Structured Metadata  ${data}  uuid,ip,score

  # Verify zstd compression markers are set
  ${count} =  Validate Zstd Compressed Fields  ${data}
  Log  Compressed fields count: ${count}

Attachment with detected MIME type
  [Documentation]  Scan message with attachment and verify content_type in export
  Scan File  ${ATTACHMENT_MESSAGE}
  ...  Settings={symbols_enabled = []}

  # Wait for async export
  Sleep  1s

  # Read from stream
  ${data} =  Redis Stream Read Msgpack  ${RSPAMD_REDIS_ADDR}  ${RSPAMD_REDIS_PORT}  test:structured
  Log  ${data}

  # Validate required fields
  Validate Structured Metadata  ${data}  uuid,ip,score

  # Verify attachments have content_type
  ${count} =  Validate Attachments Have Content Type  ${data}
  Should Be True  ${count} >= 1  msg=Expected at least 1 attachment with content_type

Email export expands and validates selector addresses
  Scan File  ${MESSAGE}
  ...  From=sender@example.com
  ...  Rcpt=first@example.com,second@example.com
  ...  User=selector-test@example.com
  ...  Settings={symbols_enabled = []}

  Wait Until Keyword Succeeds  5s  100ms  File Should Exist  ${SMTP_STATUS}
  ${smtp} =  Get File  ${SMTP_STATUS}
  Should Contain  ${smtp}  MAIL FROM: <sender@example.com>
  Should Contain  ${smtp}  HELO selector-test@example.com
  Should Contain  ${smtp}  RCPT TO: <first@example.com>
  Should Contain  ${smtp}  RCPT TO: <second@example.com>
  Should Not Contain  ${smtp}  not-an-address
  Should Contain  ${smtp}  From: <sender@example.com>
  Should Contain  ${smtp}  To: <first@example.com>, <second@example.com>
  Should Contain  ${smtp}  X-Custom: template-custom
  Should Contain  ${smtp}  X-Selector: selector-test@example.com
  ${rspamd_log} =  Get File  ${RSPAMD_TMPDIR}/rspamd.log
  Should Contain  ${rspamd_log}  METADATA_OPTIONS_EXPANDED
  Should Not Contain  ${rspamd_log}  METADATA_OPTIONS_FAILED

*** Keywords ***
Metadata Exporter Structured Setup
  Run Redis
  ${smtp} =  Start Dummy Smtp  11126  sink  127.0.0.1  ${SMTP_PID}
  ...  --status-file  ${SMTP_STATUS}
  Set Test Variable  ${DUMMY_SMTP_PROC}  ${smtp}
  Rspamd Setup

Metadata Exporter Structured Teardown
  Rspamd Teardown
  Terminate Process  ${DUMMY_SMTP_PROC}
  Wait For Process  ${DUMMY_SMTP_PROC}
  Redis Teardown
