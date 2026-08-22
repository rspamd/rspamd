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
${SMTP_STATUS_2}       ${RSPAMD_TMP_PREFIX}/metadata_exporter_smtp2.status
${SMTP_PID_2}          ${RSPAMD_TMP_PREFIX}/metadata_exporter_smtp2.pid
${SMTP_STATUS_3}       ${RSPAMD_TMP_PREFIX}/metadata_exporter_smtp3.status
${SMTP_PID_3}          ${RSPAMD_TMP_PREFIX}/metadata_exporter_smtp3.pid
${SMTP_STATUS_4}       ${RSPAMD_TMP_PREFIX}/metadata_exporter_smtp4.status
${SMTP_PID_4}          ${RSPAMD_TMP_PREFIX}/metadata_exporter_smtp4.pid
${SMTP_STATUS_5}       ${RSPAMD_TMP_PREFIX}/metadata_exporter_smtp5.status
${SMTP_PID_5}          ${RSPAMD_TMP_PREFIX}/metadata_exporter_smtp5.pid
${SMTP_STATUS_6}       ${RSPAMD_TMP_PREFIX}/metadata_exporter_smtp6.status
${SMTP_PID_6}          ${RSPAMD_TMP_PREFIX}/metadata_exporter_smtp6.pid

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
  Should Contain  ${smtp}  EHLO selector-test@example.com
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

Email export auto-encodes non-ASCII headers
  [Documentation]  Non-ASCII address display names and Subject get RFC 2047-encoded
  Scan File  ${MESSAGE}
  ...  From=sender@example.com
  ...  Rcpt=first@example.com,second@example.com
  ...  User=selector-test@example.com
  ...  Settings={symbols_enabled = []}

  Wait Until Keyword Succeeds  5s  100ms  File Should Exist  ${SMTP_STATUS_2}
  ${smtp2} =  Get File  ${SMTP_STATUS_2}
  Should Contain  ${smtp2}  From: J=?UTF-8?Q?
  Should Contain  ${smtp2}  To: =?UTF-8?Q?
  Should Contain  ${smtp2}  Subject: Pr=?UTF-8?Q?
  Should Contain  ${smtp2}  <sender@example.com>
  Should Contain  ${smtp2}  <first@example.com>, <second@example.com>
  Should Contain  ${smtp2}  Cc: Jörg <third@example.com> (Kommentar)
  Should Contain  ${smtp2}  Metadata alert
  Should Not Contain  ${smtp2}  Jörg Müller
  Should Not Contain  ${smtp2}  Änne Beispiel
  Should Not Contain  ${smtp2}  Prüfung möglich

Email export builds multipart from email_parts
  [Documentation]  email_parts assembles a multipart/mixed message: an
  ...  auto-quoted-printable text part and a base64 attachment with an
  ...  RFC 2231-encoded filename. The template's own body is empty, so no
  ...  extra leading part should appear. Numeric and empty values are valid.
  Scan File  ${MESSAGE}
  ...  From=sender@example.com
  ...  Rcpt=first@example.com
  ...  User=selector-test@example.com
  ...  Settings={symbols_enabled = []}

  Wait Until Keyword Succeeds  5s  100ms  File Should Exist  ${SMTP_STATUS_3}
  ${smtp3} =  Get File  ${SMTP_STATUS_3}
  ${info} =  Validate Multipart Email  ${smtp3}

  Should Be True  ${info}[is_multipart]
  Should Be Equal  ${info}[subtype]  mixed
  Should Be Equal As Integers  ${info}[part_count]  6
  Should Be True  ${info}[max_line_length] <= 998
  Should Be Equal  ${info}[mime_version]  1.0
  Should Not Be Equal  ${info}[message_id]  ${None}

  ${part1} =  Set Variable  ${info}[parts][0]
  Should Be Equal  ${part1}[content_type]  text/plain
  Should Be Equal  ${part1}[cte]  quoted-printable
  Should Be Equal  ${part1}[disposition]  inline
  Should Be Equal  ${part1}[decoded_text]  Prüfung ergab: alles in Ordnung.

  ${part2} =  Set Variable  ${info}[parts][1]
  Should Be Equal  ${part2}[content_type]  application/zip
  Should Be Equal  ${part2}[cte]  base64
  Should Contain  ${part2}[disposition]  attachment
  Should Be Equal  ${part2}[filename]  Bericht ö selector-test@example.com.zip
  Should Be Equal As Integers  ${part2}[decoded_length]  211
  Should Be Equal  ${part2}[decoded_sha256]  afa3a88349b72766447f9600846a12e539b3033ca5e7b12a836e72a46e586daf

  ${part3} =  Set Variable  ${info}[parts][2]
  Should Be Equal  ${part3}[content_type]  text/plain
  Should Be Equal  ${part3}[cte]  7bit
  Should Be Equal  ${part3}[decoded_text]  42

  ${part4} =  Set Variable  ${info}[parts][3]
  Should Be Equal  ${part4}[content_type]  application/octet-stream
  Should Be Equal  ${part4}[cte]  base64
  Should Be Equal As Integers  ${part4}[decoded_length]  0

  # A bare "." line survives DATA intact via SMTP dot-stuffing, so the
  # configured 8bit encoding is kept rather than escalated
  ${part5} =  Set Variable  ${info}[parts][4]
  Should Be Equal  ${part5}[content_type]  text/plain
  Should Be Equal  ${part5}[cte]  8bit
  Should Be Equal  ${part5}[decoded_text]  before\n.\nafter

  # Long filename survives RFC 2231 continuation splitting intact
  ${part6} =  Set Variable  ${info}[parts][5]
  Should Be Equal  ${part6}[filename]
  ...  Jahresabschlussbericht-Ärger-mit-Umlauten-und-sehr-langem-Namen-für-die-Ablage-2026-Quartal-vier-final.zip

Email export preserves template body MIME headers
  [Documentation]  The template's text/html Content-Type and 8bit CTE move to
  ...  its leading multipart part. A table-valued variable is flattened.
  Scan File  ${MESSAGE}
  ...  From=sender@example.com
  ...  Rcpt=first@example.com
  ...  User=selector-test@example.com
  ...  Settings={symbols_enabled = []}

  Wait Until Keyword Succeeds  5s  100ms  File Should Exist  ${SMTP_STATUS_4}
  ${smtp4} =  Get File  ${SMTP_STATUS_4}
  ${info} =  Validate Multipart Email  ${smtp4}

  Should Not Contain  ${smtp4}  BODY=8BITMIME
  Should Be True  ${info}[is_multipart]
  Should Be Equal  ${info}[subtype]  mixed
  Should Be Equal  ${info}[mime_version]  1.0
  # Template body headers move to the leading part, not the multipart wrapper
  Should Be Equal As Integers  ${info}[content_type_header_count]  1
  Should Be Equal As Integers  ${info}[cte_header_count]  0
  # Template body becomes part 1, email_parts entry follows
  Should Be Equal As Integers  ${info}[part_count]  2

  ${part1} =  Set Variable  ${info}[parts][0]
  Should Be Equal  ${part1}[content_type]  text/html
  Should Be Equal  ${part1}[cte]  8bit
  Should Be Equal  ${part1}[decoded_text]  <p>Grüße</p>

  ${part2} =  Set Variable  ${info}[parts][1]
  Should Be Equal  ${part2}[content_type]  text/plain
  Should Be Equal  ${part2}[decoded_text]  alpha\nbeta\ngamma

Email export negotiates BODY=8BITMIME when advertised
  [Documentation]  lua_smtp tries EHLO first; when the server advertises
  ...  8BITMIME, MAIL FROM gets the BODY=8BITMIME parameter.
  Scan File  ${MESSAGE}
  ...  From=sender@example.com
  ...  Rcpt=first@example.com
  ...  User=selector-test@example.com
  ...  Settings={symbols_enabled = []}

  Wait Until Keyword Succeeds  5s  100ms  File Should Exist  ${SMTP_STATUS_5}
  ${smtp5} =  Get File  ${SMTP_STATUS_5}
  Should Contain  ${smtp5}  EHLO selector-test@example.com
  Should Contain  ${smtp5}  MAIL FROM: <sender@example.com> BODY=8BITMIME
  Should Not Contain  ${smtp5}  HELO selector-test@example.com

Email export falls back to HELO when EHLO is rejected
  [Documentation]  A server that rejects EHLO gets a plain HELO retry, and
  ...  MAIL FROM is sent without a BODY= parameter.
  Scan File  ${MESSAGE}
  ...  From=sender@example.com
  ...  Rcpt=first@example.com
  ...  User=selector-test@example.com
  ...  Settings={symbols_enabled = []}

  Wait Until Keyword Succeeds  5s  100ms  File Should Exist  ${SMTP_STATUS_6}
  ${smtp6} =  Get File  ${SMTP_STATUS_6}
  Should Contain  ${smtp6}  EHLO selector-test@example.com
  Should Contain  ${smtp6}  HELO selector-test@example.com
  Should Contain  ${smtp6}  MAIL FROM: <sender@example.com>
  Should Not Contain  ${smtp6}  BODY=8BITMIME

*** Keywords ***
Metadata Exporter Structured Setup
  Run Redis
  Remove Files  ${SMTP_STATUS}  ${SMTP_STATUS_2}  ${SMTP_STATUS_3}  ${SMTP_STATUS_4}
  ...  ${SMTP_STATUS_5}  ${SMTP_STATUS_6}
  ${smtp} =  Start Dummy Smtp  11126  sink  127.0.0.1  ${SMTP_PID}
  ...  --status-file  ${SMTP_STATUS}
  Set Test Variable  ${DUMMY_SMTP_PROC}  ${smtp}
  ${smtp2} =  Start Dummy Smtp  11127  sink  127.0.0.1  ${SMTP_PID_2}
  ...  --status-file  ${SMTP_STATUS_2}
  Set Test Variable  ${DUMMY_SMTP_PROC_2}  ${smtp2}
  ${smtp3} =  Start Dummy Smtp  11128  sink  127.0.0.1  ${SMTP_PID_3}
  ...  --status-file  ${SMTP_STATUS_3}
  Set Test Variable  ${DUMMY_SMTP_PROC_3}  ${smtp3}
  ${smtp4} =  Start Dummy Smtp  11129  sink  127.0.0.1  ${SMTP_PID_4}
  ...  --status-file  ${SMTP_STATUS_4}  --ehlo-caps  X8BITMIME
  Set Test Variable  ${DUMMY_SMTP_PROC_4}  ${smtp4}
  ${smtp5} =  Start Dummy Smtp  11130  sink  127.0.0.1  ${SMTP_PID_5}
  ...  --status-file  ${SMTP_STATUS_5}  --ehlo-caps  8BITMIME
  Set Test Variable  ${DUMMY_SMTP_PROC_5}  ${smtp5}
  ${smtp6} =  Start Dummy Smtp  11131  sink  127.0.0.1  ${SMTP_PID_6}
  ...  --status-file  ${SMTP_STATUS_6}  --reject-ehlo
  Set Test Variable  ${DUMMY_SMTP_PROC_6}  ${smtp6}
  Rspamd Setup

Metadata Exporter Structured Teardown
  Rspamd Teardown
  Terminate Process  ${DUMMY_SMTP_PROC}
  Wait For Process  ${DUMMY_SMTP_PROC}
  Terminate Process  ${DUMMY_SMTP_PROC_2}
  Wait For Process  ${DUMMY_SMTP_PROC_2}
  Terminate Process  ${DUMMY_SMTP_PROC_3}
  Wait For Process  ${DUMMY_SMTP_PROC_3}
  Terminate Process  ${DUMMY_SMTP_PROC_4}
  Wait For Process  ${DUMMY_SMTP_PROC_4}
  Terminate Process  ${DUMMY_SMTP_PROC_5}
  Wait For Process  ${DUMMY_SMTP_PROC_5}
  Terminate Process  ${DUMMY_SMTP_PROC_6}
  Wait For Process  ${DUMMY_SMTP_PROC_6}
  Redis Teardown
