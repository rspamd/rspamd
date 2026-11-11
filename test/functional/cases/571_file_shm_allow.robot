*** Settings ***
Suite Setup     File Shm Allow Setup
Suite Teardown  File Shm Allow Teardown
Library         ${RSPAMD_TESTDIR}/lib/rspamd.py
Resource        ${RSPAMD_TESTDIR}/lib/rspamd.robot
Variables       ${RSPAMD_TESTDIR}/lib/vars.py

*** Variables ***
${CONFIG}          ${RSPAMD_TESTDIR}/configs/file_shm_allow.conf
${MESSAGE}         ${RSPAMD_TESTDIR}/messages/spam_message.eml
${RSPAMD_SCOPE}    Suite
${RSPAMD_URL_TLD}  ${RSPAMD_TESTDIR}/../lua/unit/test_tld.dat
# Matches options.max_message in configs/file_shm_allow.conf
${MAX_MESSAGE}     ${65536}

*** Test Cases ***
File message source still works over TCP
  [Documentation]  Compatibility: with allow_file_and_shm_inputs = true the
  ...              historical by-reference behaviour is unchanged. The URL
  ...              only exists inside the referenced file.
  Scan File By Reference  ${BENIGN_FILE}
  ...  From=allowfile@example.net  Rcpt=allowfile-rcpt@example.net
  Expect Symbol  SIMPLE_TEST
  Expect URL  file-by-reference.example.net

File message source still works over TCP with an encoded name
  ${encoded} =  Encode Filename  ${BENIGN_FILE}
  Scan File By Reference  ${encoded}
  ...  From=allowenc@example.net  Rcpt=allowenc-rcpt@example.net
  Expect Symbol  SIMPLE_TEST
  Expect URL  file-by-reference.example.net

Path message source still works over TCP
  Scan File  /dev/null  Path=${BENIGN_FILE}
  ...  From=allowpath@example.net  Rcpt=allowpath-rcpt@example.net
  Expect Symbol  SIMPLE_TEST
  Expect URL  file-by-reference.example.net

Shm message source still works over TCP
  ${name}  ${path} =  Create Shm Payload  content=${SHM_MESSAGE}
  TRY
    Scan File  /dev/null  Shm=${name}
    ...  From=allowshm@example.net  Rcpt=allowshm-rcpt@example.net
    Expect Symbol  SIMPLE_TEST
    Expect URL  shm-by-reference.example.net
  FINALLY
    Remove Shm Payload  ${path}
  END

V3 file metadata still works over TCP
  ${meta} =  Create Dictionary  file=${BENIGN_FILE}
  Scan File V3  ${MESSAGE}  metadata=${meta}
  ...  From=allowv3file@example.net  Rcpt=allowv3file-rcpt@example.net
  Expect Symbol  SIMPLE_TEST
  Expect URL  file-by-reference.example.net

File larger than max_message is rejected
  [Documentation]  A by-reference file must obey the very same size limit as
  ...              an inline body. The legacy 5xx mapping applies here: this is
  ...              a protocol error, not the new client-error gate.
  ${body} =  Scan File Expect Error  /dev/null  503  File=${OVERSIZED_FILE}
  ...  From=allowbigfile@example.net  Rcpt=allowbigfile-rcpt@example.net
  Should Contain  ${body}  Too large file

Shm payload larger than max_message is rejected
  ${name}  ${path} =  Create Shm Payload  size=${OVERSIZED}
  TRY
    ${body} =  Scan File Expect Error  /dev/null  503  Shm=${name}
    ...  From=allowbigshm@example.net  Rcpt=allowbigshm-rcpt@example.net
    Should Contain  ${body}  too large
  FINALLY
    Remove Shm Payload  ${path}
  END

*** Keywords ***
File Shm Allow Setup
  Rspamd Setup
  ${oversized} =  Evaluate  ${MAX_MESSAGE} + 4096
  Set Suite Variable  ${OVERSIZED}  ${oversized}
  ${path} =  Write Readable File  ${RSPAMD_TMPDIR}/by-reference.eml
  ...  From: <byref@example.net>\nTo: <byref-rcpt@example.net>\nSubject: scanned by reference\n\nSee http://file-by-reference.example.net/ for details.\n
  Set Suite Variable  ${BENIGN_FILE}  ${path}
  ${big} =  Write Filler File  ${RSPAMD_TMPDIR}/oversized.eml  ${oversized}
  Set Suite Variable  ${OVERSIZED_FILE}  ${big}
  Set Suite Variable  ${SHM_MESSAGE}
  ...  From: <shmref@example.net>\nTo: <shmref-rcpt@example.net>\nSubject: scanned from shared memory\n\nSee http://shm-by-reference.example.net/ for details.\n

File Shm Allow Teardown
  Rspamd Teardown
