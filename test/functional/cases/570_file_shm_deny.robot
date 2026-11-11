*** Settings ***
Suite Setup     File Shm Deny Setup
Suite Teardown  Rspamd Teardown
Library         ${RSPAMD_TESTDIR}/lib/rspamd.py
Resource        ${RSPAMD_TESTDIR}/lib/rspamd.robot
Variables       ${RSPAMD_TESTDIR}/lib/vars.py

*** Variables ***
${CONFIG}          ${RSPAMD_TESTDIR}/configs/file_shm_deny.conf
${MESSAGE}         ${RSPAMD_TESTDIR}/messages/spam_message.eml
${RSPAMD_SCOPE}    Suite
${RSPAMD_URL_TLD}  ${RSPAMD_TESTDIR}/../lua/unit/test_tld.dat
${DENIED}          file and shm message sources are not allowed
# A name only. The refusal happens on header presence alone, before the value
# is resolved, so nothing has to exist behind it and nothing has to be removed.
${SHM_NAME}        /rspamd-file-shm-deny-never-opened

*** Test Cases ***
Inline body still scans over TCP
  [Documentation]  Baseline: only the by-reference message sources are gated,
  ...              an ordinary inline scan is untouched.
  Scan File  ${MESSAGE}  From=inline@example.net  Rcpt=inline-rcpt@example.net
  Expect Symbol  SIMPLE_TEST

V2 File header is refused over TCP
  ${body} =  Scan File Expect Error  /dev/null  400  File=${BENIGN_FILE}
  ...  From=v2file@example.net  Rcpt=v2file-rcpt@example.net
  Should Contain  ${body}  ${DENIED}

V2 Path header is refused over TCP
  [Documentation]  Path is an alias of File and has to be gated with it.
  ${body} =  Scan File Expect Error  /dev/null  400  Path=${BENIGN_FILE}
  ...  From=v2path@example.net  Rcpt=v2path-rcpt@example.net
  Should Contain  ${body}  ${DENIED}

V2 Shm header is refused over TCP
  ${body} =  Scan File Expect Error  /dev/null  400  Shm=${SHM_NAME}
  ...  From=v2shm@example.net  Rcpt=v2shm-rcpt@example.net
  Should Contain  ${body}  ${DENIED}

V2 Shm-Offset header is refused over TCP
  ${body} =  Scan File Expect Error  /dev/null  400  Shm-Offset=0
  ...  From=v2shmoff@example.net  Rcpt=v2shmoff-rcpt@example.net
  Should Contain  ${body}  ${DENIED}

V2 Shm-Length header is refused over TCP
  ${body} =  Scan File Expect Error  /dev/null  400  Shm-Length=16
  ...  From=v2shmlen@example.net  Rcpt=v2shmlen-rcpt@example.net
  Should Contain  ${body}  ${DENIED}

V2 Shm triplet is refused over TCP
  ${body} =  Scan File Expect Error  /dev/null  400
  ...  Shm=${SHM_NAME}  Shm-Offset=0  Shm-Length=16
  ...  From=v2shmall@example.net  Rcpt=v2shmall-rcpt@example.net
  Should Contain  ${body}  ${DENIED}

V2 File header is refused by the controller over TCP
  [Documentation]  The controller scan endpoint is gated by its own worker
  ...              option, and a secure_ip match does not unlock it.
  ${body} =  Scan File Expect Error  /dev/null  400  port=${RSPAMD_PORT_CONTROLLER}
  ...  File=${BENIGN_FILE}  From=ctrlfile@example.net  Rcpt=ctrlfile-rcpt@example.net
  Should Contain  ${body}  ${DENIED}

V2 Shm header is refused by the controller over TCP
  ${body} =  Scan File Expect Error  /dev/null  400  port=${RSPAMD_PORT_CONTROLLER}
  ...  Shm=${SHM_NAME}  From=ctrlshm@example.net  Rcpt=ctrlshm-rcpt@example.net
  Should Contain  ${body}  ${DENIED}

V3 file metadata is refused over TCP
  ${meta} =  Create Dictionary  file=${BENIGN_FILE}
  Scan File V3 Expect Error  ${MESSAGE}  400  metadata=${meta}
  ...  From=v3file@example.net  Rcpt=v3file-rcpt@example.net

V3 shm metadata is refused over TCP
  ${meta} =  Create Dictionary  shm=${SHM_NAME}
  Scan File V3 Expect Error  ${MESSAGE}  400  metadata=${meta}
  ...  From=v3shm@example.net  Rcpt=v3shm-rcpt@example.net

Encrypted connection does not unlock the File message source
  [Documentation]  Encryption establishes that the request was not tampered
  ...              with in transit, not that the client shares a filesystem
  ...              with the daemon, so it must not widen what may be named.
  ${result} =  Run Rspamc  -p  -h  ${RSPAMD_LOCAL_ADDR}:${RSPAMD_PORT_NORMAL}
  ...  --key  ${RSPAMD_KEY_PUB1}  --header=File=${BENIGN_FILE}
  ...  --header=From=encfile@example.net  --header=Rcpt=encfile-rcpt@example.net
  ...  /dev/null
  Should Contain  ${result.stdout}${result.stderr}  ${DENIED}

Unix socket keeps the File message source
  [Documentation]  The capability follows the transport: the very same request
  ...              that is refused above succeeds on a socket whose access is
  ...              controlled by filesystem permissions (mode=0600). The URL
  ...              only exists inside the referenced file, so finding it proves
  ...              the file was really read and not merely named.
  Scan File Over Unix Socket  ${SCAN_SOCKET}  /dev/null  File=${BENIGN_FILE}
  ...  From=unixfile@example.net  Rcpt=unixfile-rcpt@example.net
  Expect Symbol  SIMPLE_TEST
  Expect URL  file-by-reference.example.net

Unix socket keeps the File message source with an encoded name
  Scan File Over Unix Socket  ${SCAN_SOCKET}  /dev/null  File=${ENCODED_FILE}
  ...  From=unixenc@example.net  Rcpt=unixenc-rcpt@example.net
  Expect Symbol  SIMPLE_TEST
  Expect URL  file-by-reference.example.net

*** Keywords ***
File Shm Deny Setup
  Rspamd Setup
  # Rspamd Startup Check only pings a TCP port, so the unix listener of the
  # very same worker needs its own barrier before the first request.
  Set Suite Variable  ${SCAN_SOCKET}  ${RSPAMD_TMPDIR}/scan.sock
  Wait Until Keyword Succeeds  30x  0.2s  Unix Socket Connect  ${SCAN_SOCKET}
  Make Benign File

Make Benign File
  [Documentation]  An ordinary message on disk carrying a URL that nothing else
  ...  in this suite contains. It lives in the suite tmpdir, which is
  ...  world-readable and is removed by Rspamd Teardown on success and on
  ...  failure alike.
  ${path} =  Write Readable File  ${RSPAMD_TMPDIR}/by-reference.eml
  ...  From: <byref@example.net>\nTo: <byref-rcpt@example.net>\nSubject: scanned by reference\n\nSee http://file-by-reference.example.net/ for details.\n
  Set Suite Variable  ${BENIGN_FILE}  ${path}
  ${encoded} =  Encode Filename  ${path}
  Set Suite Variable  ${ENCODED_FILE}  ${encoded}
