*** Settings ***
Suite Setup     File Shm Proxy Setup
Suite Teardown  File Shm Proxy Teardown
Library         ${RSPAMD_TESTDIR}/lib/rspamd.py
Resource        ${RSPAMD_TESTDIR}/lib/rspamd.robot
Variables       ${RSPAMD_TESTDIR}/lib/vars.py

*** Variables ***
${MESSAGE}         ${RSPAMD_TESTDIR}/messages/spam_message.eml
${RSPAMD_SCOPE}    Suite
${RSPAMD_URL_TLD}  ${RSPAMD_TESTDIR}/../lua/unit/test_tld.dat
${DENIED}          File and shm message sources are not allowed
# A name only: the proxy refuses or strips these controls before resolving
# them, so nothing has to exist behind it.
${SHM_NAME}        /rspamd-proxy-shm-never-opened

*** Test Cases ***
TCP upstream is scanned through an inline body
  [Documentation]  Shared memory forwarding is not permitted for this upstream,
  ...              so the proxy has to send the message inline. The scan must
  ...              still succeed with the upstream's own verdict, and the
  ...              upstream must see no privileged message source header at all.
  Set Test Variable  ${RSPAMD_PORT_NORMAL}  ${RSPAMD_PORT_PROXY}
  Scan File  ${MESSAGE}  From=inline@example.net  Rcpt=inline-rcpt@example.net
  Expect Symbol  SIMPLE_TEST
  Expect Symbol With Exact Options  FILE_SHM_PROBE  none

Proxy refuses the File query argument
  [Documentation]  A query argument becomes a request header at the upstream,
  ...              so the URL has to be sanitised as thoroughly as the headers.
  ${data} =  Get Binary File  ${MESSAGE}
  ${headers} =  Create Dictionary  Queue-Id=${TEST NAME}
  ...  From=qfile@example.net  Rcpt=qfile-rcpt@example.net
  @{result} =  HTTP Status And Reason  POST  ${RSPAMD_LOCAL_ADDR}  ${RSPAMD_PORT_PROXY}
  ...  /checkv2?File=${BENIGN_FILE}  ${data}  ${headers}
  Should Be Equal As Integers  ${result}[0]  400
  Should Contain  ${result}[1]  ${DENIED}

Proxy refuses the Path query argument
  ${data} =  Get Binary File  ${MESSAGE}
  ${headers} =  Create Dictionary  Queue-Id=${TEST NAME}
  ...  From=qpath@example.net  Rcpt=qpath-rcpt@example.net
  @{result} =  HTTP Status And Reason  POST  ${RSPAMD_LOCAL_ADDR}  ${RSPAMD_PORT_PROXY}
  ...  /checkv2?Path=${BENIGN_FILE}  ${data}  ${headers}
  Should Be Equal As Integers  ${result}[0]  400
  Should Contain  ${result}[1]  ${DENIED}

Proxy refuses the File header
  ${data} =  Get Binary File  ${MESSAGE}
  ${headers} =  Create Dictionary  Queue-Id=${TEST NAME}  File=${BENIGN_FILE}
  ...  From=hfile@example.net  Rcpt=hfile-rcpt@example.net
  @{result} =  HTTP Status And Reason  POST  ${RSPAMD_LOCAL_ADDR}  ${RSPAMD_PORT_PROXY}
  ...  /checkv2  ${data}  ${headers}
  Should Be Equal As Integers  ${result}[0]  400
  Should Contain  ${result}[1]  ${DENIED}

Proxy refuses the Path header
  ${data} =  Get Binary File  ${MESSAGE}
  ${headers} =  Create Dictionary  Queue-Id=${TEST NAME}  Path=${BENIGN_FILE}
  ...  From=hpath@example.net  Rcpt=hpath-rcpt@example.net
  @{result} =  HTTP Status And Reason  POST  ${RSPAMD_LOCAL_ADDR}  ${RSPAMD_PORT_PROXY}
  ...  /checkv2  ${data}  ${headers}
  Should Be Equal As Integers  ${result}[0]  400
  Should Contain  ${result}[1]  ${DENIED}

Client Shm headers never reach the upstream
  [Documentation]  Shm/Shm-Offset/Shm-Length are hop-by-hop and are stripped at
  ...              ingress, so the upstream -- which does honour privileged
  ...              inputs -- must not observe a single one of them. If any had
  ...              survived, the upstream would have tried to open the named
  ...              segment and the scan would have failed instead.
  Set Test Variable  ${RSPAMD_PORT_NORMAL}  ${RSPAMD_PORT_PROXY}
  Scan File  ${MESSAGE}  Shm=${SHM_NAME}  Shm-Offset=0  Shm-Length=16
  ...  From=smuggle@example.net  Rcpt=smuggle-rcpt@example.net
  Expect Symbol  SIMPLE_TEST
  Expect Symbol With Exact Options  FILE_SHM_PROBE  none

Client Shm query arguments never reach the upstream
  ${data} =  Get Binary File  ${MESSAGE}
  ${headers} =  Create Dictionary  Queue-Id=${TEST NAME}
  ...  From=qsmuggle@example.net  Rcpt=qsmuggle-rcpt@example.net
  @{result} =  HTTP Status And Reason  POST  ${RSPAMD_LOCAL_ADDR}  ${RSPAMD_PORT_PROXY}
  ...  /checkv2?Shm=${SHM_NAME}&Shm-Offset=0&Shm-Length=16  ${data}  ${headers}
  Should Be Equal As Integers  ${result}[0]  200
  ${json} =  Evaluate  __import__('json').loads($result[2])
  Set Test Variable  ${SCAN_RESULT}  ${json}
  Expect Symbol  SIMPLE_TEST
  Expect Symbol With Exact Options  FILE_SHM_PROBE  none

Ordinary query arguments survive the stripping of a privileged one
  [Documentation]  Stripping Shm means rebuilding the URL around it, and every
  ...              surviving argument becomes a request header at the upstream.
  ...              An argument that shared the URL with a stripped one must
  ...              therefore arrive under its own name: a rebuild that kept the
  ...              original '?' as well as the appended one renames it to
  ...              '?From', which silently drops the envelope sender instead.
  ${data} =  Get Binary File  ${MESSAGE}
  # From is deliberately *not* sent as a header: the query argument is the only
  # source of it, so a mangled name cannot be masked by a surviving header
  ${headers} =  Create Dictionary  Queue-Id=${TEST NAME}
  ...  Rcpt=qsurvive-rcpt@example.net
  @{result} =  HTTP Status And Reason  POST  ${RSPAMD_LOCAL_ADDR}  ${RSPAMD_PORT_PROXY}
  ...  /checkv2?From=qsurvive@example.net&Shm=${SHM_NAME}  ${data}  ${headers}
  Should Be Equal As Integers  ${result}[0]  200
  ${json} =  Evaluate  __import__('json').loads($result[2])
  Set Test Variable  ${SCAN_RESULT}  ${json}
  Expect Symbol  SIMPLE_TEST
  Expect Symbol With Exact Options  REQUEST_ARG_PROBE  From=qsurvive@example.net
  # And the privileged one really was stripped, so this is not a case of the
  # whole query having been forwarded untouched
  Expect Symbol With Exact Options  FILE_SHM_PROBE  none

Client Shm headers cannot override a permissive proxy's own triplet
  [Documentation]  The other proxy worker does forward through shared memory,
  ...              so a triplet really is generated on the upstream leg. It
  ...              must be the proxy's own one: the client's values are
  ...              reserved-header noise and are dropped before it is written,
  ...              otherwise the upstream would read an object of the client's
  ...              choosing.
  Set Test Variable  ${RSPAMD_PORT_NORMAL}  ${RSPAMD_PORT_NORMAL_SLAVE}
  Scan File  ${MESSAGE}  Shm=${SHM_NAME}  Shm-Offset=4096  Shm-Length=16
  ...  From=override@example.net  Rcpt=override-rcpt@example.net
  Expect Symbol  SIMPLE_TEST
  ${options} =  Convert To List  ${SCAN_RESULT}[symbols][FILE_SHM_PROBE][options]
  ${seen} =  Catenate  SEPARATOR=;  @{options}
  Should Contain  ${seen}  Shm=  msg=the proxy did not generate a shared body at all
  Should Not Contain  ${seen}  ${SHM_NAME}
  Should Not Contain  ${seen}  Shm-Offset=4096
  Should Not Contain  ${seen}  Shm-Length=16

*** Keywords ***
File Shm Proxy Setup
  # Run the upstream scanner & copy variables. It is deliberately permissive,
  # so a smuggled File/Shm control would really be honoured there.
  Set Suite Variable  ${CONFIG}  ${RSPAMD_TESTDIR}/configs/file_shm_backend.conf
  Rspamd Setup
  Set Suite Variable  ${SLAVE_PROCESS}  ${RSPAMD_PROCESS}
  Set Suite Variable  ${SLAVE_TMPDIR}  ${RSPAMD_TMPDIR}
  ${path} =  Write Readable File  ${RSPAMD_TMPDIR}/by-reference.eml
  ...  From: <byref@example.net>\nTo: <byref-rcpt@example.net>\nSubject: scanned by reference\n\nSee http://file-by-reference.example.net/ for details.\n
  Set Suite Variable  ${BENIGN_FILE}  ${path}

  # Run the proxy & copy variables
  Set Suite Variable  ${CONFIG}  ${RSPAMD_TESTDIR}/configs/file_shm_proxy.conf
  Rspamd Setup  check_port=${RSPAMD_PORT_PROXY}
  Set Suite Variable  ${PROXY_PROCESS}  ${RSPAMD_PROCESS}
  Set Suite Variable  ${PROXY_TMPDIR}  ${RSPAMD_TMPDIR}
  # Rspamd Startup Check only pings the first proxy port
  Wait Until Keyword Succeeds  30x  0.2s
  ...  TCP Connect  ${RSPAMD_LOCAL_ADDR}  ${RSPAMD_PORT_NORMAL_SLAVE}

File Shm Proxy Teardown
  # Restore variables & run normal teardown
  Set Suite Variable  ${RSPAMD_PROCESS}  ${PROXY_PROCESS}
  Set Suite Variable  ${RSPAMD_TMPDIR}  ${PROXY_TMPDIR}
  Rspamd Teardown
  # The permissive proxy listens on a port that Wait For Rspamd Ports Released
  # does not know about, and the next suite on this pabot worker rebinds it.
  Run Keyword And Warn On Failure  Wait Until Keyword Succeeds  30x  0.2s
  ...  Port Is Free  ${RSPAMD_LOCAL_ADDR}  ${RSPAMD_PORT_NORMAL_SLAVE}
  # Do it again for the upstream scanner
  Set Suite Variable  ${RSPAMD_PROCESS}  ${SLAVE_PROCESS}
  Set Suite Variable  ${RSPAMD_TMPDIR}  ${SLAVE_TMPDIR}
  Rspamd Teardown
