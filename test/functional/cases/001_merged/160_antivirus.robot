*** Settings ***
Library         Process
Library         OperatingSystem
Library         ${RSPAMD_TESTDIR}/lib/rspamd.py
Resource        ${RSPAMD_TESTDIR}/lib/rspamd.robot
Variables       ${RSPAMD_TESTDIR}/lib/vars.py

*** Variables ***
${MESSAGE2}         ${RSPAMD_TESTDIR}/messages/freemail.eml
${MESSAGE}          ${RSPAMD_TESTDIR}/messages/spam_message.eml
${SETTINGS_AVAST}   {symbols_enabled = [AVAST_VIRUS]}
${SETTINGS_CLAM}    {symbols_enabled = [CLAM_VIRUS]}
${SETTINGS_CLAM_FAIL}  {symbols_enabled = [CLAM_VIRUS, CLAM_VIRUS_FAIL]}
${MESSAGE3}         ${RSPAMD_TESTDIR}/messages/btc.eml
${SETTINGS_FPROT}   {symbols_enabled = [FPROT_VIRUS, FPROT2_VIRUS_DUPLICATE_DEFAULT]}
${SETTINGS_FPROT_FAIL}  {symbols_enabled = [FPROT_VIRUS, FPROT_VIRUS_FAIL]}
${SETTINGS_AVAST_FAIL}  {symbols_enabled = [AVAST_VIRUS, AVAST_VIRUS_FAIL]}
${SETTINGS_SAVAPI}  {symbols_enabled = [SAVAPI_VIRUS, SAVAPI_VIRUS_FAIL]}
${SETTINGS_SPAMD}   {symbols_enabled = [SPAMD_TEST, SPAMD_TEST_FAIL]}
${MESSAGE_B}        ${RSPAMD_TESTDIR}/messages/btc2.eml
${MESSAGE_C}        ${RSPAMD_TESTDIR}/messages/btc3.eml
${MESSAGE_D}        ${RSPAMD_TESTDIR}/messages/btc4.eml
${MESSAGE_E}        ${RSPAMD_TESTDIR}/messages/crypto.eml

*** Test Cases ***
CLAMAV MISS
  ${process} =  Run Dummy Clam  ${RSPAMD_PORT_CLAM}
  Scan File  ${MESSAGE}
  ...  Settings=${SETTINGS_CLAM}
  Do Not Expect Symbol  CLAM_VIRUS
  [Teardown]  Terminate Process  ${process}

CLAMAV HIT
  ${process} =  Run Dummy Clam  ${RSPAMD_PORT_CLAM}  1
  Scan File  ${MESSAGE2}
  ...  Settings=${SETTINGS_CLAM}
  Expect Symbol  CLAM_VIRUS
  Do Not Expect Symbol  CLAMAV_VIRUS_FAIL
  [Teardown]  Terminate Process  ${process}

CLAMAV CACHE HIT
  Scan File  ${MESSAGE2}
  ...  Settings=${SETTINGS_CLAM}
  Expect Symbol  CLAM_VIRUS
  Do Not Expect Symbol  CLAMAV_VIRUS_FAIL

CLAMAV CACHE MISS
  Scan File  ${MESSAGE}
  ...  Settings=${SETTINGS_CLAM}
  Do Not Expect Symbol  CLAM_VIRUS
  Do Not Expect Symbol  CLAMAV_VIRUS_FAIL

CLAMAV ERROR REPLY
  [Documentation]  A complete reply that is not a verdict is a failed scan, not a clean message
  ${process} =  Run Dummy Clam  ${RSPAMD_PORT_CLAM}  error
  Scan File  ${MESSAGE3}
  ...  Settings=${SETTINGS_CLAM_FAIL}
  Expect Symbol With Exact Options  CLAM_VIRUS_FAIL  unhandled response: stream: Database reload in progress ERROR
  Do Not Expect Symbol  CLAM_VIRUS
  [Teardown]  Terminate Process  ${process}

FPROT MISS
  ${process} =  Run Dummy Fprot  ${RSPAMD_PORT_FPROT}
  Scan File  ${MESSAGE2}
  ...  Settings=${SETTINGS_FPROT}
  Do Not Expect Symbol  FPROT_VIRUS
  Do Not Expect Symbol  FPROT_EICAR
  [Teardown]  Terminate Process  ${process}

FPROT HIT - PATTERN
  ${process1} =  Run Dummy Fprot  ${RSPAMD_PORT_FPROT}  1
  ${process2} =  Run Dummy Fprot  ${RSPAMD_PORT_FPROT2_DUPLICATE}  1  ${RSPAMD_TMP_PREFIX}/dummy_fprot_dupe-${RSPAMD_PORT_FPROT2_DUPLICATE}.pid
  Scan File  ${MESSAGE}
  ...  Settings=${SETTINGS_FPROT}
  Expect Symbol  FPROT_EICAR
  # Also check ordered pattern match
  Expect Symbol  FPROT2_VIRUS_DUPLICATE_PATTERN
  Do Not Expect Symbol  FPROT2_VIRUS_DUPLICATE_DEFAULT
  Do Not Expect Symbol  FPROT2_VIRUS_DUPLICATE_NOPE
  [Teardown]  Double FProt Teardown  ${process1}  ${process2}

FPROT CACHE HIT
  Scan File  ${MESSAGE}
  ...  Settings=${SETTINGS_FPROT}
  Expect Symbol  FPROT_EICAR
  Do Not Expect Symbol  CLAMAV_VIRUS
  # Also check ordered pattern match
  Expect Symbol  FPROT2_VIRUS_DUPLICATE_PATTERN
  Do Not Expect Symbol  FPROT2_VIRUS_DUPLICATE_DEFAULT

FPROT CACHE MISS
  Scan File  ${MESSAGE2}
  ...  Settings=${SETTINGS_FPROT}
  Do Not Expect Symbol  FPROT_VIRUS

AVAST MISS
  ${process} =  Run Dummy Avast  ${RSPAMD_PORT_AVAST}
  Scan File  ${MESSAGE}
  ...  Settings=${SETTINGS_AVAST}
  Do Not Expect Symbol  AVAST_VIRUS
  [Teardown]  Terminate Process  ${process}

AVAST HIT
  ${process} =  Run Dummy Avast  ${RSPAMD_PORT_AVAST}  1
  Scan File  ${MESSAGE2}
  ...  Settings=${SETTINGS_AVAST}
  Expect Symbol  AVAST_VIRUS
  Do Not Expect Symbol  AVAST_VIRUS_FAIL
  [Teardown]  Terminate Process  ${process}

AVAST CACHE HIT
  Scan File  ${MESSAGE2}
  ...  Settings=${SETTINGS_AVAST}
  Expect Symbol  AVAST_VIRUS
  Do Not Expect Symbol  AVAST_VIRUS_FAIL

AVAST CACHE MISS
  Scan File  ${MESSAGE}
  ...  Settings=${SETTINGS_AVAST}
  Do Not Expect Symbol  AVAST_VIRUS
  Do Not Expect Symbol  AVAST_VIRUS_FAIL

FPROT ERROR REPLY
  [Documentation]  A reply that is not a verdict is a failed scan, not a clean message
  ${process} =  Run Dummy Fprot  ${RSPAMD_PORT_FPROT}  error
  Scan File  ${MESSAGE3}
  ...  Settings=${SETTINGS_FPROT_FAIL}
  Expect Symbol  FPROT_VIRUS_FAIL
  Do Not Expect Symbol  FPROT_VIRUS
  [Teardown]  Terminate Process  ${process}

AVAST GARBAGE BANNER
  [Documentation]  A greeting without the 220 banner is a failed scan
  ${process} =  Run Dummy Avast  ${RSPAMD_PORT_AVAST}  banner
  Scan File  ${MESSAGE3}
  ...  Settings=${SETTINGS_AVAST_FAIL}
  Expect Symbol  AVAST_VIRUS_FAIL
  Do Not Expect Symbol  AVAST_VIRUS
  [Teardown]  Terminate Process  ${process}

SAVAPI CLEAN
  ${process} =  Run Dummy Savapi  ${RSPAMD_PORT_SAVAPI}  clean
  Scan File  ${MESSAGE_B}
  ...  Settings=${SETTINGS_SAVAPI}
  Do Not Expect Symbol  SAVAPI_VIRUS
  Do Not Expect Symbol  SAVAPI_VIRUS_FAIL
  [Teardown]  Terminate Process  ${process}

SAVAPI INFECTED STATUS DIGITS IN FILE NAME
  [Documentation]  200 or 210 inside a file name of a 310 line is not a clean status
  ${process} =  Run Dummy Savapi  ${RSPAMD_PORT_SAVAPI}  infected
  Scan File  ${MESSAGE_C}
  ...  Settings=${SETTINGS_SAVAPI}
  Expect Symbol With Exact Options  SAVAPI_VIRUS  Eicar-Repairable  Eicar-Test-File
  Do Not Expect Symbol  SAVAPI_VIRUS_FAIL
  [Teardown]  Terminate Process  ${process}

SAVAPI REPAIRABLE ALERT ONLY
  [Documentation]  420 is an alert like 310: a 420 line before the final 319 is an infection
  ${process} =  Run Dummy Savapi  ${RSPAMD_PORT_SAVAPI}  repair
  Scan File  ${MESSAGE_D}
  ...  Settings=${SETTINGS_SAVAPI}
  Expect Symbol With Exact Options  SAVAPI_VIRUS  Eicar-Repairable
  Do Not Expect Symbol  SAVAPI_VIRUS_FAIL
  [Teardown]  Terminate Process  ${process}

SAVAPI INFECTED CACHE HIT
  Scan File  ${MESSAGE_C}
  ...  Settings=${SETTINGS_SAVAPI}
  Expect Symbol  SAVAPI_VIRUS

SAVAPI GARBAGE GREETING
  ${process} =  Run Dummy Savapi  ${RSPAMD_PORT_SAVAPI}  banner
  Scan File  ${MESSAGE_E}
  ...  Settings=${SETTINGS_SAVAPI}
  Expect Symbol  SAVAPI_VIRUS_FAIL
  Do Not Expect Symbol  SAVAPI_VIRUS
  [Teardown]  Terminate Process  ${process}

SPAMD CLEAN
  ${process} =  Run Dummy Spamd  ${RSPAMD_PORT_SPAMD}  clean
  Scan File  ${MESSAGE_B}
  ...  Settings=${SETTINGS_SPAMD}
  Do Not Expect Symbol  SPAMD_TEST
  Do Not Expect Symbol  SPAMD_TEST_FAIL
  [Teardown]  Terminate Process  ${process}

SPAMD SPAM REPLY IN TWO CHUNKS
  [Documentation]  The status line arrives after the first chunk of the reply
  ${process} =  Run Dummy Spamd  ${RSPAMD_PORT_SPAMD}  spam
  Scan File  ${MESSAGE_C}
  ...  Settings=${SETTINGS_SPAMD}
  Expect Symbol With Exact Options  SPAMD_TEST  FOO_BAR,BAZ_QUX
  Do Not Expect Symbol  SPAMD_TEST_FAIL
  [Teardown]  Terminate Process  ${process}

SPAMD ERROR REPLY
  [Documentation]  An error reply is a failed scan and is not cached as a clean result
  ${process} =  Run Dummy Spamd  ${RSPAMD_PORT_SPAMD}  error
  Scan File  ${MESSAGE_D}
  ...  Settings=${SETTINGS_SPAMD}
  Expect Symbol  SPAMD_TEST_FAIL
  Do Not Expect Symbol  SPAMD_TEST
  [Teardown]  Terminate Process  ${process}

SPAMD ERROR REPLY IS NOT CACHED
  ${process} =  Run Dummy Spamd  ${RSPAMD_PORT_SPAMD}  spam
  Scan File  ${MESSAGE_D}
  ...  Settings=${SETTINGS_SPAMD}
  Expect Symbol  SPAMD_TEST
  Do Not Expect Symbol  SPAMD_TEST_FAIL
  [Teardown]  Terminate Process  ${process}

SPAMD REPLY WITHOUT STATUS HEADER
  [Documentation]  A reply without X-Spam-Status is a failed scan, not a clean message
  ${process} =  Run Dummy Spamd  ${RSPAMD_PORT_SPAMD}  nostatus
  Scan File  ${MESSAGE_E}
  ...  Settings=${SETTINGS_SPAMD}
  Expect Symbol  SPAMD_TEST_FAIL
  Do Not Expect Symbol  SPAMD_TEST
  [Teardown]  Terminate Process  ${process}

CONNECT ERRORS CALL NO BOGUS CALLBACK
  [Documentation]  The scanners above were refused connections: the connect marker in the handlers queue of
  ...              a TCP connection has no Lua callback and must not be treated as a handler that has one
  # The log of the merged suite holds bytes that are not valid UTF-8
  ${log} =  Get File  ${RSPAMD_TMPDIR}/rspamd.log  encoding_errors=ignore
  Should Contain  ${log}  Connection refused
  Should Not Contain  ${log}  lua_tcp_push_error: callback call failed: attempt to call a

*** Keywords ***
Double FProt Teardown
  [Arguments]  ${process1}  ${process2}
  Terminate Process  ${process1}
  Terminate Process  ${process2}

Run Dummy Clam
  [Arguments]  ${port}  ${found}=  ${pid}=${RSPAMD_TMP_PREFIX}/dummy_clamav-${port}.pid
  ${log} =  Set Variable  ${RSPAMD_TMP_PREFIX}/dummy_clamav-${port}.log
  ${process} =  Start Dummy Service  dummy_clam.py  ${pid}  ${log}
  ...  ${RSPAMD_TESTDIR}/util/dummy_clam.py  ${port}  ${found}  ${pid}
  RETURN    ${process}

Run Dummy Fprot
  [Arguments]  ${port}  ${found}=  ${pid}=${RSPAMD_TMP_PREFIX}/dummy_fprot-${port}.pid
  ${log} =  Set Variable  ${RSPAMD_TMP_PREFIX}/dummy_fprot-${port}.log
  ${process} =  Start Dummy Service  dummy_fprot.py  ${pid}  ${log}
  ...  ${RSPAMD_TESTDIR}/util/dummy_fprot.py  ${port}  ${found}  ${pid}
  RETURN    ${process}

Run Dummy Avast
  [Arguments]  ${port}  ${found}=  ${pid}=${RSPAMD_TMP_PREFIX}/dummy_avast-${port}.pid
  ${log} =  Set Variable  ${RSPAMD_TMP_PREFIX}/dummy_avast-${port}.log
  ${process} =  Start Dummy Service  dummy_avast.py  ${pid}  ${log}
  ...  ${RSPAMD_TESTDIR}/util/dummy_avast.py  ${port}  ${found}  ${pid}
  RETURN    ${process}

Run Dummy Savapi
  [Arguments]  ${port}  ${mode}  ${pid}=${RSPAMD_TMP_PREFIX}/dummy_savapi-${port}.pid
  ${log} =  Set Variable  ${RSPAMD_TMP_PREFIX}/dummy_savapi-${port}.log
  ${process} =  Start Dummy Service  dummy_scan_savapi.py  ${pid}  ${log}
  ...  ${RSPAMD_TESTDIR}/util/dummy_scan_savapi.py  ${port}  ${mode}  ${pid}
  RETURN    ${process}

Run Dummy Spamd
  [Arguments]  ${port}  ${mode}  ${pid}=${RSPAMD_TMP_PREFIX}/dummy_spamd-${port}.pid
  ${log} =  Set Variable  ${RSPAMD_TMP_PREFIX}/dummy_spamd-${port}.log
  ${process} =  Start Dummy Service  dummy_scan_spamd.py  ${pid}  ${log}
  ...  ${RSPAMD_TESTDIR}/util/dummy_scan_spamd.py  ${port}  ${mode}  ${pid}
  RETURN    ${process}
