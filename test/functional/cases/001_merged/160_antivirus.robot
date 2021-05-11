*** Settings ***
Suite Teardown  Antivirus Teardown
Library         Process
Library         ${RSPAMD_TESTDIR}/lib/rspamd.py
Resource        ${RSPAMD_TESTDIR}/lib/rspamd.robot
Variables       ${RSPAMD_TESTDIR}/lib/vars.py

*** Variables ***
${MESSAGE2}         ${RSPAMD_TESTDIR}/messages/freemail.eml
${MESSAGE}          ${RSPAMD_TESTDIR}/messages/spam_message.eml
${SETTINGS_AVAST}   {symbols_enabled = [AVAST_VIRUS]}
${SETTINGS_CLAM}    {symbols_enabled = [CLAM_VIRUS]}
${SETTINGS_FPROT}   {symbols_enabled = [FPROT_VIRUS, FPROT2_VIRUS_DUPLICATE_DEFAULT]}

*** Test Cases ***
CLAMAV MISS
  Run Dummy Clam  ${RSPAMD_PORT_CLAM}
  Scan File  ${MESSAGE}
  ...  Settings=${SETTINGS_CLAM}
  Do Not Expect Symbol  CLAM_VIRUS
  Shutdown clamav

CLAMAV HIT
  Run Dummy Clam  ${RSPAMD_PORT_CLAM}  1
  Scan File  ${MESSAGE2}
  ...  Settings=${SETTINGS_CLAM}
  Expect Symbol  CLAM_VIRUS
  Do Not Expect Symbol  CLAMAV_VIRUS_FAIL
  Shutdown clamav

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

FPROT MISS
  Run Dummy Fprot  ${RSPAMD_PORT_FPROT}
  Scan File  ${MESSAGE2}
  ...  Settings=${SETTINGS_FPROT}
  Do Not Expect Symbol  FPROT_VIRUS
  Do Not Expect Symbol  FPROT_EICAR
  Shutdown fport

FPROT HIT - PATTERN
  Run Dummy Fprot  ${RSPAMD_PORT_FPROT}  1
  Run Dummy Fprot  ${RSPAMD_PORT_FPROT2_DUPLICATE}  1  /tmp/dummy_fprot_dupe.pid
  Scan File  ${MESSAGE}
  ...  Settings=${SETTINGS_FPROT}
  Expect Symbol  FPROT_EICAR
  # Also check ordered pattern match
  Expect Symbol  FPROT2_VIRUS_DUPLICATE_PATTERN
  Do Not Expect Symbol  FPROT2_VIRUS_DUPLICATE_DEFAULT
  Do Not Expect Symbol  FPROT2_VIRUS_DUPLICATE_NOPE
  Shutdown fport
  Shutdown fport duplicate

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
  Run Dummy Avast  ${RSPAMD_PORT_AVAST}
  Scan File  ${MESSAGE}
  ...  Settings=${SETTINGS_AVAST}
  Do Not Expect Symbol  AVAST_VIRUS
  Shutdown avast

AVAST HIT
  Run Dummy Avast  ${RSPAMD_PORT_AVAST}  1
  Scan File  ${MESSAGE2}
  ...  Settings=${SETTINGS_AVAST}
  Expect Symbol  AVAST_VIRUS
  Do Not Expect Symbol  AVAST_VIRUS_FAIL
  Shutdown avast

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

*** Keywords ***
Antivirus Teardown
  Shutdown clamav
  Shutdown fport
  Shutdown avast

Shutdown clamav
  ${clamav_pid} =  Get File if exists  /tmp/dummy_clamav.pid
  Run Keyword if  ${clamav_pid}  Shutdown Process With Children  ${clamav_pid}

Shutdown fport
  ${fport_pid} =  Get File if exists  /tmp/dummy_fprot.pid
  Run Keyword if  ${fport_pid}  Shutdown Process With Children  ${fport_pid}

Shutdown fport duplicate
  ${fport_pid} =  Get File if exists  /tmp/dummy_fprot_dupe.pid
  Run Keyword if  ${fport_pid}  Shutdown Process With Children  ${fport_pid}

Shutdown avast
  ${avast_pid} =  Get File if exists  /tmp/dummy_avast.pid
  Run Keyword if  ${avast_pid}  Shutdown Process With Children  ${avast_pid}

Run Dummy
  [Arguments]  @{varargs}
  ${process} =  Start Process  @{varargs}
  ${pid} =  Get From List  ${varargs}  -1
  ${pass} =  Run Keyword And Return Status  Wait Until Created  ${pid}
  Run Keyword If  ${pass}  Return From Keyword
  Wait For Process  ${process}
  ${res} =  Get Process Result  ${process}
  Log To Console  ${res.stdout}
  Log To Console  ${res.stderr}
  Fail  Dummy server failed to start

Run Dummy Clam
  [Arguments]  ${port}  ${found}=  ${pid}=/tmp/dummy_clamav.pid
  Run Dummy  ${RSPAMD_TESTDIR}/util/dummy_clam.py  ${port}  ${found}  ${pid}

Run Dummy Fprot
  [Arguments]  ${port}  ${found}=  ${pid}=/tmp/dummy_fprot.pid
  Run Dummy  ${RSPAMD_TESTDIR}/util/dummy_fprot.py  ${port}  ${found}  ${pid}

Run Dummy Avast
  [Arguments]  ${port}  ${found}=  ${pid}=/tmp/dummy_avast.pid
  Run Dummy  ${RSPAMD_TESTDIR}/util/dummy_avast.py  ${port}  ${found}  ${pid}
