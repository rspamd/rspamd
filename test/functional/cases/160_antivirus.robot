*** Settings ***
Suite Setup     Antivirus Setup
Suite Teardown  Antivirus Teardown
Library         Process
Library         ${TESTDIR}/lib/rspamd.py
Resource        ${TESTDIR}/lib/rspamd.robot
Variables       ${TESTDIR}/lib/vars.py

*** Variables ***
${CONFIG}       ${TESTDIR}/configs/plugins.conf
${MESSAGE}      ${TESTDIR}/messages/spam_message.eml
${MESSAGE2}     ${TESTDIR}/messages/freemail.eml
${REDIS_SCOPE}  Suite
${RSPAMD_SCOPE}  Suite
${URL_TLD}      ${TESTDIR}/../lua/unit/test_tld.dat

*** Test Cases ***
CLAMAV MISS
  Run Dummy Clam  ${PORT_CLAM}
  Scan File  ${MESSAGE}
  Do Not Expect Symbol  CLAM_VIRUS
  Shutdown clamav

CLAMAV HIT
  Run Dummy Clam  ${PORT_CLAM}  1
  Scan File  ${MESSAGE2}
  Expect Symbol  CLAM_VIRUS
  Do Not Expect Symbol  CLAMAV_VIRUS_FAIL
  Shutdown clamav

CLAMAV CACHE HIT
  Scan File  ${MESSAGE2}
  Expect Symbol  CLAM_VIRUS
  Do Not Expect Symbol  CLAMAV_VIRUS_FAIL

CLAMAV CACHE MISS
  Scan File  ${MESSAGE}
  Do Not Expect Symbol  CLAM_VIRUS
  Do Not Expect Symbol  CLAMAV_VIRUS_FAIL

FPROT MISS
  Run Dummy Fprot  ${PORT_FPROT}
  Scan File  ${MESSAGE2}
  Do Not Expect Symbol  FPROT_VIRUS
  Do Not Expect Symbol  FPROT_EICAR
  Shutdown fport

FPROT HIT - PATTERN
  Run Dummy Fprot  ${PORT_FPROT}  1
  Run Dummy Fprot  ${PORT_FPROT2_DUPLICATE}  1  /tmp/dummy_fprot_dupe.pid
  Scan File  ${MESSAGE}
  Expect Symbol  FPROT_EICAR
  Do Not Expect Symbol  CLAMAV_VIRUS
  # Also check ordered pattern match
  Expect Symbol  FPROT2_VIRUS_DUPLICATE_PATTERN
  Do Not Expect Symbol  FPROT2_VIRUS_DUPLICATE_DEFAULT
  Do Not Expect Symbol  FPROT2_VIRUS_DUPLICATE_NOPE
  Shutdown fport
  Shutdown fport duplicate

FPROT CACHE HIT
  Scan File  ${MESSAGE}
  Expect Symbol  FPROT_EICAR
  Do Not Expect Symbol  CLAMAV_VIRUS
  # Also check ordered pattern match
  Expect Symbol  FPROT2_VIRUS_DUPLICATE_PATTERN
  Do Not Expect Symbol  FPROT2_VIRUS_DUPLICATE_DEFAULT

FPROT CACHE MISS
  Scan File  ${MESSAGE2}
  Do Not Expect Symbol  FPROT_VIRUS

AVAST MISS
  Run Dummy Avast  ${PORT_AVAST}
  Scan File  ${MESSAGE}
  Do Not Expect Symbol  AVAST_VIRUS
  Shutdown avast

AVAST HIT
  Run Dummy Avast  ${PORT_AVAST}  1
  Scan File  ${MESSAGE2}
  Expect Symbol  AVAST_VIRUS
  Do Not Expect Symbol  AVAST_VIRUS_FAIL
  Shutdown avast

AVAST CACHE HIT
  Scan File  ${MESSAGE2}
  Expect Symbol  AVAST_VIRUS
  Do Not Expect Symbol  AVAST_VIRUS_FAIL

AVAST CACHE MISS
  Scan File  ${MESSAGE}
  Do Not Expect Symbol  AVAST_VIRUS
  Do Not Expect Symbol  AVAST_VIRUS_FAIL

*** Keywords ***
Antivirus Setup
  ${PLUGIN_CONFIG} =  Get File  ${TESTDIR}/configs/antivirus.conf
  Set Suite Variable  ${PLUGIN_CONFIG}
  Generic Setup  PLUGIN_CONFIG
  Run Redis

Antivirus Teardown
  Normal Teardown
  Shutdown Process With Children  ${REDIS_PID}
  Shutdown clamav
  Shutdown fport
  Shutdown avast
  Terminate All Processes    kill=True

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
  Run Dummy  ${TESTDIR}/util/dummy_clam.py  ${port}  ${found}  ${pid}

Run Dummy Fprot
  [Arguments]  ${port}  ${found}=  ${pid}=/tmp/dummy_fprot.pid
  Run Dummy  ${TESTDIR}/util/dummy_fprot.py  ${port}  ${found}  ${pid}

Run Dummy Avast
  [Arguments]  ${port}  ${found}=  ${pid}=/tmp/dummy_avast.pid
  Run Dummy  ${TESTDIR}/util/dummy_avast.py  ${port}  ${found}  ${pid}
