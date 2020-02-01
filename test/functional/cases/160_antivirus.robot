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
  ${result} =  Scan Message With Rspamc  ${MESSAGE}
  Check Rspamc  ${result}  CLAM_VIRUS  inverse=1
  Shutdown clamav

CLAMAV HIT
  Run Dummy Clam  ${PORT_CLAM}  1
  ${result} =  Scan Message With Rspamc  ${MESSAGE2}
  Check Rspamc  ${result}  CLAM_VIRUS
  Should Not Contain  ${result.stdout}  CLAMAV_VIRUS_FAIL
  Shutdown clamav

CLAMAV CACHE HIT
  ${result} =  Scan Message With Rspamc  ${MESSAGE2}
  Check Rspamc  ${result}  CLAM_VIRUS
  Should Not Contain  ${result.stdout}  CLAMAV_VIRUS_FAIL

CLAMAV CACHE MISS
  ${result} =  Scan Message With Rspamc  ${MESSAGE}
  Check Rspamc  ${result}  CLAM_VIRUS  inverse=1
  Should Not Contain  ${result.stdout}  CLAMAV_VIRUS_FAIL

FPROT MISS
  Run Dummy Fprot  ${PORT_FPROT}
  ${result} =  Scan Message With Rspamc  ${MESSAGE2}
  Check Rspamc  ${result}  FPROT_VIRUS  inverse=1
  Should Not Contain  ${result.stdout}  FPROT_EICAR
  Shutdown fport

FPROT HIT - PATTERN
  Run Dummy Fprot  ${PORT_FPROT}  1
  Run Dummy Fprot  ${PORT_FPROT2_DUPLICATE}  1  /tmp/dummy_fprot_dupe.pid
  ${result} =  Scan Message With Rspamc  ${MESSAGE}
  Check Rspamc  ${result}  FPROT_EICAR
  Should Not Contain  ${result.stdout}  CLAMAV_VIRUS
  # Also check ordered pattern match
  Should Contain  ${result.stdout}  FPROT2_VIRUS_DUPLICATE_PATTERN
  Should Not Contain  ${result.stdout}  FPROT2_VIRUS_DUPLICATE_DEFAULT
  Should Not Contain  ${result.stdout}  FPROT2_VIRUS_DUPLICATE_NOPE
  Shutdown fport
  Shutdown fport duplicate

FPROT CACHE HIT
  ${result} =  Scan Message With Rspamc  ${MESSAGE}
  Check Rspamc  ${result}  FPROT_EICAR
  Should Not Contain  ${result.stdout}  CLAMAV_VIRUS
  # Also check ordered pattern match
  Should Contain  ${result.stdout}  FPROT2_VIRUS_DUPLICATE_PATTERN
  Should Not Contain  ${result.stdout}  FPROT2_VIRUS_DUPLICATE_DEFAULT

FPROT CACHE MISS
  ${result} =  Scan Message With Rspamc  ${MESSAGE2}
  Check Rspamc  ${result}  FPROT_VIRUS  inverse=1

AVAST MISS
  Run Dummy Avast  ${PORT_AVAST}
  ${result} =  Scan Message With Rspamc  ${MESSAGE}
  Check Rspamc  ${result}  AVAST_VIRUS  inverse=1
  Shutdown avast

AVAST HIT
  Run Dummy Avast  ${PORT_AVAST}  1
  ${result} =  Scan Message With Rspamc  ${MESSAGE2}
  Check Rspamc  ${result}  AVAST_VIRUS
  Should Not Contain  ${result.stdout}  AVAST_VIRUS_FAIL
  Shutdown avast

AVAST CACHE HIT
  ${result} =  Scan Message With Rspamc  ${MESSAGE2}
  Check Rspamc  ${result}  AVAST_VIRUS
  Should Not Contain  ${result.stdout}  AVAST_VIRUS_FAIL

AVAST CACHE MISS
  ${result} =  Scan Message With Rspamc  ${MESSAGE}
  Check Rspamc  ${result}  AVAST_VIRUS  inverse=1
  Should Not Contain  ${result.stdout}  AVAST_VIRUS_FAIL

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

Run Dummy Clam
  [Arguments]  ${port}  ${found}=
  ${result} =  Start Process  ${TESTDIR}/util/dummy_clam.py  ${port}  ${found}
  Wait Until Created  /tmp/dummy_clamav.pid

Run Dummy Fprot
  [Arguments]  ${port}  ${found}=  ${pid}=/tmp/dummy_fprot.pid
  Start Process  ${TESTDIR}/util/dummy_fprot.py  ${port}  ${found}  ${pid}
  Wait Until Created  ${pid}

Run Dummy Avast
  [Arguments]  ${port}  ${found}=
  ${result} =  Start Process  ${TESTDIR}/util/dummy_avast.py  ${port}  ${found}
  Wait Until Created  /tmp/dummy_avast.pid
