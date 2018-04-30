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

CLAMAV HIT
  Run Dummy Clam  ${PORT_CLAM}  1
  ${result} =  Scan Message With Rspamc  ${MESSAGE2}
  Check Rspamc  ${result}  CLAM_VIRUS (1.00)[Eicar-Test-Signature]
  Should Not Contain  ${result.stdout}  CLAMAV_FAIL

CLAMAV CACHE HIT
  ${result} =  Scan Message With Rspamc  ${MESSAGE2}
  Check Rspamc  ${result}  CLAM_VIRUS (1.00)[Eicar-Test-Signature]
  Should Not Contain  ${result.stdout}  CLAMAV_FAIL

CLAMAV CACHE MISS
  ${result} =  Scan Message With Rspamc  ${MESSAGE}
  Check Rspamc  ${result}  CLAM_VIRUS  inverse=1
  Should Not Contain  ${result.stdout}  CLAMAV_FAIL

FPROT MISS
  Run Dummy Fprot  ${PORT_FPROT}
  ${result} =  Scan Message With Rspamc  ${MESSAGE2}
  Check Rspamc  ${result}  FPROT_VIRUS  inverse=1
  Should Not Contain  ${result.stdout}  FPROT_EICAR

FPROT HIT - PATTERN
  Run Dummy Fprot  ${PORT_FPROT}  1
  Run Dummy Fprot  ${PORT_FPROT_DUPLICATE}  1  /tmp/dummy_fprot_dupe.pid
  ${result} =  Scan Message With Rspamc  ${MESSAGE}
  Check Rspamc  ${result}  FPROT_EICAR (1.00)[EICAR_Test_File]
  Should Not Contain  ${result.stdout}  CLAMAV_VIRUS
  # Also check ordered pattern match
  Should Contain  ${result.stdout}  FPROT_VIRUS_DUPLICATE_PATTERN
  Should Not Contain  ${result.stdout}  FPROT_VIRUS_DUPLICATE_DEFAULT
  Should Not Contain  ${result.stdout}  FPROT_VIRUS_DUPLICATE_NOPE

FPROT CACHE HIT
  ${result} =  Scan Message With Rspamc  ${MESSAGE}
  Check Rspamc  ${result}  FPROT_EICAR (1.00)[EICAR_Test_File]
  Should Not Contain  ${result.stdout}  CLAMAV_VIRUS
  # Also check ordered pattern match
  Should Contain  ${result.stdout}  FPROT_VIRUS_DUPLICATE_PATTERN
  Should Not Contain  ${result.stdout}  FPROT_VIRUS_DUPLICATE_DEFAULT

FPROT CACHE MISS
  ${result} =  Scan Message With Rspamc  ${MESSAGE2}
  Check Rspamc  ${result}  FPROT_VIRUS  inverse=1

*** Keywords ***
Antivirus Setup
  ${PLUGIN_CONFIG} =  Get File  ${TESTDIR}/configs/antivirus.conf
  Set Suite Variable  ${PLUGIN_CONFIG}
  Generic Setup  PLUGIN_CONFIG
  Run Redis

Antivirus Teardown
  Normal Teardown
  Shutdown Process With Children  ${REDIS_PID}

Run Dummy Clam
  [Arguments]  ${port}  ${found}=
  ${result} =  Start Process  ${TESTDIR}/util/dummy_clam.py  ${port}  ${found}
  Wait Until Created  /tmp/dummy_clamav.pid

Run Dummy Fprot
  [Arguments]  ${port}  ${found}=  ${pid}=/tmp/dummy_fprot.pid
  ${result} =  Start Process  ${TESTDIR}/util/dummy_fprot.py  ${port}  ${found}  ${pid}
  Wait Until Created  ${pid}
