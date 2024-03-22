*** Settings ***
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

FPROT MISS
  ${process} =  Run Dummy Fprot  ${RSPAMD_PORT_FPROT}
  Scan File  ${MESSAGE2}
  ...  Settings=${SETTINGS_FPROT}
  Do Not Expect Symbol  FPROT_VIRUS
  Do Not Expect Symbol  FPROT_EICAR
  [Teardown]  Terminate Process  ${process}

FPROT HIT - PATTERN
  ${process1} =  Run Dummy Fprot  ${RSPAMD_PORT_FPROT}  1
  ${process2} =  Run Dummy Fprot  ${RSPAMD_PORT_FPROT2_DUPLICATE}  1  /tmp/dummy_fprot_dupe.pid
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

*** Keywords ***
Double FProt Teardown
  [Arguments]  ${process1}  ${process2}
  Terminate Process  ${process1}
  Terminate Process  ${process2}

Run Dummy
  [Arguments]  @{varargs}
  ${process} =  Start Process  @{varargs}
  ${pid} =  Get From List  ${varargs}  -1
  ${pass} =  Run Keyword And Return Status  Wait Until Created  ${pid}
  IF  ${pass}
    Return From Keyword
  END
  Wait For Process  ${process}
  ${res} =  Get Process Result  ${process}
  Log To Console  ${res.stdout}
  Log To Console  ${res.stderr}
  Fail  Dummy server failed to start
  [Return]  ${process}

Run Dummy Clam
  [Arguments]  ${port}  ${found}=  ${pid}=/tmp/dummy_clamav.pid
  ${process} =  Run Dummy  ${RSPAMD_TESTDIR}/util/dummy_clam.py  ${port}  ${found}  ${pid}
  [Return]  ${process}

Run Dummy Fprot
  [Arguments]  ${port}  ${found}=  ${pid}=/tmp/dummy_fprot.pid
  ${process} =  Run Dummy  ${RSPAMD_TESTDIR}/util/dummy_fprot.py  ${port}  ${found}  ${pid}
  [Return]  ${process}

Run Dummy Avast
  [Arguments]  ${port}  ${found}=  ${pid}=/tmp/dummy_avast.pid
  ${process} =  Run Dummy  ${RSPAMD_TESTDIR}/util/dummy_avast.py  ${port}  ${found}  ${pid}
  [Return]  ${process}
