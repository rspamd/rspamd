*** Settings ***
Suite Setup     Replication Setup
Suite Teardown  Replication Teardown
Resource        lib.robot
Library         ${TESTDIR}/lib/rspamd.py
Resource        ${TESTDIR}/lib/rspamd.robot
Variables       ${TESTDIR}/lib/vars.py

*** Variables ***
${MESSAGE}      @{MESSAGES}[0]

*** Test Cases ***
Fuzzy Add And Check
  Set Suite Variable  ${RSPAMD_FUZZY_ADD_${MESSAGE}}  0
  ${result} =  Run Rspamc  -h  ${LOCAL_ADDR}:${PORT_CONTROLLER}  -w  10  -f
  ...  ${FLAG1_NUMBER}  fuzzy_add  ${MESSAGE}
  Custom Follow Rspamd Log  ${MASTER_TMPDIR}/rspamd.log  ${MASTER_LOGPOS}  MASTER_LOGPOS  Suite
  Custom Follow Rspamd Log  ${SLAVE_TMPDIR}/rspamd.log  ${SLAVE_LOGPOS}  SLAVE_LOGPOS  Suite
  Run Keyword If  ${result.rc} != 0  Log  ${result.stderr}
  Should Contain  ${result.stdout}  success = true
  Should Be Equal As Integers  ${result.rc}  0
  Sync Fuzzy Storage  ${MASTER_TMPDIR}  ${MASTER_LOGPOS}  MASTER_LOGPOS  Suite
  Sync Fuzzy Storage  ${SLAVE_TMPDIR}  ${SLAVE_LOGPOS}  SLAVE_LOGPOS  Suite
  ${result} =  Scan Message With Rspamc  ${MESSAGE}
  Custom Follow Rspamd Log  ${MASTER_TMPDIR}/rspamd.log  ${MASTER_LOGPOS}  MASTER_LOGPOS  Suite
  Custom Follow Rspamd Log  ${SLAVE_TMPDIR}/rspamd.log  ${SLAVE_LOGPOS}  SLAVE_LOGPOS  Suite
  Run Keyword If  ${result.rc} != 0  Log  ${result.stderr}
  Should Contain  ${result.stdout}  ${FLAG1_SYMBOL}
  Should Be Equal As Integers  ${result.rc}  0
  Set Suite Variable  ${RSPAMD_FUZZY_ADD_${MESSAGE}}  1

Fuzzy Check Slave
  Run Keyword If  ${RSPAMD_FUZZY_ADD_${MESSAGE}} == 0  Fail  "Fuzzy Add was not run"
  ${result} =  Run Rspamc  -h  ${LOCAL_ADDR}:${PORT_NORMAL_SLAVE}  ${MESSAGE}
  Custom Follow Rspamd Log  ${SLAVE_TMPDIR}/rspamd.log  ${SLAVE_LOGPOS}  SLAVE_LOGPOS  Suite
  Run Keyword If  ${result.rc} != 0  Log  ${result.stderr}
  Should Contain  ${result.stdout}  ${FLAG1_SYMBOL}
  Should Be Equal As Integers  ${result.rc}  0

*** Keywords ***
Replication Setup
  ${tmp_fuzzy} =  Set Variable  ${PORT_FUZZY}
  ${tmp_normal} =  Set Variable  ${PORT_NORMAL}
  ${tmp_controller} =  Set Variable  ${PORT_CONTROLLER}
  Set Suite Variable  ${PORT_FUZZY}  ${PORT_FUZZY_SLAVE}
  Set Suite Variable  ${PORT_NORMAL}  ${PORT_NORMAL_SLAVE}
  Set Suite Variable  ${PORT_CONTROLLER}  ${PORT_CONTROLLER_SLAVE}
  ${algorithm} =  Set Variable  mumhash
  ${worker_settings_tmpl} =  Get File  ${TESTDIR}/configs/fuzzy_slave_worker.conf
  ${worker_settings} =  Replace Variables  ${worker_settings_tmpl}
  ${tmp_include1} =  Make Temporary File
  Set Suite Variable  ${TMP_INCLUDE1}  ${tmp_include1}
  Create File  ${tmp_include1}  ${worker_settings}
  ${worker_settings} =  Set Variable  .include ${tmp_include1}
  ${check_settings} =  Set Variable  ${EMPTY}
  Set Suite Variable  ${SETTINGS_FUZZY_WORKER}  ${worker_settings}
  Set Suite Variable  ${SETTINGS_FUZZY_CHECK}  ${check_settings}
  Set Suite Variable  ${ALGORITHM}  ${algorithm}
  &{d} =  Run Rspamd  CONFIG=${TESTDIR}/configs/fuzzy.conf
  Set Suite Variable  ${SLAVE_LOGPOS}  &{d}[RSPAMD_LOGPOS]
  Set Suite Variable  ${SLAVE_PID}  &{d}[RSPAMD_PID]
  Set Suite Variable  ${SLAVE_TMPDIR}  &{d}[TMPDIR]
  Set Suite Variable  ${PORT_FUZZY}  ${tmp_fuzzy}
  Set Suite Variable  ${PORT_NORMAL}  ${tmp_normal}
  Set Suite Variable  ${PORT_CONTROLLER}  ${tmp_controller}
  ${worker_settings_tmpl} =  Get File  ${TESTDIR}/configs/fuzzy_master_worker.conf
  ${worker_settings} =  Replace Variables  ${worker_settings_tmpl}
  ${tmp_include2} =  Make Temporary File
  Set Suite Variable  ${TMP_INCLUDE2}  ${tmp_include2}
  Create File  ${tmp_include2}  ${worker_settings}
  ${worker_settings} =  Set Variable  .include ${tmp_include2}
  Set Suite Variable  ${SETTINGS_FUZZY_WORKER}  ${worker_settings}
  &{d} =  Run Rspamd  CONFIG=${TESTDIR}/configs/fuzzy.conf
  Set Suite Variable  ${MASTER_LOGPOS}  &{d}[RSPAMD_LOGPOS]
  Set Suite Variable  ${MASTER_PID}  &{d}[RSPAMD_PID]
  Set Suite Variable  ${MASTER_TMPDIR}  &{d}[TMPDIR]

Replication Teardown
  Shutdown Process With Children  ${MASTER_PID}
  Shutdown Process With Children  ${SLAVE_PID}
  Cleanup Temporary Directory  ${MASTER_TMPDIR}
  Cleanup Temporary Directory  ${SLAVE_TMPDIR}
  Remove File  ${TMP_INCLUDE1}
  Remove File  ${TMP_INCLUDE2}
