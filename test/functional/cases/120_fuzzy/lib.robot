*** Settings ***
Library         OperatingSystem
Library         ${TESTDIR}/lib/rspamd.py
Resource        ${TESTDIR}/lib/rspamd.robot
Variables       ${TESTDIR}/lib/vars.py

*** Variables ***
${ALGORITHM}    ${EMPTY}
${CONFIG}       ${TESTDIR}/configs/fuzzy.conf
${FLAG1_NUMBER}  50
${FLAG1_SYMBOL}  R_TEST_FUZZY_DENIED
${FLAG2_NUMBER}  51
${FLAG2_SYMBOL}  R_TEST_FUZZY_WHITE
@{MESSAGES}      ${TESTDIR}/messages/spam_message.eml  ${TESTDIR}/messages/zip.eml
@{MESSAGES_SKIP}  ${TESTDIR}/messages/priority.eml
@{RANDOM_MESSAGES}  ${TESTDIR}/messages/bad_message.eml  ${TESTDIR}/messages/zip-doublebad.eml
${REDIS_SCOPE}  Suite
${RSPAMD_SCOPE}  Suite
${SETTINGS_FUZZY_WORKER}  ${EMPTY}
${SETTINGS_FUZZY_CHECK}  ${EMPTY}

*** Keywords ***
Fuzzy Skip Add Test Base
  [Arguments]  ${message}
  Set Suite Variable  ${RSPAMD_FUZZY_ADD_${message}}  0
  ${result} =  Run Rspamc  -h  ${LOCAL_ADDR}:${PORT_CONTROLLER}  -w  10  -f
  ...  ${FLAG1_NUMBER}  fuzzy_add  ${message}
  Check Rspamc  ${result}
  Sync Fuzzy Storage
  Scan File  ${message}
  Expect Symbol  R_TEST_FUZZY_DENIED
  Create File  ${TMPDIR}/skip_hash.map.tmp  2d875d4737c59c4822fd01dadeba52a329de3933f766c6f167904c6a426bbfa7ea63a66bf807b25c5ee853baee58bfb18d3b423fcd13cfa7c3d77a840039a1ea
  Move File  ${TMPDIR}/skip_hash.map.tmp  ${TMPDIR}/skip_hash.map
  Sleep  1s  Wait for reload
  Scan File  ${message}
  Do Not Expect Symbol  R_TEST_FUZZY_DENIED

Fuzzy Add Test
  [Arguments]  ${message}
  Set Suite Variable  ${RSPAMD_FUZZY_ADD_${message}}  0
  ${result} =  Run Rspamc  -h  ${LOCAL_ADDR}:${PORT_CONTROLLER}  -w  10  -f
  ...  ${FLAG1_NUMBER}  fuzzy_add  ${message}
  Check Rspamc  ${result}
  Sync Fuzzy Storage
  Scan File  ${message}
  Expect Symbol  ${FLAG1_SYMBOL}
  Set Suite Variable  ${RSPAMD_FUZZY_ADD_${message}}  1

Fuzzy Delete Test
  [Arguments]  ${message}
  Run Keyword If  ${RSPAMD_FUZZY_ADD_${message}} == 0  Fail  "Fuzzy Add was not run"
  ${result} =  Run Rspamc  -h  ${LOCAL_ADDR}:${PORT_CONTROLLER}  -f  ${FLAG1_NUMBER}  fuzzy_del
  ...  ${message}
  Check Rspamc  ${result}
  Sync Fuzzy Storage
  Scan File  ${message}
  Do Not Expect Symbol  ${FLAG1_SYMBOL}

Fuzzy Fuzzy Test
  [Arguments]  ${message}
  Run Keyword If  ${RSPAMD_FUZZY_ADD_${message}} != 1  Fail  "Fuzzy Add was not run"
  @{path_info} =  Path Splitter  ${message}
  @{fuzzy_files} =  List Files In Directory  ${pathinfo}[0]  pattern=${pathinfo}[1].fuzzy*  absolute=1
  FOR  ${i}  IN  @{fuzzy_files}
    Scan File  ${i}
    Expect Symbol  ${FLAG1_SYMBOL}
  END

Fuzzy Miss Test
  [Arguments]  ${message}
  Scan File  ${message}
  Do Not Expect Symbol  ${FLAG1_SYMBOL}

Fuzzy Overwrite Test
  [Arguments]  ${message}
  ${flag_numbers} =  Create List  ${FLAG1_NUMBER}  ${FLAG2_NUMBER}
  FOR  ${i}  IN  @{flag_numbers}
    ${result} =  Run Rspamc  -h  ${LOCAL_ADDR}:${PORT_CONTROLLER}  -w  10
    ...  -f  ${i}  fuzzy_add  ${message}
    Check Rspamc  ${result}
  END
  Sync Fuzzy Storage
  Scan File  ${message}
  Do Not Expect Symbol  ${FLAG1_SYMBOL}
  Expect Symbol  ${FLAG2_SYMBOL}

Fuzzy Setup Encrypted
  [Arguments]  ${algorithm}
  ${worker_settings} =  Set Variable  "keypair": {"pubkey": "${KEY_PUB1}", "privkey": "${KEY_PVT1}"}; "encrypted_only": true;
  ${check_settings} =  Set Variable  encryption_key = "${KEY_PUB1}";
  Fuzzy Setup Generic  ${algorithm}  ${worker_settings}  ${check_settings}

Fuzzy Setup Encrypted Keyed
  [Arguments]  ${algorithm}
  ${worker_settings} =  Set Variable  "keypair": {"pubkey": "${KEY_PUB1}", "privkey": "${KEY_PVT1}"}; "encrypted_only": true;
  ${check_settings} =  Set Variable  fuzzy_key = "mYN888sydwLTfE32g2hN"; fuzzy_shingles_key = "hXUCgul9yYY3Zlk1QIT2"; encryption_key = "${KEY_PUB1}";
  Fuzzy Setup Generic  ${algorithm}  ${worker_settings}  ${check_settings}

Fuzzy Setup Plain
  [Arguments]  ${algorithm}
  Fuzzy Setup Generic  ${algorithm}  ${EMPTY}  ${EMPTY}

Fuzzy Setup Keyed
  [Arguments]  ${algorithm}
  ${check_settings} =  Set Variable  fuzzy_key = "mYN888sydwLTfE32g2hN"; fuzzy_shingles_key = "hXUCgul9yYY3Zlk1QIT2";
  Fuzzy Setup Generic  ${algorithm}  ${EMPTY}  ${check_settings}

Fuzzy Setup Generic
  [Arguments]  ${algorithm}  ${worker_settings}  ${check_settings}  &{kwargs}
  ${worker_settings} =  Set Variable  backend \= "redis"; ${worker_settings}
  ${tmpdir} =  Make Temporary Directory
  Set Suite Variable  ${TMPDIR}  ${tmpdir}
  Set Suite Variable  ${SETTINGS_FUZZY_WORKER}  ${worker_settings}
  Set Suite Variable  ${SETTINGS_FUZZY_CHECK}  ${check_settings}
  Run Redis
  Generic Setup  TMPDIR=${TMPDIR}

Fuzzy Setup Plain Fasthash
  Fuzzy Setup Plain  fasthash

Fuzzy Setup Plain Mumhash
  Fuzzy Setup Plain  mumhash

Fuzzy Setup Plain Siphash
  Fuzzy Setup Plain  siphash

Fuzzy Setup Plain Xxhash
  Fuzzy Setup Plain  xxhash

Fuzzy Setup Keyed Fasthash
  Fuzzy Setup Keyed  fasthash

Fuzzy Setup Keyed Mumhash
  Fuzzy Setup Keyed  mumhash

Fuzzy Setup Keyed Siphash
  Fuzzy Setup Keyed  siphash

Fuzzy Setup Keyed Xxhash
  Fuzzy Setup Keyed  xxhash

Fuzzy Setup Encrypted Siphash
  Fuzzy Setup Encrypted  siphash

Fuzzy Skip Hash Test Message
  FOR  ${i}  IN  @{MESSAGES_SKIP}
    Fuzzy Skip Add Test Base  ${i}
  END

Fuzzy Multimessage Add Test
  FOR  ${i}  IN  @{MESSAGES}
    Fuzzy Add Test  ${i}
  END

Fuzzy Multimessage Fuzzy Test
  FOR  ${i}  IN  @{MESSAGES}
    Fuzzy Fuzzy Test  ${i}
  END

Fuzzy Multimessage Miss Test
  FOR  ${i}  IN  @{RANDOM_MESSAGES}
    Fuzzy Miss Test  ${i}
  END

Fuzzy Multimessage Delete Test
  FOR  ${i}  IN  @{MESSAGES}
    Fuzzy Delete Test  ${i}
  END

Fuzzy Multimessage Overwrite Test
  FOR  ${i}  IN  @{MESSAGES}
    Fuzzy Overwrite Test  ${i}
  END

Fuzzy Teardown
  Normal Teardown
  Shutdown Process With Children  ${REDIS_PID}
