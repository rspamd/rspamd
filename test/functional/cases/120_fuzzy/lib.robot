*** Settings ***
Library         OperatingSystem
Library         ${RSPAMD_TESTDIR}/lib/rspamd.py
Resource        ${RSPAMD_TESTDIR}/lib/rspamd.robot
Variables       ${RSPAMD_TESTDIR}/lib/vars.py

*** Variables ***
${CONFIG}                       ${RSPAMD_TESTDIR}/configs/fuzzy.conf
${FLAG1_SYMBOL}                 R_TEST_FUZZY_DENIED
${FLAG2_SYMBOL}                 R_TEST_FUZZY_WHITE
${REDIS_SCOPE}                  Suite
${RSPAMD_FLAG1_NUMBER}          50
${RSPAMD_FLAG2_NUMBER}          51
${RSPAMD_FUZZY_BACKEND}         redis
${RSPAMD_FUZZY_ENCRYPTED_ONLY}  false
${RSPAMD_FUZZY_ENCRYPTION_KEY}  null
${RSPAMD_FUZZY_INCLUDE}         ${RSPAMD_TESTDIR}/configs/empty.conf
${RSPAMD_FUZZY_KEY}             null
${RSPAMD_FUZZY_SHINGLES_KEY}    null
${RSPAMD_SCOPE}                 Suite
${SETTINGS_FUZZY_CHECK}         ${EMPTY}
${SETTINGS_FUZZY_WORKER}        ${EMPTY}
@{MESSAGES_SKIP}                ${RSPAMD_TESTDIR}/messages/priority.eml
@{MESSAGES}                     ${RSPAMD_TESTDIR}/messages/spam_message.eml  ${RSPAMD_TESTDIR}/messages/zip.eml
@{RANDOM_MESSAGES}              ${RSPAMD_TESTDIR}/messages/bad_message.eml  ${RSPAMD_TESTDIR}/messages/zip-doublebad.eml

*** Keywords ***
Fuzzy Skip Add Test Base
  [Arguments]  ${message}
  Set Suite Variable  ${RSPAMD_FUZZY_ADD_${message}}  0
  ${result} =  Run Rspamc  -h  ${RSPAMD_LOCAL_ADDR}:${RSPAMD_PORT_CONTROLLER}  -w  10  -f
  ...  ${RSPAMD_FLAG1_NUMBER}  fuzzy_add  ${message}
  Check Rspamc  ${result}
  Sync Fuzzy Storage
  Scan File  ${message}
  Expect Symbol  R_TEST_FUZZY_DENIED
  Create File  ${RSPAMD_TMPDIR}/skip_hash.map.tmp  2d875d4737c59c4822fd01dadeba52a329de3933f766c6f167904c6a426bbfa7ea63a66bf807b25c5ee853baee58bfb18d3b423fcd13cfa7c3d77a840039a1ea
  Move File  ${RSPAMD_TMPDIR}/skip_hash.map.tmp  ${RSPAMD_TMPDIR}/skip_hash.map
  Sleep  1s  Wait for reload
  Scan File  ${message}
  Do Not Expect Symbol  R_TEST_FUZZY_DENIED

Fuzzy Add Test
  [Arguments]  ${message}
  Set Suite Variable  ${RSPAMD_FUZZY_ADD_${message}}  0
  ${result} =  Run Rspamc  -h  ${RSPAMD_LOCAL_ADDR}:${RSPAMD_PORT_CONTROLLER}  -w  10  -f
  ...  ${RSPAMD_FLAG1_NUMBER}  fuzzy_add  ${message}
  Check Rspamc  ${result}
  Sync Fuzzy Storage
  Scan File  ${message}
  Expect Symbol  ${FLAG1_SYMBOL}
  Set Suite Variable  ${RSPAMD_FUZZY_ADD_${message}}  1

Fuzzy Delete Test
  [Arguments]  ${message}
  Run Keyword If  ${RSPAMD_FUZZY_ADD_${message}} == 0  Fail  "Fuzzy Add was not run"
  ${result} =  Run Rspamc  -h  ${RSPAMD_LOCAL_ADDR}:${RSPAMD_PORT_CONTROLLER}  -f  ${RSPAMD_FLAG1_NUMBER}  fuzzy_del
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
  ${flag_numbers} =  Create List  ${RSPAMD_FLAG1_NUMBER}  ${RSPAMD_FLAG2_NUMBER}
  FOR  ${i}  IN  @{flag_numbers}
    ${result} =  Run Rspamc  -h  ${RSPAMD_LOCAL_ADDR}:${RSPAMD_PORT_CONTROLLER}  -w  10
    ...  -f  ${i}  fuzzy_add  ${message}
    Check Rspamc  ${result}
  END
  Sync Fuzzy Storage
  Scan File  ${message}
  Do Not Expect Symbol  ${FLAG1_SYMBOL}
  Expect Symbol  ${FLAG2_SYMBOL}

Fuzzy Setup Encrypted
  [Arguments]  ${algorithm}
  Set Suite Variable  ${RSPAMD_FUZZY_ALGORITHM}  ${algorithm}
  Set Suite Variable  ${RSPAMD_FUZZY_ENCRYPTED_ONLY}  true
  Set Suite Variable  ${RSPAMD_FUZZY_ENCRYPTION_KEY}  ${RSPAMD_KEY_PUB1}
  Set Suite Variable  ${RSPAMD_FUZZY_INCLUDE}  ${RSPAMD_TESTDIR}/configs/fuzzy-encryption-key.conf
  Rspamd Redis Setup

Fuzzy Setup Encrypted Keyed
  [Arguments]  ${algorithm}
  Set Suite Variable  ${RSPAMD_FUZZY_ALGORITHM}  ${algorithm}
  Set Suite Variable  ${RSPAMD_FUZZY_ENCRYPTED_ONLY}  true
  Set Suite Variable  ${RSPAMD_FUZZY_ENCRYPTION_KEY}  ${RSPAMD_KEY_PUB1} 

  Set Suite Variable  ${RSPAMD_FUZZY_KEY}  mYN888sydwLTfE32g2hN
  Set Suite Variable  ${RSPAMD_FUZZY_SHINGLES_KEY}  hXUCgul9yYY3Zlk1QIT2
  Rspamd Redis Setup

Fuzzy Setup Plain
  [Arguments]  ${algorithm}
  Set Suite Variable  ${RSPAMD_FUZZY_ALGORITHM}  ${algorithm}
  Rspamd Redis Setup

Fuzzy Setup Keyed
  [Arguments]  ${algorithm}
  Set Suite Variable  ${RSPAMD_FUZZY_ALGORITHM}  ${algorithm}
  Set Suite Variable  ${RSPAMD_FUZZY_KEY}  mYN888sydwLTfE32g2hN
  Set Suite Variable  ${RSPAMD_FUZZY_SHINGLES_KEY}  hXUCgul9yYY3Zlk1QIT2
  Rspamd Redis Setup

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
