*** Settings ***
Suite Setup     Settings Setup
Suite Teardown  Settings Teardown
Library         ${TESTDIR}/lib/rspamd.py
Resource        ${TESTDIR}/lib/rspamd.robot
Variables       ${TESTDIR}/lib/vars.py

*** Variables ***
${CONFIG}       ${TESTDIR}/configs/plugins.conf
${LUA_SCRIPT}   ${TESTDIR}/lua/settings.lua
${MESSAGE}      ${TESTDIR}/messages/spam_message.eml
${MESSAGE_PRIORITY}      ${TESTDIR}/messages/priority.eml
${MESSAGE_7BIT}      ${TESTDIR}/messages/utf.eml
${MESSAGE_CUSTOM_HDR}      ${TESTDIR}/messages/empty-plain-text.eml
${MESSAGE_ABSENT_MIME}      ${TESTDIR}/messages/ed25519.eml
${SPAM_MESSAGE}      ${TESTDIR}/messages/spam.eml
${HAM_MESSAGE}      ${TESTDIR}/messages/ham.eml
${RSPAMD_SCOPE}  Suite
${URL_TLD}      ${TESTDIR}/../lua/unit/test_tld.dat

*** Test Cases ***
NO SETTINGS SPAM
  ${result} =  Scan Message With Rspamc  ${SPAM_MESSAGE}
  Check Rspamc  ${result}  SIMPLE_TEST
  Should Contain  ${result.stdout}  SIMPLE_VIRTUAL
  Should Not Contain  ${result.stdout}  SIMPLE_VIRTUAL1
  Should Contain  ${result.stdout}  SIMPLE_PRE
  Should Contain  ${result.stdout}  SIMPLE_POST
  Should Contain  ${result.stdout}  BAYES_SPAM

NO SETTINGS HAM
  ${result} =  Scan Message With Rspamc  ${HAM_MESSAGE}
  Check Rspamc  ${result}  SIMPLE_TEST
  Should Contain  ${result.stdout}  SIMPLE_PRE
  Should Contain  ${result.stdout}  SIMPLE_POST
  Should Contain  ${result.stdout}  BAYES_HAM

ENABLE SYMBOL - NORMAL
  ${result} =  Scan Message With Rspamc  ${HAM_MESSAGE}  --header  Settings={symbols_enabled = ["SIMPLE_TEST"]}
  Check Rspamc  ${result}  SIMPLE_TEST
  Should Not Contain  ${result.stdout}  SIMPLE_PRE
  Should Not Contain  ${result.stdout}  SIMPLE_POST
  Should Not Contain  ${result.stdout}  BAYES_HAM

ENABLE SYMBOL - POSTFILTER
  ${result} =  Scan Message With Rspamc  ${HAM_MESSAGE}  --header  Settings={symbols_enabled = ["SIMPLE_TEST", "SIMPLE_POST"]}
  Check Rspamc  ${result}  SIMPLE_TEST
  Should Contain  ${result.stdout}  SIMPLE_POST
  Should Not Contain  ${result.stdout}  SIMPLE_PRE
  Should Not Contain  ${result.stdout}  BAYES_HAM

ENABLE SYMBOL - PREFILTER
  ${result} =  Scan Message With Rspamc  ${HAM_MESSAGE}  --header  Settings={symbols_enabled = ["SIMPLE_PRE"]}
  Check Rspamc  ${result}  SIMPLE_PRE
  Should Not Contain  ${result.stdout}  SIMPLE_POST
  Should Not Contain  ${result.stdout}  SIMPLE_TEST
  Should Not Contain  ${result.stdout}  BAYES_HAM

ENABLE SYMBOL - CLASSIFIER
  ${result} =  Scan Message With Rspamc  ${HAM_MESSAGE}  --header  Settings={symbols_enabled = ["BAYES_HAM", "BAYES_SPAM"]}
  Check Rspamc  ${result}  BAYES_HAM
  Should Not Contain  ${result.stdout}  SIMPLE_PRE
  Should Not Contain  ${result.stdout}  SIMPLE_POST
  Should Not Contain  ${result.stdout}  SIMPLE_TEST

DISABLE SYMBOL - NORMAL
  ${result} =  Scan Message With Rspamc  ${MESSAGE}  --header  Settings={symbols_disabled = ["SIMPLE_TEST"]}
  Check Rspamc  ${result}  SIMPLE_TEST  inverse=1
  Should Contain  ${result.stdout}  SIMPLE_PRE
  Should Contain  ${result.stdout}  SIMPLE_POST

RESCORE SYMBOL - NORMAL
  ${result} =  Scan Message With Rspamc  ${MESSAGE}  --header  Settings={SIMPLE_TEST = 3.33}
  Check Rspamc  ${result}  SIMPLE_TEST (3.33)

INJECT SYMBOL - NORMAL
  ${result} =  Scan Message With Rspamc  ${MESSAGE}  --header  Settings={symbols = ["INJECTED_SYMBOL1", "INJECTED_SYMBOL2"]}
  Check Rspamc  ${result}  INJECTED_SYMBOL1
  Should Contain  ${result.stdout}  INJECTED_SYMBOL2

RESCORE ACTION
  ${result} =  Scan Message With Rspamc  ${MESSAGE}  --header  Settings={actions { reject = 1234.5; } }
  Check Rspamc  ${result}  ${SPACE}/ 1234.50

DISABLE GROUP - NORMAL
  ${result} =  Scan Message With Rspamc  ${MESSAGE}  --header  Settings={groups_disabled = ["b"]}
  Check Rspamc  ${result}  SIMPLE_TEST  inverse=1
  Should Contain  ${result.stdout}  SIMPLE_PRE
  Should Contain  ${result.stdout}  SIMPLE_POST

ENABLE GROUP - NORMAL
  ${result} =  Scan Message With Rspamc  ${MESSAGE}  --header  Settings={groups_enabled = ["b"]}
  Check Rspamc  ${result}  SIMPLE_TEST
  Should Not Contain  ${result.stdout}  SIMPLE_PRE
  Should Not Contain  ${result.stdout}  SIMPLE_POST

SETTINGS ID - NORMAL
  ${result} =  Scan Message With Rspamc  ${MESSAGE}  --header  Settings-Id=id_test
  Check Rspamc  ${result}  SIMPLE_TEST
  Should Not Contain  ${result.stdout}  SIMPLE_PRE
  Should Not Contain  ${result.stdout}  SIMPLE_POST

SETTINGS ID - PRE
  ${result} =  Scan Message With Rspamc  ${MESSAGE}  --header  Settings-Id=id_pre
  Check Rspamc  ${result}  SIMPLE_PRE
  Should Not Contain  ${result.stdout}  SIMPLE_TEST
  Should Not Contain  ${result.stdout}  SIMPLE_POST

SETTINGS ID - VIRTUAL
  ${result} =  Scan Message With Rspamc  ${MESSAGE}  --header  Settings-Id=id_virtual
  Check Rspamc  ${result}  SIMPLE_VIRTUAL
  Should Not Contain  ${result.stdout}  SIMPLE_TEST
  Should Not Contain  ${result.stdout}  SIMPLE_VIRTUAL1
  Should Not Contain  ${result.stdout}  DEP_REAL
  Should Not Contain  ${result.stdout}  SIMPLE_POST
  Should Not Contain  ${result.stdout}  SIMPLE_PRE

SETTINGS ID - VIRTUAL GROUP
  ${result} =  Scan Message With Rspamc  ${MESSAGE}  --header  Settings-Id=id_virtual_group
  Check Rspamc  ${result}  SIMPLE_VIRTUAL (10
  Should Contain  ${result.stdout}  EXPLICIT_VIRTUAL (10
  Should Not Contain  ${result.stdout}  SIMPLE_TEST
  Should Not Contain  ${result.stdout}  SIMPLE_VIRTUAL1
  Should Not Contain  ${result.stdout}  DEP_REAL
  Should Not Contain  ${result.stdout}  SIMPLE_POST
  Should Not Contain  ${result.stdout}  SIMPLE_PRE

SETTINGS ID - VIRTUAL FROM
  ${result} =  Scan Message With Rspamc  ${MESSAGE}  --from  test2@example.com
  Check Rspamc  ${result}  SIMPLE_VIRTUAL (10
  Should Contain  ${result.stdout}  EXPLICIT_VIRTUAL (10
  Should Not Contain  ${result.stdout}  SIMPLE_TEST
  Should Not Contain  ${result.stdout}  SIMPLE_VIRTUAL1
  Should Not Contain  ${result.stdout}  DEP_REAL
  Should Not Contain  ${result.stdout}  SIMPLE_POST
  Should Not Contain  ${result.stdout}  SIMPLE_PRE

SETTINGS ID - VIRTUAL USER
  ${result} =  Scan Message With Rspamc  ${MESSAGE}  --user  test@example.com
  Check Rspamc  ${result}  SIMPLE_VIRTUAL (10
  Should Contain  ${result.stdout}  EXPLICIT_VIRTUAL (10
  Should Not Contain  ${result.stdout}  SIMPLE_TEST
  Should Not Contain  ${result.stdout}  SIMPLE_VIRTUAL1
  Should Not Contain  ${result.stdout}  DEP_REAL
  Should Not Contain  ${result.stdout}  SIMPLE_POST
  Should Not Contain  ${result.stdout}  SIMPLE_PRE

SETTINGS ID - VIRTUAL HOSTNAME
  ${result} =  Scan Message With Rspamc  ${MESSAGE}  --hostname  example.com
  Check Rspamc  ${result}  SIMPLE_VIRTUAL (10
  Should Contain  ${result.stdout}  EXPLICIT_VIRTUAL (10
  Should Not Contain  ${result.stdout}  SIMPLE_TEST
  Should Not Contain  ${result.stdout}  SIMPLE_VIRTUAL1
  Should Not Contain  ${result.stdout}  DEP_REAL
  Should Not Contain  ${result.stdout}  SIMPLE_POST
  Should Not Contain  ${result.stdout}  SIMPLE_PRE

SETTINGS ID - VIRTUAL SELECTOR
  ${result} =  Scan Message With Rspamc  ${MESSAGE}  --rcpt  user3@example.com
  Check Rspamc  ${result}  SIMPLE_VIRTUAL (10
  Should Contain  ${result.stdout}  EXPLICIT_VIRTUAL (10
  Should Not Contain  ${result.stdout}  SIMPLE_TEST
  Should Not Contain  ${result.stdout}  SIMPLE_VIRTUAL1
  Should Not Contain  ${result.stdout}  DEP_REAL
  Should Not Contain  ${result.stdout}  SIMPLE_POST
  Should Not Contain  ${result.stdout}  SIMPLE_PRE

SETTINGS ID - ANGLED RECIPIENT
  ${result} =  Scan Message With Rspamc  ${MESSAGE}  --rcpt  <user3@example.com>
  Check Rspamc  ${result}  SIMPLE_VIRTUAL (10
  Should Contain  ${result.stdout}  EXPLICIT_VIRTUAL (10
  Should Not Contain  ${result.stdout}  SIMPLE_TEST
  Should Not Contain  ${result.stdout}  SIMPLE_VIRTUAL1
  Should Not Contain  ${result.stdout}  DEP_REAL
  Should Not Contain  ${result.stdout}  SIMPLE_POST
  Should Not Contain  ${result.stdout}  SIMPLE_PRE

SETTINGS ID - VIRTUAL HEADER MATCH
  ${result} =  Scan Message With Rspamc  ${MESSAGE_7BIT}
  Check Rspamc  ${result}  SIMPLE_VIRTUAL (10
  Should Contain  ${result.stdout}  EXPLICIT_VIRTUAL (10
  Should Not Contain  ${result.stdout}  SIMPLE_TEST
  Should Not Contain  ${result.stdout}  SIMPLE_VIRTUAL1
  Should Not Contain  ${result.stdout}  DEP_REAL
  Should Not Contain  ${result.stdout}  SIMPLE_POST
  Should Not Contain  ${result.stdout}  SIMPLE_PRE

SETTINGS ID - VIRTUAL HEADER EXISTS
  ${result} =  Scan Message With Rspamc  ${MESSAGE_CUSTOM_HDR}
  Check Rspamc  ${result}  SIMPLE_VIRTUAL (10
  Should Not Contain  ${result.stdout}  SIMPLE_TEST
  Should Not Contain  ${result.stdout}  SIMPLE_VIRTUAL1
  Should Not Contain  ${result.stdout}  DEP_REAL
  Should Not Contain  ${result.stdout}  SIMPLE_POST
  Should Not Contain  ${result.stdout}  SIMPLE_PRE

SETTINGS ID - VIRTUAL HEADER ABSENT
  ${result} =  Scan Message With Rspamc  ${MESSAGE_ABSENT_MIME}
  Check Rspamc  ${result}  SIMPLE_VIRTUAL (10
  Should Not Contain  ${result.stdout}  SIMPLE_TEST
  Should Not Contain  ${result.stdout}  SIMPLE_VIRTUAL1
  Should Not Contain  ${result.stdout}  DEP_REAL
  Should Not Contain  ${result.stdout}  SIMPLE_POST
  Should Not Contain  ${result.stdout}  SIMPLE_PRE

SETTINGS ID - VIRTUAL REQUEST HEADER
  ${result} =  Scan Message With Rspamc  ${MESSAGE}  --header  Test=passed
  Check Rspamc  ${result}  SIMPLE_VIRTUAL (10
  Should Not Contain  ${result.stdout}  SIMPLE_TEST
  Should Not Contain  ${result.stdout}  SIMPLE_VIRTUAL1
  Should Not Contain  ${result.stdout}  DEP_REAL
  Should Not Contain  ${result.stdout}  SIMPLE_POST
  Should Not Contain  ${result.stdout}  SIMPLE_PRE

SETTINGS ID - VIRTUAL DEP
  ${result} =  Scan Message With Rspamc  ${MESSAGE}  --header  Settings-Id=id_virtual1
  Check Rspamc  ${result}  EXPLICIT_VIRTUAL1
  Should Contain  ${result.stdout}  DEP_VIRTUAL
  Should Contain  ${result.stdout}  DEP_REAL
  Should Not Contain  ${result.stdout}  SIMPLE_TEST
  Should Not Contain  ${result.stdout}  SIMPLE_VIRTUAL
  Should Not Contain  ${result.stdout}  SIMPLE_POST
  Should Not Contain  ${result.stdout}  SIMPLE_PRE

PRIORITY
  ${result} =  Scan Message With Rspamc  ${MESSAGE_PRIORITY}  --header  Settings-Id=id_virtual_group  --from  user@test.com
  Should Contain  ${result.stdout}  PRIORITY_2


*** Keywords ***
Settings Setup
  Copy File  ${TESTDIR}/data/bayes.spam.sqlite3  /tmp/bayes.spam.sqlite3
  Copy File  ${TESTDIR}/data/bayes.ham.sqlite3  /tmp/bayes.ham.sqlite3
  ${PLUGIN_CONFIG} =  Get File  ${TESTDIR}/configs/settings.conf
  Set Suite Variable  ${PLUGIN_CONFIG}
  Generic Setup  PLUGIN_CONFIG

Settings Teardown
  Normal Teardown
