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
${SPAM_MESSAGE}      ${TESTDIR}/messages/spam.eml
${HAM_MESSAGE}      ${TESTDIR}/messages/ham.eml
${RSPAMD_SCOPE}  Suite
${URL_TLD}      ${TESTDIR}/../lua/unit/test_tld.dat

*** Test Cases ***
NO SETTINGS SPAM
  ${result} =  Scan Message With Rspamc  ${SPAM_MESSAGE}
  Check Rspamc  ${result}  SIMPLE_TEST
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
  ${result} =  Scan Message With Rspamc  ${MESSAGE}  --header  Settings={symbols_enabled = ["SIMPLE_TEST"]}
  Check Rspamc  ${result}  SIMPLE_TEST
  Should Not Contain  ${result.stdout}  SIMPLE_PRE
  Should Not Contain  ${result.stdout}  SIMPLE_POST

ENABLE SYMBOL - POSTFILTER
  ${result} =  Scan Message With Rspamc  ${MESSAGE}  --header  Settings={symbols_enabled = ["SIMPLE_TEST", "SIMPLE_POST"]}
  Check Rspamc  ${result}  SIMPLE_TEST
  Should Contain  ${result.stdout}  SIMPLE_POST
  Should Not Contain  ${result.stdout}  SIMPLE_PRE

ENABLE SYMBOL - PREFILTER
  ${result} =  Scan Message With Rspamc  ${MESSAGE}  --header  Settings={symbols_enabled = ["SIMPLE_PRE"]}
  Check Rspamc  ${result}  SIMPLE_PRE
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

*** Keywords ***
Settings Setup
  ${PLUGIN_CONFIG} =  Get File  ${TESTDIR}/configs/settings.conf
  Set Suite Variable  ${PLUGIN_CONFIG}
  Generic Setup  PLUGIN_CONFIG

Settings Teardown
  Normal Teardown
