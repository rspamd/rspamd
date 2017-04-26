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
${RSPAMD_SCOPE}  Suite
${URL_TLD}      ${TESTDIR}/../lua/unit/test_tld.dat

*** Test Cases ***
NO SETTINGS
  ${result} =  Scan Message With Rspamc  ${MESSAGE}
  Check Rspamc  ${result}  SIMPLE_TEST
  Should Contain  ${result.stdout}  SIMPLE_PRE
  Should Contain  ${result.stdout}  SIMPLE_POST

ENABLE SYMBOL - SIMPLE_TEST
  ${result} =  Scan Message With Rspamc  ${MESSAGE}  --header  Settings={symbols_enabled = ["SIMPLE_TEST"]}
  Check Rspamc  ${result}  SIMPLE_TEST
  Should Not Contain  ${result.stdout}  SIMPLE_PRE
  Should Not Contain  ${result.stdout}  SIMPLE_POST

ENABLE SYMBOL - SIMPLE_POST
  ${result} =  Scan Message With Rspamc  ${MESSAGE}  --header  Settings={symbols_enabled = ["SIMPLE_TEST", "SIMPLE_POST"]}
  Check Rspamc  ${result}  SIMPLE_TEST
  Should Contain  ${result.stdout}  SIMPLE_POST
  Should Not Contain  ${result.stdout}  SIMPLE_PRE

*** Keywords ***
Settings Setup
  ${PLUGIN_CONFIG} =  Get File  ${TESTDIR}/configs/settings.conf
  Set Suite Variable  ${PLUGIN_CONFIG}
  Generic Setup  PLUGIN_CONFIG

Settings Teardown
  Normal Teardown
