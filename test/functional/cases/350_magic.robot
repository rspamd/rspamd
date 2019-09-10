*** Settings ***
Suite Setup     Generic Setup
Suite Teardown  Simple Teardown
Library         ${TESTDIR}/lib/rspamd.py
Resource        ${TESTDIR}/lib/rspamd.robot
Variables       ${TESTDIR}/lib/vars.py

*** Variables ***
${CONFIG}       ${TESTDIR}/configs/lua_script.conf
${LUA_SCRIPT}   ${TESTDIR}/lua/magic.lua
${RSPAMD_SCOPE}  Suite
${URL_TLD}      ${TESTDIR}/../lua/unit/test_tld.dat

*** Test Cases ***
Magic detections bundle 1
  ${result} =  Scan Message With Rspamc  ${TESTDIR}/messages/gargantua.eml
  Follow Rspamd Log
  Should Contain  ${result.stdout}  MAGIC_SYM_ZIP_2
  Should Contain  ${result.stdout}  MAGIC_SYM_RAR_3

