*** Settings ***
Suite Setup     FNames Setup
Suite Teardown  Normal Teardown
Library         ${TESTDIR}/lib/rspamd.py
Resource        ${TESTDIR}/lib/rspamd.robot
Variables       ${TESTDIR}/lib/vars.py

*** Variables ***
${CONFIG}       ${TESTDIR}/configs/lua_script.conf
${LUA_SCRIPT}   ${TESTDIR}/lua/test_fname.lua
${RSPAMD_SCOPE}  Suite
${URL_TLD}      ${TESTDIR}/../lua/unit/test_tld.dat


*** Test Cases ***
FILE NAMES
  Scan File  ${TESTDIR}/messages/fname.eml
  Expect Symbol With Option  TEST_FNAME  [삼성생명]2020.08.14 데일리 경제뉴스.pdf
  Expect Symbol With Option  TEST_FNAME  01029_402110_10620_RGT06902_PRT180ML_20200803_101820.pdf

*** Keyword ***
FNames Setup
  New Setup  LUA_SCRIPT=${LUA_SCRIPT}
