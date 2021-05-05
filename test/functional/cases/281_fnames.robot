*** Settings ***
Suite Setup     Rspamd Setup
Suite Teardown  Rspamd Teardown
Library         ${RSPAMD_TESTDIR}/lib/rspamd.py
Resource        ${RSPAMD_TESTDIR}/lib/rspamd.robot
Variables       ${RSPAMD_TESTDIR}/lib/vars.py

*** Variables ***
${CONFIG}             ${RSPAMD_TESTDIR}/configs/lua_script.conf
${RSPAMD_LUA_SCRIPT}  ${RSPAMD_TESTDIR}/lua/test_fname.lua
${RSPAMD_SCOPE}       Suite
${RSPAMD_URL_TLD}     ${RSPAMD_TESTDIR}/../lua/unit/test_tld.dat


*** Test Cases ***
FILE NAMES
  Scan File  ${RSPAMD_TESTDIR}/messages/fname.eml
  Expect Symbol With Option  TEST_FNAME  [삼성생명]2020.08.14 데일리 경제뉴스.pdf
  Expect Symbol With Option  TEST_FNAME  01029_402110_10620_RGT06902_PRT180ML_20200803_101820.pdf
