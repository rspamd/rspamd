*** Settings ***
Library         ${RSPAMD_TESTDIR}/lib/rspamd.py
Resource        ${RSPAMD_TESTDIR}/lib/rspamd.robot
Variables       ${RSPAMD_TESTDIR}/lib/vars.py

*** Variables ***
${SETTINGS_FNAME}   {symbols_enabled = [TEST_FNAME]}

*** Test Cases ***
FILE NAMES
  Scan File  ${RSPAMD_TESTDIR}/messages/fname.eml  Settings=${SETTINGS_FNAME}
  Expect Symbol With Option  TEST_FNAME  [삼성생명]2020.08.14 데일리 경제뉴스.pdf
  Expect Symbol With Option  TEST_FNAME  01029_402110_10620_RGT06902_PRT180ML_20200803_101820.pdf
