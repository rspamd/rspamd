*** Settings ***
Library         ${RSPAMD_TESTDIR}/lib/rspamd.py
Resource        ${RSPAMD_TESTDIR}/lib/rspamd.robot
Variables       ${RSPAMD_TESTDIR}/lib/vars.py

*** Variables ***
${MSG_IN_MAP}      ${RSPAMD_TESTDIR}/messages/lua_extras_in_map.eml
${MSG_NOT_IN_MAP}  ${RSPAMD_TESTDIR}/messages/lua_extras_not_in_map.eml

*** Test Cases ***
Lua_extras deferred selector fires regexp when From in map
  Scan File  ${MSG_IN_MAP}
  ...  Settings={symbols_enabled = [TEST_EXTRAS_LOCAL_FROM]}
  Expect Symbol  TEST_EXTRAS_LOCAL_FROM

Lua_extras deferred selector silent when From not in map
  Scan File  ${MSG_NOT_IN_MAP}
  ...  Settings={symbols_enabled = [TEST_EXTRAS_LOCAL_FROM]}
  Do Not Expect Symbol  TEST_EXTRAS_LOCAL_FROM
