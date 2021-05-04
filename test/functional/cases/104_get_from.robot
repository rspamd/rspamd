*** Settings ***
Suite Setup     GetFrom Setup
Suite Teardown  Simple Teardown
Library         ${RSPAMD_TESTDIR}/lib/rspamd.py
Resource        ${RSPAMD_TESTDIR}/lib/rspamd.robot
Variables       ${RSPAMD_TESTDIR}/lib/vars.py

*** Variables ***
${CONFIG}        ${RSPAMD_TESTDIR}/configs/lua_script.conf
${RSPAMD_LUA_SCRIPT}    ${RSPAMD_TESTDIR}/lua/get_from.lua
${RSPAMD_SCOPE}  Suite

${SYMBOL}   GET_FROM
${OPTIONS1}  ,user@example.org,user,example.org
${OPTIONS2}  First Last,user@example.org,user,example.org
${OPTIONS3}  First M. Last,user@example.org,user,example.org

*** Test Cases ***
task:get_from('mime') - address only
  Scan File  ${RSPAMD_TESTDIR}/messages/from/from.eml
  Expect Symbol  ${SYMBOL}

task:get_from('mime') - comment
  Scan File  ${RSPAMD_TESTDIR}/messages/from/from_comment.eml
  Expect Symbol With Exact Options  ${SYMBOL}  ${OPTIONS1}

task:get_from('mime') - display name
  Scan File  ${RSPAMD_TESTDIR}/messages/from/from_dn.eml
  Expect Symbol With Exact Options  ${SYMBOL}  ${OPTIONS2}

task:get_from('mime') - display name Base64
  Scan File  ${RSPAMD_TESTDIR}/messages/from/from_dn_base64.eml
  Expect Symbol With Exact Options  ${SYMBOL}  Кириллица,user@example.org,user,example.org

task:get_from('mime') - display name and comment
  Scan File  ${RSPAMD_TESTDIR}/messages/from/from_dn_comment.eml
  Expect Symbol With Exact Options  ${SYMBOL}  ${OPTIONS2}

task:get_from('mime') - quoted display name
  Scan File  ${RSPAMD_TESTDIR}/messages/from/from_quoted_dn.eml
  Expect Symbol With Exact Options  ${SYMBOL}  ${OPTIONS3}

task:get_from('mime') - quoted display name and comment
  Scan File  ${RSPAMD_TESTDIR}/messages/from/from_quoted_dn_comment.eml
  Expect Symbol With Exact Options  ${SYMBOL}  ${OPTIONS3}

task:get_from('mime') - quoted in the middle of DN (outer spaces)
  Scan File  ${RSPAMD_TESTDIR}/messages/from/from_quoted_dn_middle.eml
  Expect Symbol With Exact Options  ${SYMBOL}  ${OPTIONS3}

task:get_from('mime') - quoted in the middle of DN (inner spaces)
  Scan File  ${RSPAMD_TESTDIR}/messages/from/from_quoted_dn_middle_inner.eml
  Expect Symbol With Exact Options  ${SYMBOL}  ${OPTIONS3}

*** Keywords ***
GetFrom Setup
  New Setup
