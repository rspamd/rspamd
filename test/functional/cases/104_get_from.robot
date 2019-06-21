*** Settings ***
Suite Setup     Generic Setup
Suite Teardown  Simple Teardown
Library         ${TESTDIR}/lib/rspamd.py
Resource        ${TESTDIR}/lib/rspamd.robot
Variables       ${TESTDIR}/lib/vars.py

*** Variables ***
${CONFIG}        ${TESTDIR}/configs/lua_script.conf
${LUA_SCRIPT}    ${TESTDIR}/lua/get_from.lua
${RSPAMD_SCOPE}  Suite

${SYMBOL}   GET_FROM (0.00)
${SYMBOL1}  ${SYMBOL}\[,user@example.org,user,example.org]
${SYMBOL2}  ${SYMBOL}\[First Last,user@example.org,user,example.org]
${SYMBOL3}  ${SYMBOL}\[First M. Last,user@example.org,user,example.org]

*** Test Cases ***
task:get_from('mime') - address only
  ${result} =  Scan Message With Rspamc  ${TESTDIR}/messages/from/from.eml
  Check Rspamc  ${result}  ${SYMBOL1}

task:get_from('mime') - comment
  ${result} =  Scan Message With Rspamc  ${TESTDIR}/messages/from/from_comment.eml
  Check Rspamc  ${result}  ${SYMBOL1}

task:get_from('mime') - display name
  ${result} =  Scan Message With Rspamc  ${TESTDIR}/messages/from/from_dn.eml
  Check Rspamc  ${result}  ${SYMBOL2}

task:get_from('mime') - display name Base64
  ${result} =  Scan Message With Rspamc  ${TESTDIR}/messages/from/from_dn_base64.eml
  Check Rspamc  ${result}  ${SYMBOL}\[Кириллица,user@example.org,user,example.org]

task:get_from('mime') - display name and comment
  ${result} =  Scan Message With Rspamc  ${TESTDIR}/messages/from/from_dn_comment.eml
  Check Rspamc  ${result}  ${SYMBOL2}

task:get_from('mime') - quoted display name
  ${result} =  Scan Message With Rspamc  ${TESTDIR}/messages/from/from_quoted_dn.eml
  Check Rspamc  ${result}  ${SYMBOL3}

task:get_from('mime') - quoted display name and comment
  ${result} =  Scan Message With Rspamc  ${TESTDIR}/messages/from/from_quoted_dn_comment.eml
  Check Rspamc  ${result}  ${SYMBOL3}

task:get_from('mime') - quoted in the middle of DN (outer spaces)
  ${result} =  Scan Message With Rspamc  ${TESTDIR}/messages/from/from_quoted_dn_middle.eml
  Check Rspamc  ${result}  ${SYMBOL3}

task:get_from('mime') - quoted in the middle of DN (inner spaces)
  ${result} =  Scan Message With Rspamc  ${TESTDIR}/messages/from/from_quoted_dn_middle_inner.eml
  Check Rspamc  ${result}  ${SYMBOL3}
