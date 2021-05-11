*** Settings ***
Library         ${RSPAMD_TESTDIR}/lib/rspamd.py
Resource        ${RSPAMD_TESTDIR}/lib/rspamd.robot
Variables       ${RSPAMD_TESTDIR}/lib/vars.py

*** Variables ***
${OPTIONS1}           ,user@example.org,user,example.org
${OPTIONS2}           First Last,user@example.org,user,example.org
${OPTIONS3}           First M. Last,user@example.org,user,example.org
${SETTINGS_GETFROM}   {symbols_enabled = [${SYMBOL}]}
${SYMBOL}             GET_FROM

*** Test Cases ***
task:get_from('mime') - address only
  Scan File  ${RSPAMD_TESTDIR}/messages/from/from.eml
  ...  Settings=${SETTINGS_GETFROM}
  Expect Symbol  ${SYMBOL}

task:get_from('mime') - comment
  Scan File  ${RSPAMD_TESTDIR}/messages/from/from_comment.eml
  ...  Settings=${SETTINGS_GETFROM}
  Expect Symbol With Exact Options  ${SYMBOL}  ${OPTIONS1}

task:get_from('mime') - display name
  Scan File  ${RSPAMD_TESTDIR}/messages/from/from_dn.eml
  ...  Settings=${SETTINGS_GETFROM}
  Expect Symbol With Exact Options  ${SYMBOL}  ${OPTIONS2}

task:get_from('mime') - display name Base64
  Scan File  ${RSPAMD_TESTDIR}/messages/from/from_dn_base64.eml
  ...  Settings=${SETTINGS_GETFROM}
  Expect Symbol With Exact Options  ${SYMBOL}  Кириллица,user@example.org,user,example.org

task:get_from('mime') - display name and comment
  Scan File  ${RSPAMD_TESTDIR}/messages/from/from_dn_comment.eml
  ...  Settings=${SETTINGS_GETFROM}
  Expect Symbol With Exact Options  ${SYMBOL}  ${OPTIONS2}

task:get_from('mime') - quoted display name
  Scan File  ${RSPAMD_TESTDIR}/messages/from/from_quoted_dn.eml
  ...  Settings=${SETTINGS_GETFROM}
  Expect Symbol With Exact Options  ${SYMBOL}  ${OPTIONS3}

task:get_from('mime') - quoted display name and comment
  Scan File  ${RSPAMD_TESTDIR}/messages/from/from_quoted_dn_comment.eml
  ...  Settings=${SETTINGS_GETFROM}
  Expect Symbol With Exact Options  ${SYMBOL}  ${OPTIONS3}

task:get_from('mime') - quoted in the middle of DN (outer spaces)
  Scan File  ${RSPAMD_TESTDIR}/messages/from/from_quoted_dn_middle.eml
  ...  Settings=${SETTINGS_GETFROM}
  Expect Symbol With Exact Options  ${SYMBOL}  ${OPTIONS3}

task:get_from('mime') - quoted in the middle of DN (inner spaces)
  Scan File  ${RSPAMD_TESTDIR}/messages/from/from_quoted_dn_middle_inner.eml
  ...  Settings=${SETTINGS_GETFROM}
  Expect Symbol With Exact Options  ${SYMBOL}  ${OPTIONS3}
