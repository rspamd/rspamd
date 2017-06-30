*** Settings ***
Suite Setup     URL Tags Setup
Suite Teardown  URL Tags Teardown
Library         ${TESTDIR}/lib/rspamd.py
Resource        ${TESTDIR}/lib/rspamd.robot
Variables       ${TESTDIR}/lib/vars.py

*** Variables ***
${ADDITIONAL}   ${TESTDIR}/lua/url_tags.lua
${CONFIG}       ${TESTDIR}/configs/pluginsplus.conf
${MESSAGE}      ${TESTDIR}/messages/url1.eml
${REDIS_SCOPE}  Suite
${RSPAMD_SCOPE}  Suite
${URL_TLD}      ${TESTDIR}/../lua/unit/test_tld.dat

*** Test Cases ***
URL TAGS PERSISTENCE
  ${result} =  Scan Message With Rspamc  --header=addtags=1  ${MESSAGE}
  Check Rspamc  ${result}  ADDED_TAGS (1.00)[no worry]
  ${result} =  Scan Message With Rspamc  ${MESSAGE}
  Check Rspamc  ${result}  FOUND_TAGS (1.00)[no worry]

*** Keywords ***
URL Tags Setup
  ${TMPDIR} =  Make Temporary Directory
  Set Suite Variable  ${TMPDIR}
  Run Redis
  ${LUA} =  Make Temporary File
  ${goop} =  Get File  ${INSTALLROOT}/share/rspamd/rules/rspamd.lua
  ${goop2} =  Get File  ${ADDITIONAL}
  ${goop_unesc} =  Catenate  ${goop}  ${goop2}
  ${PLUGIN_CONFIG} =  Get File  ${TESTDIR}/configs/url_tags.conf
  Set Suite Variable  ${LUA}
  Set Suite Variable  ${PLUGIN_CONFIG}
  Create File  ${LUA}  ${goop_unesc}
  Generic Setup  TMPDIR=${TMPDIR}

URL Tags Teardown
  Normal Teardown
  Remove File  ${LUA}
  Shutdown Process With Children  ${REDIS_PID}
