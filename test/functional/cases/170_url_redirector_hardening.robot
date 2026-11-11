*** Settings ***
Suite Setup     Urlredirector Hardening Setup
Suite Teardown  Urlredirector Hardening Teardown
Library         Process
Library         ${RSPAMD_TESTDIR}/lib/rspamd.py
Resource        ${RSPAMD_TESTDIR}/lib/rspamd.robot
Test Tags       notparallel
Variables       ${RSPAMD_TESTDIR}/lib/vars.py

*** Variables ***
${CONFIG}          ${RSPAMD_TESTDIR}/configs/url_redirector_hardening.conf
${BACKSLASH_MESSAGE}    ${RSPAMD_TESTDIR}/messages/redir_backslash.eml
${DOUBLE_MESSAGE}       ${RSPAMD_TESTDIR}/messages/redir_double_location.eml
${LONG_MESSAGE}         ${RSPAMD_TESTDIR}/messages/redir_long_non_http.eml
${FLAKY_MESSAGE}        ${RSPAMD_TESTDIR}/messages/redir_flaky.eml
${SLOW_MESSAGE}         ${RSPAMD_TESTDIR}/messages/redir_slow.eml
${MANY_MESSAGE}         ${RSPAMD_TESTDIR}/messages/redir_many.eml
${REDIS_SCOPE}     Suite
${RSPAMD_SCOPE}    Suite
${RSPAMD_URL_TLD}  ${RSPAMD_TESTDIR}/../lua/unit/test_tld.dat
${SETTINGS}        {symbols_enabled=[URL_REDIRECTOR_CHECK]}

*** Test Cases ***
BACKSLASH IN LOCATION LEADS TO ANOTHER HOST
  Scan File  ${BACKSLASH_MESSAGE}  Flags=ext_urls  Settings=${SETTINGS}
  Expect Extended URL  http://backslash-target.example.net:${RSPAMD_PORT_DUMMY_HTTP}/hello

TWO LOCATION HEADERS
  Scan File  ${DOUBLE_MESSAGE}  Flags=ext_urls  Settings=${SETTINGS}
  Expect Extended URL  http://first-target.example.net:${RSPAMD_PORT_DUMMY_HTTP}/hello

LONG LOCATION IS CUT IN THE OPTION
  Scan File  ${LONG_MESSAGE}  Flags=ext_urls  Settings=${SETTINGS}
  Expect Symbol  URL_REDIRECTOR_NON_HTTP
  ${options} =  Convert To List  ${SCAN_RESULT}[symbols][URL_REDIRECTOR_NON_HTTP][options]
  ${length} =  Get Length  ${options}[0]
  Should Be True  ${length} < 200

A FAILURE IS NOT REMEMBERED FOR LONG
  # The first request gets an error, which is cached for a second
  Scan File  ${FLAKY_MESSAGE}  Flags=ext_urls  Settings=${SETTINGS}
  Do Not Expect Extended URL  http://flaky-target.example.net:${RSPAMD_PORT_DUMMY_HTTP}/hello
  Sleep  2s
  Scan File  ${FLAKY_MESSAGE}  Flags=ext_urls  Settings=${SETTINGS}
  Expect Extended URL  http://flaky-target.example.net:${RSPAMD_PORT_DUMMY_HTTP}/hello

A SCAN WAITS FOR ANOTHER ONE THAT RESOLVES THE SAME URL
  # The first scan holds the lock while the server takes its time; the
  # second one must end up with the target and must not ask the server again
  ${first} =  Start Process  ${RSPAMC}  -t  60  -h  ${RSPAMD_LOCAL_ADDR}:${RSPAMD_PORT_NORMAL}
  ...  --header  Settings\=${SETTINGS}  ${SLOW_MESSAGE}
  ...  env:LD_LIBRARY_PATH=${RSPAMD_TESTDIR}/../../contrib/aho-corasick
  Sleep  0.4s
  Scan File  ${SLOW_MESSAGE}  Flags=ext_urls  Settings=${SETTINGS}
  Expect Extended URL  http://slow-target.example.net:${RSPAMD_PORT_DUMMY_HTTP}/hello
  Wait For Process  ${first}  timeout=30s
  ${log} =  Get File  ${DUMMY_HTTP_LOG}
  Should Contain X Times  ${log}  HEAD /hard_slow  1

REDIRECTOR URLS OVER THE LIMIT ARE TOLD ABOUT
  Scan File  ${MANY_MESSAGE}  Flags=ext_urls  Settings=${SETTINGS}
  Expect Symbol With Exact Options  URL_REDIRECTOR_LIMIT  2

*** Keywords ***
Urlredirector Hardening Setup
  Run Dummy Http
  Rspamd Redis Setup
  FOR  ${name}  IN  BACKSLASH_MESSAGE  DOUBLE_MESSAGE  LONG_MESSAGE
  ...  FLAKY_MESSAGE  SLOW_MESSAGE  MANY_MESSAGE
    ${rendered} =  Render Message Template  ${${name}}
    Set Suite Variable  ${${name}}  ${rendered}
  END

Urlredirector Hardening Teardown
  Rspamd Redis Teardown
  Dummy Http Teardown
  Terminate All Processes    kill=True
