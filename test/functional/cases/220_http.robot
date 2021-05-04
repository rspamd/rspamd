*** Settings ***
Test Setup      Http Setup
Test Teardown   Http Teardown
Library         Process
Library         ${TESTDIR}/lib/rspamd.py
Resource        ${TESTDIR}/lib/rspamd.robot
Variables       ${TESTDIR}/lib/vars.py

*** Variables ***
# ${CONFIG}       ${TESTDIR}/configs/http.conf
${URL_TLD}      ${TESTDIR}/../lua/unit/test_tld.dat
${CONFIG}       ${TESTDIR}/configs/lua_test.conf
${MESSAGE}      ${TESTDIR}/messages/spam_message.eml
${RSPAMD_SCOPE}  Test

*** Test Cases ***
Simple HTTP request
  Check url  /request  get  HTTP_DNS_200  HTTP_200  HTTP_CORO_DNS_200  HTTP_CORO_200  method_get  hello world  HTTP_CORO_200 (0.00)[hello world]
  Check url  /request  post  HTTP_DNS_200  HTTP_200  HTTP_CORO_DNS_200  HTTP_CORO_200  method_post  hello post  HTTP_CORO_DNS_200 (0.00)[hello post]

*** Test Cases ***
HTTP request 403
  Check url  /error_403  get  HTTP_DNS_403  HTTP_403  HTTP_CORO_DNS_403  HTTP_CORO_403  method_get
  Check url  /error_403  post  HTTP_DNS_403  HTTP_403  HTTP_CORO_DNS_403  HTTP_CORO_403  method_post


*** Test Cases ***
HTTP timeout
  Check url  /timeout  get  HTTP_ERROR  HTTP_ERROR  HTTP_CORO_DNS_ERROR  HTTP_CORO_ERROR  method_get  IO timeout
  Check url  /timeout  post  HTTP_DNS_ERROR  HTTP_ERROR  HTTP_CORO_DNS_ERROR  HTTP_CORO_ERROR  method_post  IO timeout


*** Test Cases ***
HTTP empty response
  Check url  /empty  get  HTTP_ERROR  HTTP_ERROR  HTTP_CORO_DNS_ERROR  HTTP_CORO_ERROR  method_get  IO read error: unexpected EOF
  Check url  /empty  post  HTTP_DNS_ERROR  HTTP_ERROR  HTTP_CORO_DNS_ERROR  HTTP_CORO_ERROR  method_post  IO read error: unexpected EOF

SSL Large HTTP request
  Scan File  ${MESSAGE}
  Expect Symbol  HTTP_SSL_LARGE

*** Keywords ***
Http Setup
  Run Dummy Http
  Run Dummy Https
  New Setup  LUA_SCRIPT=${TESTDIR}/lua/http.lua  URL_TLD=${URL_TLD}

Http Teardown
  ${http_pid} =  Get File  /tmp/dummy_http.pid
  Shutdown Process With Children  ${http_pid}
  ${https_pid} =  Get File  /tmp/dummy_https.pid
  Shutdown Process With Children  ${https_pid}
  Normal Teardown

Run Dummy Http
  ${result} =  Start Process  ${TESTDIR}/util/dummy_http.py
  Wait Until Created  /tmp/dummy_http.pid

Run Dummy Https
  ${result} =  Start Process  ${TESTDIR}/util/dummy_https.py  ${TESTDIR}/util/server.pem
  Wait Until Created  /tmp/dummy_https.pid

Check url
  [Arguments]  ${url}  ${method}  @{expect_results}
  ${result} =  Scan Message With Rspamc  --header=url:${url}  --header=method:${method}  ${MESSAGE}
  FOR  ${expect}  IN  @{expect_results}
    Check Rspamc  ${result}  ${expect}
  END
