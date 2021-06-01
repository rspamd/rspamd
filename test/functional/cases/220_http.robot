*** Settings ***
Test Setup      Http Setup
Test Teardown   Http Teardown
Library         Process
Library         ${RSPAMD_TESTDIR}/lib/rspamd.py
Resource        ${RSPAMD_TESTDIR}/lib/rspamd.robot
Variables       ${RSPAMD_TESTDIR}/lib/vars.py

*** Variables ***
${CONFIG}              ${RSPAMD_TESTDIR}/configs/lua_test.conf
${MESSAGE}             ${RSPAMD_TESTDIR}/messages/spam_message.eml
${RSPAMD_LUA_SCRIPT}   ${RSPAMD_TESTDIR}/lua/http.lua
${RSPAMD_SCOPE}        Suite
${RSPAMD_URL_TLD}      ${RSPAMD_TESTDIR}/../lua/unit/test_tld.dat

*** Test Cases ***
Simple HTTP request
  Scan File  ${MESSAGE}  Url=/request  Method=get
  ...  Settings={symbols_enabled = [SIMPLE_HTTP_TEST]}
  Expect Symbols  HTTP_DNS_200  HTTP_200  HTTP_CORO_DNS_200
  Expect Symbol With Exact Options  HTTP_CORO_200  hello world

  Scan File  ${MESSAGE}  Url=/request  Method=post
  ...  Settings={symbols_enabled = [SIMPLE_HTTP_TEST]}
  Expect Symbols  HTTP_DNS_200  HTTP_200  HTTP_CORO_DNS_200
  Expect Symbol With Exact Options  HTTP_CORO_200  hello post

HTTP request 403
  Scan File  ${MESSAGE}  Url=/error_403  Method=get
  ...  Settings={symbols_enabled = [SIMPLE_HTTP_TEST]}
  Expect Symbols  HTTP_DNS_403  HTTP_403  HTTP_CORO_DNS_403  method_get

  Scan File  ${MESSAGE}  Url=/error_403  Method=post
  ...  Settings={symbols_enabled = [SIMPLE_HTTP_TEST]}
  Expect Symbols  HTTP_DNS_403  HTTP_403  HTTP_CORO_DNS_403  method_post

HTTP timeout
  Scan File  ${MESSAGE}  Url=/timeout  Method=get
  ...  Settings={symbols_enabled = [SIMPLE_HTTP_TEST]}
  Expect Symbols  HTTP_ERROR  HTTP_ERROR  HTTP_CORO_DNS_ERROR  HTTP_CORO_ERROR  method_get
  # FIXME: where is "IO timeout"

  Scan File  ${MESSAGE}  Url=/timeout  Method=post
  ...  Settings={symbols_enabled = [SIMPLE_HTTP_TEST]}
  Expect Symbols  HTTP_ERROR  HTTP_ERROR  HTTP_CORO_DNS_ERROR  HTTP_CORO_ERROR  method_post
  # FIXME: where is "IO timeout"

HTTP empty response
  Scan File  ${MESSAGE}  Url=/empty  Method=get
  ...  Settings={symbols_enabled = [SIMPLE_HTTP_TEST]}
  Expect Symbols  HTTP_ERROR  HTTP_ERROR  HTTP_CORO_DNS_ERROR  HTTP_CORO_ERROR  method_get
  # FIXME: where is "IO read error: unexpected EOF"

  Scan File  ${MESSAGE}  Url=/empty  Method=post
  ...  Settings={symbols_enabled = [SIMPLE_HTTP_TEST]}
  Expect Symbols  HTTP_ERROR  HTTP_ERROR  HTTP_CORO_DNS_ERROR  HTTP_CORO_ERROR  method_post
  # FIXME: where is "IO read error: unexpected EOF"

SSL Large HTTP request
  Scan File  ${MESSAGE}
  ...  Settings={symbols_enabled = [LARGE_HTTP_TEST]}
  Expect Symbol  HTTP_SSL_LARGE

*** Keywords ***
Http Setup
  Run Dummy Http
  Run Dummy Https
  Rspamd Setup

Http Teardown
  ${http_pid} =  Get File  /tmp/dummy_http.pid
  Shutdown Process With Children  ${http_pid}
  ${https_pid} =  Get File  /tmp/dummy_https.pid
  Shutdown Process With Children  ${https_pid}
  Rspamd Teardown

Run Dummy Http
  ${result} =  Start Process  ${RSPAMD_TESTDIR}/util/dummy_http.py
  Wait Until Created  /tmp/dummy_http.pid

Run Dummy Https
  ${result} =  Start Process  ${RSPAMD_TESTDIR}/util/dummy_https.py  ${RSPAMD_TESTDIR}/util/server.pem
  Wait Until Created  /tmp/dummy_https.pid
