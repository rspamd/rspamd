*** Settings ***
Suite Setup      Servers Setup
Suite Teardown   Servers Teardown
Library          Process
Library          ${RSPAMD_TESTDIR}/lib/rspamd.py
Resource         ${RSPAMD_TESTDIR}/lib/rspamd.robot
Variables        ${RSPAMD_TESTDIR}/lib/vars.py

*** Variables ***
${CONFIG}              ${RSPAMD_TESTDIR}/configs/lua_test.conf
${MESSAGE}             ${RSPAMD_TESTDIR}/messages/spam_message.eml
${RSPAMD_LUA_SCRIPT}   ${RSPAMD_TESTDIR}/lua/tcp.lua
${RSPAMD_SCOPE}        Suite
${RSPAMD_URL_TLD}      ${RSPAMD_TESTDIR}/../lua/unit/test_tld.dat

*** Test Cases ***
Simple TCP request
  Scan File  ${MESSAGE}
  ...  Settings={symbols_enabled = [SIMPLE_TCP_ASYNC_TEST]}
  Expect Symbol  HTTP_ASYNC_RESPONSE
  Expect Symbol  HTTP_ASYNC_RESPONSE_2

#SSL TCP request
#  Scan File  ${MESSAGE}
#  ...  Settings={symbols_enabled = [SIMPLE_TCP_ASYNC_SSL_TEST]}
#  Expect Symbol With Exact Options  TCP_SSL_RESPONSE  hello
#  Expect Symbol With Exact Options  TCP_SSL_RESPONSE_2  hello

#SSL Large TCP request
#  Scan File  ${MESSAGE}
#  ...  Settings={symbols_enabled = [LARGE_TCP_ASYNC_SSL_TEST]}
#  Expect Symbol  TCP_SSL_LARGE
#  Expect Symbol  TCP_SSL_LARGE_2

Sync API TCP request
  Scan File  ${MESSAGE}
  ...  Settings={symbols_enabled = [SIMPLE_TCP_TEST]}
  Expect Symbol  HTTP_SYNC_RESPONSE
  Should Contain  ${SCAN_RESULT}[symbols][HTTP_SYNC_RESPONSE][options][0]  hello world
  Should Contain  ${SCAN_RESULT}[symbols][HTTP_SYNC_RESPONSE_2][options][0]  hello post

Sync API TCP get request
  #Check url  /request  get  HTTP_SYNC_EOF_get  hello world
  Check url  /request  get  HTTP_SYNC_CONTENT_get  hello world

# Broken due to dummy_https issues, disable for now
#Sync API TCP post request
#  Check url  /request  post  HTTP_SYNC_EOF_post  hello post
#  Check url  /content-length  post  HTTP_SYNC_CONTENT_post  hello post

Phased timeouts on success path
  Scan File  ${MESSAGE}
  ...  Settings={symbols_enabled = [PHASED_TIMEOUT_TEST]}
  Expect Symbol  PHASED_TCP_OK
  Do Not Expect Symbol  PHASED_TCP_ERROR

on_error fires on connect refused
  Scan File  ${MESSAGE}
  ...  Settings={symbols_enabled = [ON_ERROR_REFUSED_TEST]}
  Expect Symbol  ON_ERROR_FIRED
  Do Not Expect Symbol  ON_ERROR_REGULAR_CB_FIRED

on_error not fired post-connect
  Scan File  ${MESSAGE}
  ...  Settings={symbols_enabled = [ON_ERROR_POST_CONNECT_TEST]}
  Expect Symbol  POST_CONNECT_READ_TIMEOUT
  Do Not Expect Symbol  POST_CONNECT_ON_ERROR_FIRED
  Do Not Expect Symbol  POST_CONNECT_READ_OK

*** Keywords ***
Servers Setup
  Run Dummy Http
  Run Dummy Ssl
  Rspamd Setup

Servers Teardown
  Dummy Http Teardown
  Rspamd Teardown
  Teardown Dummy Ssl

Run Dummy Ssl
  [Arguments]
  ${result} =  Start Process  ${RSPAMD_TESTDIR}/util/dummy_ssl.py  ${RSPAMD_TESTDIR}/util/server.pem
  Wait Until Created  /tmp/dummy_ssl.pid  timeout=2 second

Teardown Dummy Ssl
  ${ssl_pid} =  Get File  /tmp/dummy_ssl.pid
  Shutdown Process With Children  ${ssl_pid}

Check url
  [Arguments]  ${url}  ${method}  ${expect_symbol}  @{expect_options}
  Scan File  ${MESSAGE}  URL=${url}  Method=${method}
  ...  Settings={symbols_enabled = [HTTP_TCP_TEST]}
  Expect Symbol With Exact Options  ${expect_symbol}  @{expect_options}
