*** Settings ***
Test Setup      Http Early Response Setup
Test Teardown   Http Early Response Teardown
Library         Process
Library         ${RSPAMD_TESTDIR}/lib/rspamd.py
Resource        ${RSPAMD_TESTDIR}/lib/rspamd.robot
Variables       ${RSPAMD_TESTDIR}/lib/vars.py

*** Variables ***
${CONFIG}              ${RSPAMD_TESTDIR}/configs/lua_test.conf
${MESSAGE}             ${RSPAMD_TESTDIR}/messages/spam_message.eml
${RSPAMD_LUA_SCRIPT}   ${RSPAMD_TESTDIR}/lua/http_early_response.lua
${RSPAMD_SCOPE}        Suite
${RSPAMD_URL_TLD}      ${RSPAMD_TESTDIR}/../lua/unit/test_tld.dat

*** Test Cases ***
HTTP Early Reply
  [Documentation]  Test server sending response before reading request body
  Scan File  ${MESSAGE}  test-type=early-reply
  ...  Settings={symbols_enabled = [HTTP_EARLY_RESPONSE_TEST]}
  # We expect either success (200) or an error - both indicate the client handled
  # the early response scenario (success = client received response, error = connection issue)
  ${result} =  Run Keyword And Return Status  Expect Symbol  HTTP_EARLY_REPLY_200
  IF  not ${result}
    Expect Symbol  HTTP_EARLY_REPLY_ERROR
  END

HTTP Early 413 Error
  [Documentation]  Test server sending 413 error before reading request body
  Scan File  ${MESSAGE}  test-type=early-413
  ...  Settings={symbols_enabled = [HTTP_EARLY_RESPONSE_TEST]}
  ${result} =  Run Keyword And Return Status  Expect Symbol  HTTP_EARLY_413_413
  IF  not ${result}
    Expect Symbol  HTTP_EARLY_413_ERROR
  END

HTTP Keepalive Early Response
  [Documentation]  Test keepalive with server sending early response
  Scan File  ${MESSAGE}  test-type=keepalive-early
  ...  Settings={symbols_enabled = [HTTP_EARLY_RESPONSE_TEST]}
  ${result} =  Run Keyword And Return Status  Expect Symbol  HTTP_KEEPALIVE_EARLY_200
  IF  not ${result}
    Expect Symbol  HTTP_KEEPALIVE_EARLY_ERROR
  END

HTTP Early Reply Coroutine
  [Documentation]  Test early response with coroutine-based HTTP request
  Scan File  ${MESSAGE}  test-type=early-coro
  ...  Settings={symbols_enabled = [HTTP_EARLY_RESPONSE_TEST]}
  ${result} =  Run Keyword And Return Status  Expect Symbol  HTTP_EARLY_CORO_200
  IF  not ${result}
    Expect Symbol  HTTP_EARLY_CORO_ERROR
  END

HTTP Normal Request Baseline
  [Documentation]  Baseline test with normal request handling
  Scan File  ${MESSAGE}  test-type=normal
  ...  Settings={symbols_enabled = [HTTP_EARLY_RESPONSE_TEST]}
  Expect Symbol  HTTP_NORMAL_200

HTTP Keepalive Sequential
  [Documentation]  Test sequential keepalive requests
  Scan File  ${MESSAGE}
  ...  Settings={symbols_enabled = [HTTP_KEEPALIVE_SEQUENTIAL_TEST]}
  # Should have at least some successful requests
  Expect Symbol  HTTP_KEEPALIVE_SEQ_SUCCESS

HTTP Early Keepalive Stress
  [Documentation]  Stress test mixing early responses with keepalive
  Scan File  ${MESSAGE}
  ...  Settings={symbols_enabled = [HTTP_EARLY_KEEPALIVE_STRESS_TEST]}
  Expect Symbol  HTTP_EARLY_KEEPALIVE_STRESS

HTTP Immediate Close Large Body
  [Documentation]  Test server immediately closing connection during large body send
  [Tags]  aggressive
  Scan File  ${MESSAGE}
  ...  Settings={symbols_enabled = [HTTP_IMMEDIATE_CLOSE_TEST]}
  # Either we get the 413 response OR an error - both are valid outcomes
  ${result} =  Run Keyword And Return Status  Expect Symbol  HTTP_IMMEDIATE_CLOSE_413
  IF  not ${result}
    Expect Symbol  HTTP_IMMEDIATE_CLOSE_ERROR
  END

HTTP Slow Response Large Body
  [Documentation]  Test server responding slowly while client sends large body
  [Tags]  aggressive
  Scan File  ${MESSAGE}
  ...  Settings={symbols_enabled = [HTTP_SLOW_RESPONSE_TEST]}
  ${result} =  Run Keyword And Return Status  Expect Symbol  HTTP_SLOW_RESPONSE_200
  IF  not ${result}
    Expect Symbol  HTTP_SLOW_RESPONSE_ERROR
  END

HTTP Rapid Close Requests
  [Documentation]  Rapid sequential requests to server that closes immediately
  [Tags]  aggressive
  Scan File  ${MESSAGE}
  ...  Settings={symbols_enabled = [HTTP_RAPID_CLOSE_TEST]}
  Expect Symbol  HTTP_RAPID_CLOSE_RESULTS

HTTP Block And Reply
  [Documentation]  TRUE early response test - 512KB body with server not reading
  [Tags]  early-response  critical
  Scan File  ${MESSAGE}
  ...  Settings={symbols_enabled = [HTTP_BLOCK_REPLY_TEST]}
  # Ideal: HTTP_BLOCK_REPLY_413 (got early response)
  # Acceptable: HTTP_BLOCK_REPLY_ERROR (connection error, but no crash)
  ${result} =  Run Keyword And Return Status  Expect Symbol  HTTP_BLOCK_REPLY_413
  IF  not ${result}
    Expect Symbol  HTTP_BLOCK_REPLY_ERROR
  END

HTTP Block And Reply Coroutine
  [Documentation]  Coroutine version of block-and-reply test
  [Tags]  early-response  critical
  Scan File  ${MESSAGE}
  ...  Settings={symbols_enabled = [HTTP_BLOCK_REPLY_CORO_TEST]}
  ${result} =  Run Keyword And Return Status  Expect Symbol  HTTP_BLOCK_REPLY_CORO_413
  IF  not ${result}
    Expect Symbol  HTTP_BLOCK_REPLY_CORO_ERROR
  END

HTTP Block Slow Response
  [Documentation]  Server waits 1s then responds - 1MB body
  [Tags]  early-response  slow
  Scan File  ${MESSAGE}
  ...  Settings={symbols_enabled = [HTTP_BLOCK_SLOW_TEST]}
  ${result} =  Run Keyword And Return Status  Expect Symbol  HTTP_BLOCK_SLOW_503
  IF  not ${result}
    Expect Symbol  HTTP_BLOCK_SLOW_ERROR
  END

HTTP Instant Reply
  [Documentation]  Server responds BEFORE reading headers - most aggressive early response
  [Tags]  early-response  critical
  Scan File  ${MESSAGE}
  ...  Settings={symbols_enabled = [HTTP_INSTANT_REPLY_TEST]}
  ${result} =  Run Keyword And Return Status  Expect Symbol  HTTP_INSTANT_REPLY_413
  IF  not ${result}
    Expect Symbol  HTTP_INSTANT_REPLY_ERROR
  END

*** Keywords ***
Http Early Response Setup
  Run Dummy Http Early Response
  Rspamd Setup

Http Early Response Teardown
  Rspamd Teardown
  Dummy Http Early Teardown
