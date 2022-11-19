*** Settings ***
Suite Setup     Multi Setup
Suite Teardown  Rspamd Redis Teardown
Library         ${RSPAMD_TESTDIR}/lib/rspamd.py
Resource        ${RSPAMD_TESTDIR}/lib/rspamd.robot
Variables       ${RSPAMD_TESTDIR}/lib/vars.py

*** Variables ***
${CONFIG}                         ${RSPAMD_TESTDIR}/configs/merged.conf
${REDIS_SCOPE}                    Suite
${RSPAMD_EXTERNAL_RELAY_ENABLED}  false
${RSPAMD_MAP_MAP}                 ${RSPAMD_TESTDIR}/configs/maps/map.list
${RSPAMD_RADIX_MAP}               ${RSPAMD_TESTDIR}/configs/maps/ip2.list
${RSPAMD_REGEXP_MAP}              ${RSPAMD_TESTDIR}/configs/maps/regexp.list
${RSPAMD_SCOPE}                   Suite

*** Keywords ***
Multi Setup
  Run Redis
  Run Dummy Http
  Run Dummy Https
  Rspamd Setup

Multi Teardown
  Rspamd Teardown
  ${http_pid} =  Get File  /tmp/dummy_http.pid
  Shutdown Process With Children  ${http_pid}
  ${https_pid} =  Get File  /tmp/dummy_https.pid
  Shutdown Process With Children  ${https_pid}
  Redis Teardown

Run Dummy Http
  ${result} =  Start Process  ${RSPAMD_TESTDIR}/util/dummy_http.py
  Wait Until Created  /tmp/dummy_http.pid

Run Dummy Https
  ${result} =  Start Process  ${RSPAMD_TESTDIR}/util/dummy_https.py  ${RSPAMD_TESTDIR}/util/server.pem
  Wait Until Created  /tmp/dummy_https.pid