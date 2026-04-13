*** Settings ***
Suite Setup     Multi Setup
Suite Teardown  Multi Teardown
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
  Generate SSL Test Cert
  Rspamd Setup

Multi Teardown
  Rspamd Teardown
  Dummy Http Teardown
  Dummy Https Teardown
  Redis Teardown
  SSL Cert Teardown
  Try Reap Zombies

Generate SSL Test Cert
  ${ssl_dir} =  Make Temporary Directory
  ${cert}  ${key} =  Generate SSL Cert  ${ssl_dir}
  Set Suite Variable  ${RSPAMD_SSL_CERT}  ${cert}
  Set Suite Variable  ${RSPAMD_SSL_KEY}  ${key}
  Set Suite Variable  ${SSL_TMPDIR}  ${ssl_dir}

SSL Cert Teardown
  Cleanup Temporary Directory  ${SSL_TMPDIR}
