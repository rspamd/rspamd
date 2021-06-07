*** Settings ***
Suite Setup     Rspamd Redis Setup
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
