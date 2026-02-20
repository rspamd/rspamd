*** Settings ***
Suite Setup       Rspamd Redis Setup
Suite Teardown    Rspamd Redis Teardown
Test Setup        Set Test Hash Documentation
Resource          multiclass_lib.robot

*** Variables ***
${CONFIG}                      ${RSPAMD_TESTDIR}/configs/multiclass_bayes.conf
${REDIS_SCOPE}                 Suite
${RSPAMD_REDIS_SERVER}         ${RSPAMD_REDIS_ADDR}:${RSPAMD_REDIS_PORT}
${RSPAMD_SCOPE}                Suite
${RSPAMD_STATS_BACKEND}        redis
${RSPAMD_STATS_HASH}           null
${RSPAMD_STATS_KEY}            null
${RSPAMD_STATS_PER_USER}       true

*** Test Cases ***
Multiclass Per-User Basic Learn Test
    Multiclass Basic Learn Test  test@example.com

Multiclass Per-User Relearn Test
    Multiclass Relearn Test  test@example.com

Multiclass Per-User Cross-Learn Test
    Multiclass Cross-Learn Test  test@example.com

Multiclass Per-User Unlearn Test
    Multiclass Unlearn Test  test@example.com