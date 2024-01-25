*** Settings ***
Suite Setup     Rspamd Redis Setup
Suite Teardown  Rspamd Redis Teardown
Resource        lib.robot

*** Variables ***
${RSPAMD_REDIS_SERVER}  ${RSPAMD_REDIS_ADDR}:${RSPAMD_REDIS_PORT}
${RSPAMD_STATS_HASH}    xxhash
${RSPAMD_STATS_KEY}     ${RSPAMD_KEY_PVT1}

*** Test Cases ***
Learn
  Learn Test

Relearn
  Relearn Test
