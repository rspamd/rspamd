*** Settings ***
Suite Setup     Redis Statistics Setup
Suite Teardown  Redis Statistics Teardown
Resource        lib.robot

*** Variables ***
${RSPAMD_REDIS_SERVER}  ${RSPAMD_REDIS_ADDR}:${RSPAMD_REDIS_PORT}
${RSPAMD_STATS_HASH}   xxhash

*** Test Cases ***
Learn
  Learn Test

Relearn
  Relearn Test
