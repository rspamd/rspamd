*** Settings ***
Suite Setup     Redis Statistics Setup
Suite Teardown  Redis Statistics Teardown
Resource        lib.robot

*** Variables ***
${REDIS_SERVER}  ${REDIS_ADDR}:${REDIS_PORT}
${STATS_HASH}   xxhash

*** Test Cases ***
Learn
  Learn Test

Relearn
  Relearn Test
