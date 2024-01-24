*** Settings ***
Suite Setup     Rspamd Redis Setup
Suite Teardown  Rspamd Redis Teardown
Resource        lib.robot

*** Variables ***
${RSPAMD_REDIS_SERVER}    ${RSPAMD_REDIS_ADDR}:${RSPAMD_REDIS_PORT}
${RSPAMD_STATS_PER_USER}  true

*** Test Cases ***
Learn
  Learn Test  test@example.com

Relearn
  Relearn Test  test@example.com
