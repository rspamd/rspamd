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

Dump User Statistics
  Learn  other@example.com  spam  ${MESSAGE_SPAM}
  ${all} =  Statistics Dump  dump
  Should Contain  ${all.stdout}  "RStest@example.com":
  Should Contain  ${all.stdout}  "RSother@example.com":
  ${result} =  Statistics Dump  dump  --user  test@example.com
  Should Contain  ${result.stdout}  "BAYES_SPAM_keys": ["RStest@example.com"]
  Should Contain  ${result.stdout}  "RStest@example.com_
  Should Not Contain  ${result.stdout}  RSother@example.com
