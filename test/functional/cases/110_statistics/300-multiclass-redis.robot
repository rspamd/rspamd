*** Settings ***
Documentation   Multiclass Bayes Classification Tests with Redis Backend
Suite Setup     Rspamd Redis Setup
Suite Teardown  Rspamd Redis Teardown
Test Setup      Set Test Hash Documentation
Resource        multiclass_lib.robot

*** Variables ***
${RSPAMD_REDIS_SERVER}  ${RSPAMD_REDIS_ADDR}:${RSPAMD_REDIS_PORT}
${RSPAMD_STATS_HASH}    siphash
${CONFIG}               ${RSPAMD_TESTDIR}/configs/multiclass_bayes.conf

*** Test Cases ***
Multiclass Basic Learning and Classification
    [Documentation]    Test basic multiclass learning and classification
    [Tags]             multiclass  basic  learning
    Multiclass Basic Learn Test

Multiclass Legacy Compatibility
    [Documentation]    Test that old learn_spam/learn_ham commands still work
    [Tags]             multiclass  compatibility  legacy
    Multiclass Legacy Compatibility Test

Multiclass Relearn
    [Documentation]    Test reclassifying messages to different classes
    [Tags]             multiclass  relearn
    Multiclass Relearn Test

Multiclass Cross-Class Learning
    [Documentation]    Test learning message as different class than expected
    [Tags]             multiclass  cross-learn
    Multiclass Cross-Learn Test

Multiclass Unlearn
    [Documentation]    Test unlearning (learning message as different class)
    [Tags]             multiclass  unlearn
    Multiclass Unlearn Test

Multiclass Statistics
    [Documentation]    Test that statistics show all class information
    [Tags]             multiclass  statistics
    Multiclass Stats Test

Per-User Multiclass Learning
    [Documentation]    Test per-user multiclass classification
    [Tags]             multiclass  per-user
    [Setup]            Set Suite Variable  ${RSPAMD_STATS_PER_USER}  1
    Multiclass Basic Learn Test  user@example.com
    [Teardown]         Set Suite Variable  ${RSPAMD_STATS_PER_USER}  ${EMPTY}

Multiclass Empty Part Test
    [Documentation]    Test multiclass learning with empty parts
    [Tags]             multiclass  empty-part
    Set Test Variable  ${MESSAGE}  ${RSPAMD_TESTDIR}/messages/empty_part.eml
    Learn Multiclass  ${EMPTY}  spam  ${MESSAGE}
    Scan File  ${MESSAGE}
    Expect Symbol  BAYES_SPAM
