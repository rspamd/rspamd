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