*** Settings ***
Documentation   Multiclass Bayes Migration Tests
Suite Setup     Rspamd Redis Setup
Suite Teardown  Rspamd Redis Teardown
Resource        multiclass_lib.robot
Resource        lib.robot

*** Variables ***
${RSPAMD_REDIS_SERVER}    ${RSPAMD_REDIS_ADDR}:${RSPAMD_REDIS_PORT}
${RSPAMD_STATS_HASH}      siphash
${BINARY_CONFIG}          ${RSPAMD_TESTDIR}/configs/stats.conf
${MULTICLASS_CONFIG}      ${RSPAMD_TESTDIR}/configs/multiclass_bayes.conf

*** Test Cases ***
Binary to Multiclass Migration
    [Documentation]    Test migration from binary to multiclass configuration
    [Tags]             migration  binary-to-multiclass
    
    # First, start with binary configuration and learn some data
    Set Suite Variable  ${CONFIG}  ${BINARY_CONFIG}
    Rspamd Redis Teardown
    Rspamd Redis Setup
    
    # Learn with binary system
    Learn Test
    
    # Now switch to multiclass configuration
    Set Suite Variable  ${CONFIG}  ${MULTICLASS_CONFIG}
    Rspamd Teardown
    Rspamd Setup
    
    # Should still work with existing data
    Scan File  ${MESSAGE_SPAM}
    Expect Symbol  BAYES_SPAM
    Scan File  ${MESSAGE_HAM}
    Expect Symbol  BAYES_HAM
    
    # Should be able to add new classes
    Learn Multiclass  ${EMPTY}  newsletter  ${MESSAGE_NEWSLETTER}
    Scan File  ${MESSAGE_NEWSLETTER}
    Expect Symbol  BAYES_NEWSLETTER

Configuration Validation
    [Documentation]    Test multiclass configuration validation
    [Tags]             configuration  validation
    
    # Test that configuration loads without errors
    ${result} =  Run Process  rspamd  -t  -c  ${MULTICLASS_CONFIG}
    Should Be Equal As Integers  ${result.rc}  0  msg=Configuration validation failed: ${result.stderr}

Redis Data Format Migration
    [Documentation]    Test that Redis data format is properly migrated
    [Tags]             migration  redis  data-format
    
    # Start with binary data
    Set Suite Variable  ${CONFIG}  ${BINARY_CONFIG}
    Rspamd Redis Teardown
    Rspamd Redis Setup
    Learn Test
    
    # Check binary format in Redis
    ${redis_result} =  Run Process  redis-cli  -p  ${RSPAMD_REDIS_PORT}  KEYS  *_learns
    Should Contain  ${redis_result.stdout}  _learns
    
    # Switch to multiclass
    Set Suite Variable  ${CONFIG}  ${MULTICLASS_CONFIG}
    Rspamd Teardown
    Rspamd Setup
    
    # Data should still be accessible
    Scan File  ${MESSAGE_SPAM}
    Expect Symbol  BAYES_SPAM

Backward Compatibility
    [Documentation]    Test that multiclass system maintains backward compatibility
    [Tags]             compatibility  backward
    
    # Use multiclass config but test old commands
    Learn  ${EMPTY}  spam  ${MESSAGE_SPAM}
    Learn  ${EMPTY}  ham  ${MESSAGE_HAM}
    
    # Should work the same as before
    Scan File  ${MESSAGE_SPAM}
    Expect Symbol  BAYES_SPAM
    Scan File  ${MESSAGE_HAM}
    Expect Symbol  BAYES_HAM

Class Label Validation
    [Documentation]    Test class label validation and error handling
    [Tags]             validation  class-labels
    
    # This would test invalid class names, duplicate labels, etc.
    # Implementation depends on how validation errors are exposed
    ${result} =  Run Rspamc  -h  ${RSPAMD_LOCAL_ADDR}:${RSPAMD_PORT_CONTROLLER}  learn_class:invalid-class-name  ${MESSAGE_SPAM}
    Should Not Be Equal As Integers  ${result.rc}  0  msg=Should reject invalid class name

Multiclass Stats Format
    [Documentation]    Test that stats output shows multiclass information
    [Tags]             statistics  multiclass-format
    
    # Learn some data across multiple classes
    Learn Multiclass  ${EMPTY}  spam  ${MESSAGE_SPAM}
    Learn Multiclass  ${EMPTY}  ham  ${MESSAGE_HAM}
    Learn Multiclass  ${EMPTY}  newsletter  ${MESSAGE_NEWSLETTER}
    
    # Check stats format
    ${result} =  Run Rspamc  -h  ${RSPAMD_LOCAL_ADDR}:${RSPAMD_PORT_CONTROLLER}  stat
    Check Rspamc  ${result}
    
    # Should show all classes in stats
    Should Contain  ${result.stdout}  spam
    Should Contain  ${result.stdout}  ham
    Should Contain  ${result.stdout}  newsletter
    
    # Should show learn counts
    Should Match Regexp  ${result.stdout}  learned.*\\d+