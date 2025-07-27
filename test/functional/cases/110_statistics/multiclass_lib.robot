*** Settings ***
Resource        lib.robot

*** Variables ***
${CONFIG}                      ${RSPAMD_TESTDIR}/configs/multiclass_bayes.conf
${MESSAGE_HAM}                 ${RSPAMD_TESTDIR}/messages/ham.eml
${MESSAGE_SPAM}                ${RSPAMD_TESTDIR}/messages/spam_message.eml
${MESSAGE_NEWSLETTER}          ${RSPAMD_TESTDIR}/messages/newsletter.eml
${REDIS_SCOPE}                 Suite
${RSPAMD_REDIS_SERVER}         null
${RSPAMD_SCOPE}                Suite
${RSPAMD_STATS_BACKEND}        redis
${RSPAMD_STATS_HASH}           null
${RSPAMD_STATS_KEY}            null
${RSPAMD_STATS_PER_USER}       ${EMPTY}

*** Keywords ***
Learn Multiclass
    [Arguments]  ${user}  ${class}  ${message}
    IF  "${user}"
        ${result} =  Run Rspamc  -d  ${user}  -h  ${RSPAMD_LOCAL_ADDR}:${RSPAMD_PORT_CONTROLLER}  learn_class:${class}  ${message}
    ELSE
        ${result} =  Run Rspamc  -h  ${RSPAMD_LOCAL_ADDR}:${RSPAMD_PORT_CONTROLLER}  learn_class:${class}  ${message}
    END
    Check Rspamc  ${result}

Learn Multiclass Legacy
    [Arguments]  ${user}  ${class}  ${message}
    # Test backward compatibility with old learn_spam/learn_ham commands
    IF  "${user}"
        ${result} =  Run Rspamc  -d  ${user}  -h  ${RSPAMD_LOCAL_ADDR}:${RSPAMD_PORT_CONTROLLER}  learn_${class}  ${message}
    ELSE
        ${result} =  Run Rspamc  -h  ${RSPAMD_LOCAL_ADDR}:${RSPAMD_PORT_CONTROLLER}  learn_${class}  ${message}
    END
    Check Rspamc  ${result}

Multiclass Basic Learn Test
    [Arguments]  ${user}=${EMPTY}
    Set Suite Variable  ${RSPAMD_STATS_LEARNTEST}  0
    Set Test Variable  ${kwargs}  &{EMPTY}
    IF  "${user}"
        Set To Dictionary  ${kwargs}  Deliver-To=${user}
    END

    # Learn all classes
    Learn Multiclass  ${user}  spam  ${MESSAGE_SPAM}
    Learn Multiclass  ${user}  ham  ${MESSAGE_HAM}
    Learn Multiclass  ${user}  newsletter  ${MESSAGE_NEWSLETTER}

    # Test classification
    Scan File  ${MESSAGE_SPAM}  &{kwargs}
    Expect Symbol  BAYES_SPAM

    Scan File  ${MESSAGE_HAM}  &{kwargs}
    Expect Symbol  BAYES_HAM

    Scan File  ${MESSAGE_NEWSLETTER}  &{kwargs}
    Expect Symbol  BAYES_NEWSLETTER

    Set Suite Variable  ${RSPAMD_STATS_LEARNTEST}  1

Multiclass Legacy Compatibility Test
    [Arguments]  ${user}=${EMPTY}
    Set Test Variable  ${kwargs}  &{EMPTY}
    IF  "${user}"
        Set To Dictionary  ${kwargs}  Deliver-To=${user}
    END

    # Test legacy learn_spam and learn_ham commands still work
    Learn Multiclass Legacy  ${user}  spam  ${MESSAGE_SPAM}
    Learn Multiclass Legacy  ${user}  ham  ${MESSAGE_HAM}

    # Should still classify correctly
    Scan File  ${MESSAGE_SPAM}  &{kwargs}
    Expect Symbol  BAYES_SPAM

    Scan File  ${MESSAGE_HAM}  &{kwargs}
    Expect Symbol  BAYES_HAM

Multiclass Relearn Test
    [Arguments]  ${user}=${EMPTY}
    IF  ${RSPAMD_STATS_LEARNTEST} == 0
        Fail  "Learn test was not run"
    END

    Set Test Variable  ${kwargs}  &{EMPTY}
    IF  "${user}"
        Set To Dictionary  ${kwargs}  Deliver-To=${user}
    END

    # Relearn spam message as ham
    Learn Multiclass  ${user}  ham  ${MESSAGE_SPAM}

    # Should now classify as ham or at least not spam
    Scan File  ${MESSAGE_SPAM}  &{kwargs}
    ${pass} =  Run Keyword And Return Status  Expect Symbol  BAYES_HAM
    IF  ${pass}
        Pass Execution  Successfully reclassified spam as ham
    END
    Do Not Expect Symbol  BAYES_SPAM

Multiclass Cross-Learn Test
    [Arguments]  ${user}=${EMPTY}
    Set Test Variable  ${kwargs}  &{EMPTY}
    IF  "${user}"
        Set To Dictionary  ${kwargs}  Deliver-To=${user}
    END

    # Learn newsletter message as ham to test cross-class learning
    Learn Multiclass  ${user}  ham  ${MESSAGE_NEWSLETTER}

    # Should classify as ham, not newsletter (since we trained it as ham)
    Scan File  ${MESSAGE_NEWSLETTER}  &{kwargs}
    Expect Symbol  BAYES_HAM
    Do Not Expect Symbol  BAYES_NEWSLETTER

Multiclass Unlearn Test
    [Arguments]  ${user}=${EMPTY}
    Set Test Variable  ${kwargs}  &{EMPTY}
    IF  "${user}"
        Set To Dictionary  ${kwargs}  Deliver-To=${user}
    END

    # First learn spam
    Learn Multiclass  ${user}  spam  ${MESSAGE_SPAM}
    Scan File  ${MESSAGE_SPAM}  &{kwargs}
    Expect Symbol  BAYES_SPAM

    # Then unlearn spam (learn as ham)
    Learn Multiclass  ${user}  ham  ${MESSAGE_SPAM}

    # Should no longer classify as spam
    Scan File  ${MESSAGE_SPAM}  &{kwargs}
    Do Not Expect Symbol  BAYES_SPAM

Check Multiclass Results
    [Arguments]  ${result}  ${expected_class}
    # Check that scan result contains expected class information
    Should Contain  ${result.stdout}  BAYES_${expected_class.upper()}
    # Check for multiclass result format [class_name]
    Should Match Regexp  ${result.stdout}  BAYES_${expected_class.upper()}.*\\[${expected_class}\\]

Multiclass Stats Test
    # Check that rspamc stat shows learning counts for all classes
    ${result} =  Run Rspamc  -h  ${RSPAMD_LOCAL_ADDR}:${RSPAMD_PORT_CONTROLLER}  stat
    Check Rspamc  ${result}

    # Should show statistics for all classes
    Should Contain  ${result.stdout}  spam
    Should Contain  ${result.stdout}  ham
    Should Contain  ${result.stdout}  newsletter

Multiclass Configuration Migration Test
    # Test that old binary config can be automatically migrated
    Set Test Variable  ${binary_config}  ${RSPAMD_TESTDIR}/configs/stats.conf

    # Start with binary config
    ${result} =  Run Rspamc  --config  ${binary_config}  stat
    Check Rspamc  ${result}

    # Should show deprecation warning but work
    Should Contain  ${result.stderr}  deprecated  ignore_case=True

Multiclass Performance Test
    [Arguments]  ${num_messages}=100
    # Test classification performance with multiple classes
    ${start_time} =  Get Time  epoch

    FOR  ${i}  IN RANGE  ${num_messages}
        Scan File  ${MESSAGE_SPAM}
        Scan File  ${MESSAGE_HAM}
        Scan File  ${MESSAGE_NEWSLETTER}
    END

    ${end_time} =  Get Time  epoch
    ${duration} =  Evaluate  ${end_time} - ${start_time}

    # Should complete in reasonable time (adjust threshold as needed)
    Should Be True  ${duration} < 30  msg=Performance test took ${duration}s, expected < 30s

Multiclass Memory Test
    # Test that memory usage is reasonable for multiclass classification
    ${result} =  Run Rspamc  -h  ${RSPAMD_LOCAL_ADDR}:${RSPAMD_PORT_CONTROLLER}  stat
    Check Rspamc  ${result}

    # Extract memory usage if available in stats
    # This is a placeholder - actual implementation would parse memory stats
