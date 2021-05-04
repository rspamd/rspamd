*** Settings ***
Documentation     Checks if rspamd is able to upgrade migration schema from v0 (very initial) to v2
Test Setup        Clickhouse Setup
Test Teardown     Clickhosue Teardown
Variables         ${RSPAMD_TESTDIR}/lib/vars.py
Library           ${RSPAMD_TESTDIR}/lib/rspamd.py
Library           clickhouse.py
Resource          ${RSPAMD_TESTDIR}/lib/rspamd.robot

*** Variables ***
${CONFIG}             ${RSPAMD_TESTDIR}/configs/clickhouse.conf
${RSPAMD_SCOPE}       Suite
${CLICKHOUSE_PORT}    ${18123}

*** Test Cases ***
# Usually broken
#Migration
    #Initial schema
    #    Prepare rspamd
    #    Sleep    2    #TODO: replace this check with waiting until migration finishes
    #    Column should exist    rspamd    Symbols.Scores
    #    Column should exist    rspamd    Attachments.Digest
    #    Column should exist    rspamd    Symbols.Scores
    #    Schema version should be    3
#    Upload new schema                    ${RSPAMD_TESTDIR}/data/initial_schema/schema.sql
#    Insert data    rspamd                ${RSPAMD_TESTDIR}/data/initial_schema/data.rspamd.sql
#    Insert data    rspamd_asn            ${RSPAMD_TESTDIR}/data/initial_schema/data.rspamd_asn.sql
#    Insert data    rspamd_urls           ${RSPAMD_TESTDIR}/data/initial_schema/data.rspamd_urls.sql
#    Insert data    rspamd_emails         ${RSPAMD_TESTDIR}/data/initial_schema/data.rspamd_emails.sql
#    Insert data    rspamd_symbols        ${RSPAMD_TESTDIR}/data/initial_schema/data.rspamd_symbols.sql
#    Insert data    rspamd_attachments    ${RSPAMD_TESTDIR}/data/initial_schema/data.rspamd_attachments.sql
#    Prepare rspamd
#    Sleep    2    #TODO: replace this check with waiting until migration finishes
#    Column should exist    rspamd    Symbols.Scores
#    Column should exist    rspamd    Attachments.Digest
#    Column should exist    rspamd    Symbols.Scores
#    # Added in schema version 7
#    Column should exist    rspamd    Helo
#    Column should exist    rspamd    SMTPRecipients
#    # Added in schema version 8
#    Column should exist    rspamd    Groups.Scores
#    Schema version should be    8

# Eventually broken
#Retention
#    Upload new schema        ${RSPAMD_TESTDIR}/data/schema_2/schema.sql
#    Insert data    rspamd    ${RSPAMD_TESTDIR}/data/schema_2/data.rspamd.sql
#    Assert rows count    rspamd    56
#    Prepare rspamd
#    Sleep    2    #TODO: replace this check with waiting until migration finishes
#    Assert rows count    rspamd    30

*** Keywords ***
Clickhouse Setup
    ${RSPAMD_TMPDIR} =    Make Temporary Directory
    Set Suite Variable        ${RSPAMD_TMPDIR}
    Set Directory Ownership    ${RSPAMD_TMPDIR}    ${RSPAMD_USER}    ${RSPAMD_GROUP}
    ${template} =    Get File    ${RSPAMD_TESTDIR}/configs/clickhouse-config.xml
    ${config} =    Replace Variables    ${template}
    Create File    ${RSPAMD_TMPDIR}/clickhouse-config.xml    ${config}
    Copy File    ${RSPAMD_TESTDIR}/configs/clickhouse-users.xml    ${RSPAMD_TMPDIR}/users.xml
    Create Directory           ${RSPAMD_TMPDIR}/clickhouse
    Set Directory Ownership    ${RSPAMD_TMPDIR}/clickhouse    clickhouse    clickhouse
    ${result} =    Run Process    su    -s    /bin/sh    clickhouse    -c
    ...    clickhouse-server --daemon --config-file\=${RSPAMD_TMPDIR}/clickhouse-config.xml --pid-file\=${RSPAMD_TMPDIR}/clickhouse/clickhouse.pid
    Run Keyword If    ${result.rc} != 0    Log    ${result.stderr}
    Should Be Equal As Integers    ${result.rc}    0
    Wait Until Keyword Succeeds    5 sec    50 ms    TCP Connect    localhost    ${CLICKHOUSE_PORT}
    Set Suite Variable    ${RSPAMD_TMPDIR}    ${RSPAMD_TMPDIR}

Clickhosue Teardown
    # Sleep 30
    ${clickhouse_pid} =    Get File    ${RSPAMD_TMPDIR}/clickhouse/clickhouse.pid
    Shutdown Process With Children    ${clickhouse_pid}
    Log File    ${RSPAMD_TMPDIR}/clickhouse/clickhouse-server.err.log
    Rspamd Teardown

Prepare rspamd
    &{d} =    Run Rspamd    CONFIG=${RSPAMD_TESTDIR}/configs/clickhouse.conf    TMPDIR=${RSPAMD_TMPDIR}
    ${keys} =    Get Dictionary Keys    ${d}
    FOR    ${i}    IN    @{keys}
        Run Keyword If    '${RSPAMD_SCOPE}' == 'Suite'    Set Suite Variable    ${${i}}    ${d}[${i}]
        ...    ELSE IF    '${RSPAMD_SCOPE}' == 'Test'     Set Test Variable     ${${i}}    ${d}[${i}]
        ...    ELSE    Fail    'RSPAMD_SCOPE must be Test or Suite'
    END
