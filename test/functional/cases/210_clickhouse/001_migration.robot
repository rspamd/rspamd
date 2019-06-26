*** Settings ***
Documentation     Checks if rspamd is able to upgrade migration schema from v0 (very initial) to v2
Test Setup        Clickhouse Setup
Test Teardown     Clickhosue Teardown
Variables         ${TESTDIR}/lib/vars.py
Library           ${TESTDIR}/lib/rspamd.py
Library           clickhouse.py
Resource          ${TESTDIR}/lib/rspamd.robot

*** Variables ***
${CONFIG}             ${TESTDIR}/configs/clickhouse.conf
${RSPAMD_SCOPE}       Suite
${CLICKHOUSE_PORT}    ${18123}

*** Test Cases ***
Migration
    #Initial schema
    #    Prepare rspamd
    #    Sleep    2    #TODO: replace this check with waiting until migration finishes
    #    Column should exist    rspamd    Symbols.Scores
    #    Column should exist    rspamd    Attachments.Digest
    #    Column should exist    rspamd    Symbols.Scores
    #    Schema version should be    3
    Upload new schema                    ${TESTDIR}/data/initial_schema/schema.sql
    Insert data    rspamd                ${TESTDIR}/data/initial_schema/data.rspamd.sql
    Insert data    rspamd_asn            ${TESTDIR}/data/initial_schema/data.rspamd_asn.sql
    Insert data    rspamd_urls           ${TESTDIR}/data/initial_schema/data.rspamd_urls.sql
    Insert data    rspamd_emails         ${TESTDIR}/data/initial_schema/data.rspamd_emails.sql
    Insert data    rspamd_symbols        ${TESTDIR}/data/initial_schema/data.rspamd_symbols.sql
    Insert data    rspamd_attachments    ${TESTDIR}/data/initial_schema/data.rspamd_attachments.sql
    Prepare rspamd
    Sleep    2    #TODO: replace this check with waiting until migration finishes
    Column should exist    rspamd    Symbols.Scores
    Column should exist    rspamd    Attachments.Digest
    Column should exist    rspamd    Symbols.Scores
    # Added in schema version 7
    Column should exist    rspamd    Helo
    Column should exist    rspamd    SMTPRecipients
    Schema version should be    7

Retention
    Upload new schema        ${TESTDIR}/data/schema_2/schema.sql
    Insert data    rspamd    ${TESTDIR}/data/schema_2/data.rspamd.sql
    Assert rows count    rspamd    56
    Prepare rspamd
    Sleep    2    #TODO: replace this check with waiting until migration finishes
    Assert rows count    rspamd    30

*** Keywords ***
Clickhouse Setup
    ${TMPDIR} =    Make Temporary Directory
    Set Global Variable        ${TMPDIR}
    Set Directory Ownership    ${TMPDIR}    ${RSPAMD_USER}    ${RSPAMD_GROUP}
    ${template} =    Get File    ${TESTDIR}/configs/clickhouse-config.xml
    ${config} =    Replace Variables    ${template}
    Create File    ${TMPDIR}/clickhouse-config.xml    ${config}
    Copy File    ${TESTDIR}/configs/clickhouse-users.xml    ${TMPDIR}/users.xml
    Create Directory           ${TMPDIR}/clickhouse
    Set Directory Ownership    ${TMPDIR}/clickhouse    clickhouse    clickhouse
    ${result} =    Run Process    su    -s    /bin/sh    clickhouse    -c
    ...    clickhouse-server --daemon --config-file\=${TMPDIR}/clickhouse-config.xml --pid-file\=${TMPDIR}/clickhouse/clickhouse.pid
    Run Keyword If    ${result.rc} != 0    Log    ${result.stderr}
    Should Be Equal As Integers    ${result.rc}    0
    Wait Until Keyword Succeeds    5 sec    50 ms    TCP Connect    localhost    ${CLICKHOUSE_PORT}
    Set Suite Variable    ${TMPDIR}    ${TMPDIR}

Clickhosue Teardown
    # Sleep 30
    ${clickhouse_pid} =    Get File    ${TMPDIR}/clickhouse/clickhouse.pid
    Shutdown Process With Children    ${clickhouse_pid}
    Log File    ${TMPDIR}/clickhouse/clickhouse-server.err.log
    Simple Teardown

Prepare rspamd
    &{d} =    Run Rspamd    CONFIG=${TESTDIR}/configs/clickhouse.conf    TMPDIR=${TMPDIR}
    ${keys} =    Get Dictionary Keys    ${d}
    FOR    ${i}    IN    @{keys}
        Run Keyword If    '${RSPAMD_SCOPE}' == 'Suite'    Set Suite Variable    ${${i}}    &{d}[${i}]
        ...    ELSE IF    '${RSPAMD_SCOPE}' == 'Test'     Set Test Variable     ${${i}}    &{d}[${i}]
        ...    ELSE    Fail    'RSPAMD_SCOPE must be Test or Suite'
    END
