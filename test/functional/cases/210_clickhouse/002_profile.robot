*** Settings ***
Documentation     The clickhouse plugin and the symbols profile columns, checked against
...               a stub of the ClickHouse HTTP interface (util/dummy_clickhouse.py).
...               Nothing here talks to a real ClickHouse server.
Test Teardown     Profile Case Teardown
Library           Process
Library           ${RSPAMD_TESTDIR}/lib/rspamd.py
Library           ch_stub_log.py
Resource          ${RSPAMD_TESTDIR}/lib/rspamd.robot
Variables         ${RSPAMD_TESTDIR}/lib/vars.py

*** Variables ***
${CONFIG}              ${RSPAMD_TESTDIR}/configs/clickhouse_profile.conf
${MESSAGE}             ${RSPAMD_TESTDIR}/messages/spam_message.eml
${RSPAMD_SCOPE}        Test
${RSPAMD_URL_TLD}      ${RSPAMD_TESTDIR}/../lua/unit/test_tld.dat

*** Test Cases ***
Profile Columns Are Sent After Migration To 13
  [Setup]  Profile Case Setup  13  1  false
  Scan And Wait For Insert
  ${n} =  Stub Check Inserts  ${STUB_OUT}  ${TRUE}  ${FALSE}
  Should Be True  ${n} >= 1
  Rspamd Log Should Contain  symbols profile is enabled
  # The schema is already at 13: no migration statement for the profile
  ${statements} =  Stub Statements  ${STUB_OUT}
  FOR  ${sql}  IN  @{statements}
    Should Not Contain  ${sql}  ADD COLUMN IF NOT EXISTS ProfileReason
  END

Profile Columns With Symbols Follow The Groups Block
  [Setup]  Profile Case Setup  13  1  true
  Scan And Wait For Insert
  ${n} =  Stub Check Inserts  ${STUB_OUT}  ${TRUE}  ${TRUE}
  Should Be True  ${n} >= 1

Feature Off Sends No Profile Columns
  [Setup]  Profile Case Setup  13  0  false
  Scan And Wait For Insert
  ${n} =  Stub Check Inserts  ${STUB_OUT}  ${FALSE}  ${FALSE}
  Should Be True  ${n} >= 1

Feature Off With Symbols Sends No Profile Columns
  [Setup]  Profile Case Setup  13  0  true
  Scan And Wait For Insert
  ${n} =  Stub Check Inserts  ${STUB_OUT}  ${FALSE}  ${TRUE}
  Should Be True  ${n} >= 1

Old Schema Gets The Migration And No Profile Columns
  [Documentation]  The stub stays at schema version 12: the controller issues the
  ...              ALTER of migration 12, but no INSERT may name the new columns
  [Setup]  Profile Case Setup  12  1  true
  Scan And Wait For Insert
  ${n} =  Stub Check Inserts  ${STUB_OUT}  ${FALSE}  ${TRUE}
  Should Be True  ${n} >= 1
  Wait Until Keyword Succeeds  10x  0.5s  Migration Statement Was Sent
  Rspamd Log Should Contain  symbols profile is disabled until the schema

Schema 13 Without Profile Columns Keeps The Gate Closed
  [Documentation]  The version number alone does not open the gate: a server at
  ...              schema 13 that lacks the profile columns gets no INSERT naming them
  [Setup]  Profile Case Setup  13  1  true  0
  Scan And Wait For Insert
  ${n} =  Stub Check Inserts  ${STUB_OUT}  ${FALSE}  ${TRUE}
  Should Be True  ${n} >= 1
  Rspamd Log Should Contain  symbols profile is disabled until the schema

*** Keywords ***
Profile Case Setup
  [Arguments]  ${version}  ${sample_rate}  ${enable_symbols}  ${profile_columns}=-1
  ${out} =  Set Variable  ${RSPAMD_TMP_PREFIX}/dummy_clickhouse-${RSPAMD_PORT_DUMMY_HTTP}.jsonl
  ${pid} =  Set Variable  ${RSPAMD_TMP_PREFIX}/dummy_clickhouse-${RSPAMD_PORT_DUMMY_HTTP}.pid
  ${log} =  Set Variable  ${RSPAMD_TMP_PREFIX}/dummy_clickhouse-${RSPAMD_PORT_DUMMY_HTTP}.log
  ${proc} =  Start Dummy Service  dummy_clickhouse.py  ${pid}  ${log}
  ...  python3  ${RSPAMD_TESTDIR}/util/dummy_clickhouse.py  -pf  ${pid}
  ...  -p  ${RSPAMD_PORT_DUMMY_HTTP}  -v  ${version}  -c  ${profile_columns}  -o  ${out}
  Wait Until Dummy Listening  ${RSPAMD_LOCAL_ADDR}  ${RSPAMD_PORT_DUMMY_HTTP}
  Set Test Variable  ${DUMMY_CH_PROC}  ${proc}
  Set Test Variable  ${STUB_OUT}  ${out}
  Set Test Variable  ${RSPAMD_CH_SAMPLE_RATE}  ${sample_rate}
  Set Test Variable  ${RSPAMD_CH_ENABLE_SYMBOLS}  ${enable_symbols}
  Set Test Variable  ${RSPAMD_LUA_SCRIPT}  ${RSPAMD_TESTDIR}/lua/clickhouse_profile.lua
  Rspamd Setup

Profile Case Teardown
  Rspamd Teardown
  Terminate Process  ${DUMMY_CH_PROC}
  Wait For Process  ${DUMMY_CH_PROC}

Scan And Wait For Insert
  Scan File  ${MESSAGE}
  Scan File  ${MESSAGE}
  Wait Until Keyword Succeeds  20x  0.5s  An Insert Was Sent

An Insert Was Sent
  ${n} =  Stub Main Insert Count  ${STUB_OUT}
  Should Be True  ${n} >= 1

Migration Statement Was Sent
  ${statements} =  Stub Statements  ${STUB_OUT}
  ${all} =  Catenate  SEPARATOR=\n  @{statements}
  Should Contain  ${all}  ADD COLUMN IF NOT EXISTS ProfileReason Enum8('none' = 0, 'sampled' = 1, 'slow' = 2) DEFAULT 'none'
  Should Contain  ${all}  AFTER `Groups.Scores`
  Should Contain  ${all}  ADD COLUMN IF NOT EXISTS `Profile.Flags` Array(UInt8)
  Should Contain  ${all}  INSERT INTO rspamd_version (Version) Values (13)

Rspamd Log Should Contain
  [Arguments]  ${text}
  ${log} =  Get File  ${RSPAMD_TMPDIR}/rspamd.log  encoding_errors=ignore
  Should Contain  ${log}  ${text}
