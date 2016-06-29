*** Settings ***
Library         ${TESTDIR}/lib/rspamd.py
Resource        ${TESTDIR}/lib/rspamd.robot

*** Variables ***
@{ALIASES}       STATSDIR
${CONFIG}        ${TESTDIR}/configs/stats.conf
${MESSAGE}       ${TESTDIR}/messages/spam_message.eml
${RSPAMD_SCOPE}  Test

*** Keywords ***
Statistics Setup
  [Arguments]  @{aliases}  &{kw}
  &{RSPAMD_KEYWORDS} =  Create Dictionary  KEY_PRIVATE=${KEY_PVT1}  KEY_PUBLIC=${KEY_PUB1}  LOCAL_ADDR=${LOCAL_ADDR}  PORT_CONTROLLER=${PORT_CONTROLLER}  PORT_NORMAL=${PORT_NORMAL}  TESTDIR=${TESTDIR}
  Update Dictionary  ${RSPAMD_KEYWORDS}  ${kw}
  Set Test Variable  &{RSPAMD_KEYWORDS}
  ${TMPDIR}  ${RSPAMD_PID}  ${RSPAMD_LOGPOS} =  Run Rspamd  @{aliases}  &{RSPAMD_KEYWORDS}
  Export Rspamd Vars To Test  ${TMPDIR}  ${RSPAMD_LOGPOS}  ${RSPAMD_PID}

*** Test Cases ***
Sqlite Learn - Keyed, siphash
  [Setup]  Statistics Setup  @{ALIASES}  STATS_BACKEND=sqlite3  STATS_HASH=siphash STATS_KEY=${KEY_PVT1}
  ${result} =  Run Rspamc  -h  ${LOCAL_ADDR}:${PORT_CONTROLLER}  learn_spam  ${MESSAGE}
  Check Rspamc  ${result}
  ${result} =  Scan Message With Rspamc  ${MESSAGE}
  Check Rspamc  ${result}  BAYES_SPAM
  [Teardown]  Generic Teardown

Sqlite Learn - Keyed, xxhash
  [Setup]  Statistics Setup  @{ALIASES}  STATS_BACKEND=sqlite3  STATS_HASH=xxh  STATS_KEY=${KEY_PVT1}
  ${result} =  Run Rspamc  -h  ${LOCAL_ADDR}:${PORT_CONTROLLER}  learn_spam  ${MESSAGE}
  Check Rspamc  ${result}
  ${result} =  Scan Message With Rspamc  ${MESSAGE}
  Check Rspamc  ${result}  BAYES_SPAM
  [Teardown]  Generic Teardown

Sqlite Learn - Broken Stats Directory
  [Setup]  Statistics Setup  @{EMPTY}  STATS_BACKEND=sqlite3  STATS_HASH=xxh  STATS_KEY=${KEY_PVT1}  STATSDIR=/does/not/exist
  ${result} =  Run Rspamc  -h  ${LOCAL_ADDR}:${PORT_CONTROLLER}  learn_spam  ${MESSAGE}
  Follow Rspamd Log
  Should Not Contain  ${result.stdout}  success = true
  [Teardown]  Generic Teardown

Sqlite Learn - Empty part
  [Setup]  Statistics Setup  @{ALIASES}  STATS_BACKEND=sqlite3  STATS_HASH=xxh  STATS_KEY=${KEY_PVT1}
  Set Test Variable  ${MESSAGE}  ${TESTDIR}/messages/empty_part.eml
  ${result} =  Run Rspamc  -h  ${LOCAL_ADDR}:${PORT_CONTROLLER}  learn_spam  ${MESSAGE}
  Check Rspamc  ${result}
  ${result} =  Scan Message With Rspamc  ${MESSAGE}
  Check Rspamc  ${result}  BAYES_SPAM
  [Teardown]  Generic Teardown

Sqlite Relearn
  [Setup]  Statistics Setup  @{ALIASES}  STATS_BACKEND=sqlite3  STATS_HASH=xxh  STATS_KEY=${KEY_PVT1}
  ${result} =  Run Rspamc  -h  ${LOCAL_ADDR}:${PORT_CONTROLLER}  learn_spam  ${MESSAGE}
  Check Rspamc  ${result}
  ${result} =  Scan Message With Rspamc  ${MESSAGE}
  Check Rspamc  ${result}  BAYES_SPAM
  ${result} =  Run Rspamc  -h  ${LOCAL_ADDR}:${PORT_CONTROLLER}  learn_ham  ${MESSAGE}
  Check Rspamc  ${result}
  ${result} =  Scan Message With Rspamc  ${MESSAGE}
  Check Rspamc  ${result}  BAYES_HAM
  [Teardown]  Generic Teardown

Mmap Learn
  [Setup]  Statistics Setup  @{ALIASES}  STATS_BACKEND=mmap  STATS_HASH=compat  STATS_KEY=${KEY_PVT1}
  ${result} =  Run Rspamc  -h  ${LOCAL_ADDR}:${PORT_CONTROLLER}  learn_spam  ${MESSAGE}
  Check Rspamc  ${result}
  ${result} =  Scan Message With Rspamc  ${MESSAGE}
  Check Rspamc  ${result}  BAYES_SPAM
  [Teardown]  Generic Teardown

Mmap Relearn
  [Setup]  Statistics Setup  @{ALIASES}  STATS_BACKEND=mmap  STATS_HASH=compat  STATS_KEY=${KEY_PVT1}
  ${result} =  Run Rspamc  -h  ${LOCAL_ADDR}:${PORT_CONTROLLER}  learn_spam  ${MESSAGE}
  Check Rspamc  ${result}
  ${result} =  Scan Message With Rspamc  ${MESSAGE}
  Check Rspamc  ${result}  BAYES_SPAM
  ${result} =  Run Rspamc  -h  ${LOCAL_ADDR}:${PORT_CONTROLLER}  learn_ham  ${MESSAGE}
  Check Rspamc  ${result}
  ${result} =  Scan Message With Rspamc  ${MESSAGE}
  Check Rspamc  ${result}  BAYES_HAM
  [Teardown]  Generic Teardown
