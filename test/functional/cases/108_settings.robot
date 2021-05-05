*** Settings ***
Suite Setup     Settings Setup
Suite Teardown  Settings Teardown
Library         ${RSPAMD_TESTDIR}/lib/rspamd.py
Resource        ${RSPAMD_TESTDIR}/lib/rspamd.robot
Variables       ${RSPAMD_TESTDIR}/lib/vars.py

*** Variables ***
${CONFIG}               ${RSPAMD_TESTDIR}/configs/settings.conf
${HAM_MESSAGE}          ${RSPAMD_TESTDIR}/messages/ham.eml
${MESSAGE_7BIT}         ${RSPAMD_TESTDIR}/messages/utf.eml
${MESSAGE_ABSENT_MIME}  ${RSPAMD_TESTDIR}/messages/ed25519.eml
${MESSAGE_CUSTOM_HDR}   ${RSPAMD_TESTDIR}/messages/empty-plain-text.eml
${MESSAGE_PRIORITY}     ${RSPAMD_TESTDIR}/messages/priority.eml
${MESSAGE}              ${RSPAMD_TESTDIR}/messages/spam_message.eml
${RSPAMD_LUA_SCRIPT}    ${RSPAMD_TESTDIR}/lua/settings.lua
${RSPAMD_SCOPE}         Suite
${RSPAMD_URL_TLD}       ${RSPAMD_TESTDIR}/../lua/unit/test_tld.dat
${SPAM_MESSAGE}         ${RSPAMD_TESTDIR}/messages/spam.eml

*** Keywords ***
Check Everything Disabled
  Expect Action  no action
  Do Not Expect Symbol  SIMPLE_VIRTUAL
  Do Not Expect Symbol  SIMPLE_PRE
  Do Not Expect Symbol  SIMPLE_POST
  Do Not Expect Symbol  BAYES_SPAM

*** Test Cases ***
NO SETTINGS SPAM
  Scan File  ${SPAM_MESSAGE}
  Expect Symbol  SIMPLE_TEST
  Expect Symbol  SIMPLE_VIRTUAL
  Do Not Expect Symbol  SIMPLE_VIRTUAL1
  Expect Symbol  SIMPLE_PRE
  Expect Symbol  SIMPLE_POST
  Expect Symbol  BAYES_SPAM

NO SETTINGS HAM
  Scan File  ${HAM_MESSAGE}
  Expect Symbol  SIMPLE_TEST
  Expect Symbol  SIMPLE_PRE
  Expect Symbol  SIMPLE_POST
  Expect Symbol  BAYES_HAM

EMPTY SYMBOLS ENABLED - STATIC
  Scan File  ${SPAM_MESSAGE}  IP=5.5.5.5
  Check Everything Disabled

EMPTY GROUPS ENABLED - STATIC
  Scan File  ${SPAM_MESSAGE}  IP=5.5.5.6
  Check Everything Disabled

EMPTY SYMBOLS ENABLED - SETTINGS-ID
  Scan File  ${SPAM_MESSAGE}  Settings-Id=empty_symbols_enabled
  Check Everything Disabled

EMPTY GROUPS ENABLED - SETTINGS-ID
  Scan File  ${SPAM_MESSAGE}  Settings-Id=empty_groups_enabled
  Check Everything Disabled

ENABLE SYMBOL - NORMAL
  Scan File  ${HAM_MESSAGE}  Settings={symbols_enabled = ["SIMPLE_TEST"]}
  Expect Symbol  SIMPLE_TEST
  Do Not Expect Symbol  SIMPLE_PRE
  Do Not Expect Symbol  SIMPLE_POST
  Do Not Expect Symbol  BAYES_HAM

ENABLE SYMBOL - POSTFILTER
  Scan File  ${HAM_MESSAGE}  Settings={symbols_enabled = ["SIMPLE_TEST", "SIMPLE_POST"]}
  Expect Symbol  SIMPLE_TEST
  Expect Symbol  SIMPLE_POST
  Do Not Expect Symbol  SIMPLE_PRE
  Do Not Expect Symbol  BAYES_HAM

ENABLE SYMBOL - PREFILTER
  Scan File  ${HAM_MESSAGE}  Settings={symbols_enabled = ["SIMPLE_PRE"]}
  Expect Symbol  SIMPLE_PRE
  Do Not Expect Symbol  SIMPLE_POST
  Do Not Expect Symbol  SIMPLE_TEST
  Do Not Expect Symbol  BAYES_HAM

ENABLE SYMBOL - CLASSIFIER
  Scan File  ${HAM_MESSAGE}  Settings={symbols_enabled = ["BAYES_HAM", "BAYES_SPAM"]}
  Expect Symbol  BAYES_HAM
  Do Not Expect Symbol  SIMPLE_PRE
  Do Not Expect Symbol  SIMPLE_POST
  Do Not Expect Symbol  SIMPLE_TEST

DISABLE SYMBOL - NORMAL
  Scan File  ${MESSAGE}  Settings={symbols_disabled = ["SIMPLE_TEST"]}
  Do Not Expect Symbol  SIMPLE_TEST
  Expect Symbol  SIMPLE_PRE
  Expect Symbol  SIMPLE_POST

RESCORE SYMBOL - NORMAL
  Scan File  ${MESSAGE}  Settings={SIMPLE_TEST = 3.33}
  Expect Symbol With Score  SIMPLE_TEST  3.33

INJECT SYMBOL - NORMAL
  Scan File  ${MESSAGE}  Settings={symbols = ["INJECTED_SYMBOL1", "INJECTED_SYMBOL2"]}
  Expect Symbol  INJECTED_SYMBOL1
  Expect Symbol  INJECTED_SYMBOL2

RESCORE ACTION
  Scan File  ${MESSAGE}  Settings={actions { reject = 1234.5; } }
  Expect Required Score  1234.5

DISABLE GROUP - NORMAL
  Scan File  ${MESSAGE}  Settings={groups_disabled = ["b"]}
  Do Not Expect Symbol  SIMPLE_TEST
  Expect Symbol  SIMPLE_PRE
  Expect Symbol  SIMPLE_POST

ENABLE GROUP - NORMAL
  Scan File  ${MESSAGE}  Settings={groups_enabled = ["b"]}
  Expect Symbol  SIMPLE_TEST
  Do Not Expect Symbol  SIMPLE_PRE
  Do Not Expect Symbol  SIMPLE_POST

SETTINGS ID - NORMAL
  Scan File  ${MESSAGE}  Settings-Id=id_test
  Expect Symbol  SIMPLE_TEST
  Do Not Expect Symbol  SIMPLE_PRE
  Do Not Expect Symbol  SIMPLE_POST

SETTINGS ID - PRE
  Scan File  ${MESSAGE}  Settings-Id=id_pre
  Expect Symbol  SIMPLE_PRE
  Do Not Expect Symbol  SIMPLE_TEST
  Do Not Expect Symbol  SIMPLE_POST

SETTINGS ID - VIRTUAL
  Scan File  ${MESSAGE}  Settings-Id=id_virtual
  Expect Symbol  SIMPLE_VIRTUAL
  Do Not Expect Symbol  SIMPLE_TEST
  Do Not Expect Symbol  SIMPLE_VIRTUAL1
  Do Not Expect Symbol  DEP_REAL
  Do Not Expect Symbol  SIMPLE_POST
  Do Not Expect Symbol  SIMPLE_PRE

SETTINGS ID - VIRTUAL GROUP
  Scan File  ${MESSAGE}  Settings-Id=id_virtual_group
  Expect Symbol With Score  SIMPLE_VIRTUAL  10
  Expect Symbol With Score  EXPLICIT_VIRTUAL  10
  Do Not Expect Symbol  SIMPLE_TEST
  Do Not Expect Symbol  SIMPLE_VIRTUAL1
  Do Not Expect Symbol  DEP_REAL
  Do Not Expect Symbol  SIMPLE_POST
  Do Not Expect Symbol  SIMPLE_PRE

SETTINGS ID - VIRTUAL FROM
  Scan File  ${MESSAGE}  From=test2@example.com
  Expect Symbol With Score  SIMPLE_VIRTUAL  10
  Expect Symbol With Score  EXPLICIT_VIRTUAL  10
  Do Not Expect Symbol  SIMPLE_TEST
  Do Not Expect Symbol  SIMPLE_VIRTUAL1
  Do Not Expect Symbol  DEP_REAL
  Do Not Expect Symbol  SIMPLE_POST
  Do Not Expect Symbol  SIMPLE_PRE

SETTINGS ID - VIRTUAL USER
  Scan File  ${MESSAGE}  User=test@example.com
  Expect Symbol With Score  SIMPLE_VIRTUAL  10
  Expect Symbol With Score  EXPLICIT_VIRTUAL  10
  Do Not Expect Symbol  SIMPLE_TEST
  Do Not Expect Symbol  SIMPLE_VIRTUAL1
  Do Not Expect Symbol  DEP_REAL
  Do Not Expect Symbol  SIMPLE_POST
  Do Not Expect Symbol  SIMPLE_PRE

SETTINGS ID - VIRTUAL HOSTNAME
  Scan File  ${MESSAGE}  Hostname=example.com
  Expect Symbol With Score  SIMPLE_VIRTUAL  10
  Expect Symbol With Score  EXPLICIT_VIRTUAL  10
  Do Not Expect Symbol  SIMPLE_TEST
  Do Not Expect Symbol  SIMPLE_VIRTUAL1
  Do Not Expect Symbol  DEP_REAL
  Do Not Expect Symbol  SIMPLE_POST
  Do Not Expect Symbol  SIMPLE_PRE

SETTINGS ID - VIRTUAL SELECTOR
  Scan File  ${MESSAGE}  Rcpt=user3@example.com
  Expect Symbol With Score  SIMPLE_VIRTUAL  10
  Expect Symbol With Score  EXPLICIT_VIRTUAL  10
  Do Not Expect Symbol  SIMPLE_TEST
  Do Not Expect Symbol  SIMPLE_VIRTUAL1
  Do Not Expect Symbol  DEP_REAL
  Do Not Expect Symbol  SIMPLE_POST
  Do Not Expect Symbol  SIMPLE_PRE

SETTINGS ID - ANGLED RECIPIENT
  Scan File  ${MESSAGE}  Rcpt=<user3@example.com>
  Expect Symbol With Score  SIMPLE_VIRTUAL  10
  Expect Symbol With Score  EXPLICIT_VIRTUAL  10
  Do Not Expect Symbol  SIMPLE_TEST
  Do Not Expect Symbol  SIMPLE_VIRTUAL1
  Do Not Expect Symbol  DEP_REAL
  Do Not Expect Symbol  SIMPLE_POST
  Do Not Expect Symbol  SIMPLE_PRE

SETTINGS ID - VIRTUAL HEADER MATCH
  Scan File  ${MESSAGE_7BIT}
  Expect Symbol With Score  SIMPLE_VIRTUAL  10
  Expect Symbol With Score  EXPLICIT_VIRTUAL  10
  Do Not Expect Symbol  SIMPLE_TEST
  Do Not Expect Symbol  SIMPLE_VIRTUAL1
  Do Not Expect Symbol  DEP_REAL
  Do Not Expect Symbol  SIMPLE_POST
  Do Not Expect Symbol  SIMPLE_PRE

SETTINGS ID - VIRTUAL HEADER EXISTS
  Scan File  ${MESSAGE_CUSTOM_HDR}
  Expect Symbol With Score  SIMPLE_VIRTUAL  10
  Do Not Expect Symbol  SIMPLE_TEST
  Do Not Expect Symbol  SIMPLE_VIRTUAL1
  Do Not Expect Symbol  DEP_REAL
  Do Not Expect Symbol  SIMPLE_POST
  Do Not Expect Symbol  SIMPLE_PRE

SETTINGS ID - VIRTUAL HEADER ABSENT
  Scan File  ${MESSAGE_ABSENT_MIME}
  Expect Symbol With Score  SIMPLE_VIRTUAL  10
  Do Not Expect Symbol  SIMPLE_TEST
  Do Not Expect Symbol  SIMPLE_VIRTUAL1
  Do Not Expect Symbol  DEP_REAL
  Do Not Expect Symbol  SIMPLE_POST
  Do Not Expect Symbol  SIMPLE_PRE

SETTINGS ID - VIRTUAL REQUEST HEADER
  Scan File  ${MESSAGE}  Test=passed
  Expect Symbol With Score  SIMPLE_VIRTUAL  10
  Do Not Expect Symbol  SIMPLE_TEST
  Do Not Expect Symbol  SIMPLE_VIRTUAL1
  Do Not Expect Symbol  DEP_REAL
  Do Not Expect Symbol  SIMPLE_POST
  Do Not Expect Symbol  SIMPLE_PRE

SETTINGS ID - VIRTUAL DEP
  Scan File  ${MESSAGE}  Settings-Id=id_virtual1
  Expect Symbol  EXPLICIT_VIRTUAL1
  Expect Symbol  DEP_VIRTUAL
  Expect Symbol  DEP_REAL
  Do Not Expect Symbol  SIMPLE_TEST
  Do Not Expect Symbol  SIMPLE_VIRTUAL
  Do Not Expect Symbol  SIMPLE_POST
  Do Not Expect Symbol  SIMPLE_PRE

PRIORITY
  Scan File  ${MESSAGE_PRIORITY}  Settings-Id=id_virtual_group  From=user@test.com
  Expect Symbol  PRIORITY_2


*** Keywords ***
Settings Setup
  Copy File  ${RSPAMD_TESTDIR}/data/bayes.spam.sqlite3  /tmp/bayes.spam.sqlite3
  Copy File  ${RSPAMD_TESTDIR}/data/bayes.ham.sqlite3  /tmp/bayes.ham.sqlite3
  Rspamd Setup

Settings Teardown
  Rspamd Teardown
  Remove Files  /tmp/bayes.spam.sqlite3  /tmp/bayes.ham.sqlite3
