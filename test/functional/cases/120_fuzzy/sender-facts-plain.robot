*** Settings ***
Suite Setup     Fuzzy Setup Plain Siphash
Suite Teardown  Rspamd Redis Teardown
Resource        lib.robot

*** Variables ***
${MESSAGE}                      ${RSPAMD_TESTDIR}/messages/spam_message.eml

*** Test Cases ***
Extensions Are Suppressed Over An Unencrypted Connection
  # Same remote sender that gets the full set of extensions over an encrypted
  # rule: without encryption they would travel in the clear, so none are sent
  Remove File  ${RSPAMD_TMPDIR}/fuzzy_extensions.log
  Scan File  ${MESSAGE}  IP=8.8.8.8  From=foo@example.com
  Wait Until Created  ${RSPAMD_TMPDIR}/fuzzy_extensions.log  timeout=10s
  ${extensions} =  Get File  ${RSPAMD_TMPDIR}/fuzzy_extensions.log
  Log  ${extensions}
  Should Contain  ${extensions}  extensions=none
