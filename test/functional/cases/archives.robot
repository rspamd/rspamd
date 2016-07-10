*** Settings ***
Suite Setup     Generic Setup
Suite Teardown  Generic Teardown
Library         ${TESTDIR}/lib/rspamd.py
Resource        ${TESTDIR}/lib/rspamd.robot
Variables       ${TESTDIR}/lib/vars.py

*** Variables ***
${CONFIG}       ${TESTDIR}/configs/plugins.conf
${RSPAMD_SCOPE}  Suite

*** Test Cases ***
Zip
  ${result} =  Scan Message With Rspamc  ${TESTDIR}/messages/zip.eml
  Check Rspamc  ${result}  MIME_BAD_EXTENSION \\(\\d+\\.\\d+\\)\\[exe\\]\\n  re=1

Zip Double Bad Extension
  ${result} =  Scan Message With Rspamc  ${TESTDIR}/messages/zip-doublebad.eml
  Check Rspamc  ${result}  MIME_DOUBLE_BAD_EXTENSION \\(\\d+\\.\\d+\\)\\[pdf, exe\\]\\n  re=1

Rar4
  ${result} =  Scan Message With Rspamc  ${TESTDIR}/messages/rar4.eml
  Check Rspamc  ${result}  MIME_BAD_EXTENSION \\(\\d+\\.\\d+\\)\\[exe\\]\\n  re=1
