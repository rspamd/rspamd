*** Settings ***
Suite Setup     MIMETypes Setup
Suite Teardown  Simple Teardown
Library         ${TESTDIR}/lib/rspamd.py
Resource        ${TESTDIR}/lib/rspamd.robot
Variables       ${TESTDIR}/lib/vars.py

*** Variables ***
${CONFIG}       ${TESTDIR}/configs/plugins.conf
${RSPAMD_SCOPE}  Suite
${URL_TLD}      ${TESTDIR}/../lua/unit/test_tld.dat

*** Test Cases ***
Zip
  ${result} =  Scan Message With Rspamc  ${TESTDIR}/messages/zip.eml
  Check Rspamc  ${result}  MIME_BAD_EXTENSION \\(\\d+\\.\\d+\\)\\[exe\\]\\n  re=1

Zip Double Bad Extension
  ${result} =  Scan Message With Rspamc  ${TESTDIR}/messages/zip-doublebad.eml
  Check Rspamc  ${result}  MIME_DOUBLE_BAD_EXTENSION \\(\\d+\\.\\d+\\)\\[\\.pdf\\.exe\\]\\n  re=1

Next-to-last Double Bad Extension
  ${result} =  Scan Message With Rspamc  ${TESTDIR}/messages/next2last-doublebad.eml
  Check Rspamc  ${result}  MIME_DOUBLE_BAD_EXTENSION \\(\\d+\\.\\d+\\)\\[\\.scr\\.xz\\]\\n  re=1

Date is followed by Bad Extension
  ${result} =  Scan Message With Rspamc  ${TESTDIR}/messages/rar-date-bad-ext.eml
  Check Rspamc  ${result}  MIME_BAD_EXTENSION \\(\\d+\\.\\d+\\)\\[scr\\]\\n  re=1
  Should Not Contain  ${result.stdout}  MIME_DOUBLE_BAD_EXTENSION

Dotted file name is followed by Bad Extension
  ${result} =  Scan Message With Rspamc  ${TESTDIR}/messages/bad_ext.dotted_file_name.eml
  Check Rspamc  ${result}  MIME_BAD_EXTENSION \\(\\d+\\.\\d+\\)\\[exe\\]\\n  re=1
  Should Not Contain  ${result.stdout}  MIME_DOUBLE_BAD_EXTENSION

Rar4
  ${result} =  Scan Message With Rspamc  ${TESTDIR}/messages/rar4.eml
  Check Rspamc  ${result}  MIME_BAD_EXTENSION \\(\\d+\\.\\d+\\)\\[exe\\]\\n  re=1

Cloaked Archive Extension
  ${result} =  Scan Message With Rspamc  ${TESTDIR}/messages/f.zip.gz.eml
  Check Rspamc  ${result}  MIME_ARCHIVE_IN_ARCHIVE \\(\\d+\\.\\d+\\)\\[\\.zip\\.gz  re=1

Multipart Archive Extension
  ${result} =  Scan Message With Rspamc  ${TESTDIR}/messages/f.zip.001.eml
  Should Not Contain  ${result.stdout}  MIME_ARCHIVE_IN_ARCHIVE

Empty text part should not be treat as html
  ${result} =  Scan Message With Rspamc  ${TESTDIR}/messages/empty-plain-text.eml
  Should Not Contain  ${result.stdout}  FORGED_OUTLOOK_HTML

*** Keywords ***
MIMETypes Setup
  ${PLUGIN_CONFIG} =  Get File  ${TESTDIR}/configs/mime_types.conf
  Set Suite Variable  ${PLUGIN_CONFIG}
  Generic Setup  PLUGIN_CONFIG
