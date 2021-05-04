*** Settings ***
Suite Setup     MIMETypes Setup
Suite Teardown  Simple Teardown
Library         ${TESTDIR}/lib/rspamd.py
Resource        ${TESTDIR}/lib/rspamd.robot
Variables       ${TESTDIR}/lib/vars.py

*** Variables ***
${CONFIG}       ${TESTDIR}/configs/mime_types.conf
${RSPAMD_SCOPE}  Suite
${URL_TLD}      ${TESTDIR}/../lua/unit/test_tld.dat

*** Test Cases ***
Zip
  Scan File  ${TESTDIR}/messages/zip.eml
  Expect Symbol With Exact Options  MIME_BAD_EXTENSION  exe

Zip Double Bad Extension
  Scan File  ${TESTDIR}/messages/zip-doublebad.eml
  Expect Symbol With Exact Options  MIME_DOUBLE_BAD_EXTENSION  .pdf.exe

Next-to-last Double Bad Extension
  Scan File  ${TESTDIR}/messages/next2last-doublebad.eml
  Expect Symbol With Exact Options  MIME_DOUBLE_BAD_EXTENSION  .scr.xz

Date is followed by Bad Extension
  Scan File  ${TESTDIR}/messages/rar-date-bad-ext.eml
  Expect Symbol With Exact Options  MIME_BAD_EXTENSION  scr
  Do Not Expect Symbol  MIME_DOUBLE_BAD_EXTENSION

Dotted file name is followed by Bad Extension
  Scan File  ${TESTDIR}/messages/bad_ext.dotted_file_name.eml
  Expect Symbol With Exact Options  MIME_BAD_EXTENSION  exe
  Do Not Expect Symbol  MIME_DOUBLE_BAD_EXTENSION

Dotted numbers in parentheses is followed by Bad Extension
  Scan File  ${TESTDIR}/messages/next2last-digits_in_parens.eml
  Expect Symbol With Exact Options  MIME_BAD_EXTENSION  msi
  Do Not Expect Symbol  MIME_DOUBLE_BAD_EXTENSION

Dotted numbers in square brackets is followed by Bad Extension
  Scan File  ${TESTDIR}/messages/next2last-digits_in_brackets.eml
  Expect Symbol With Exact Options  MIME_BAD_EXTENSION  msi
  Do Not Expect Symbol  MIME_DOUBLE_BAD_EXTENSION

Rar4
  Scan File  ${TESTDIR}/messages/rar4.eml
  Expect Symbol With Exact Options  MIME_BAD_EXTENSION  exe

Cloaked Archive Extension
  Scan File  ${TESTDIR}/messages/f.zip.gz.eml
  Expect Symbol With Exact Options  MIME_ARCHIVE_IN_ARCHIVE  .zip.gz  zip

Multipart Archive Extension
  Scan File  ${TESTDIR}/messages/f.zip.001.eml
  Do Not Expect Symbol  MIME_ARCHIVE_IN_ARCHIVE

Exe file, but name in filename_whitelist
  Scan File  ${TESTDIR}/messages/exe_attm.eml
  Do Not Expect Symbol  MIME_BAD_EXTENSION
  Do Not Expect Symbol  MIME_BAD_ATTACHMENT
  Do Not Expect Symbol  MIME_DOUBLE_BAD_EXTENSION

Empty text part should not be treat as html
  Scan File  ${TESTDIR}/messages/empty-plain-text.eml
  Do Not Expect Symbol  FORGED_OUTLOOK_HTML

*** Keywords ***
MIMETypes Setup
  New Setup  URL_TLD=${URL_TLD}
