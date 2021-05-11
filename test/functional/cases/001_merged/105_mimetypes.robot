*** Settings ***
Library         ${RSPAMD_TESTDIR}/lib/rspamd.py
Resource        ${RSPAMD_TESTDIR}/lib/rspamd.robot
Variables       ${RSPAMD_TESTDIR}/lib/vars.py

*** Variables ***
${SETTINGS_MIMETYPES}  {symbols_enabled = [MIME_TYPES_CALLBACK]}

*** Test Cases ***
Zip
  Scan File  ${RSPAMD_TESTDIR}/messages/zip.eml
  ...  Settings=${SETTINGS_MIMETYPES}
  Expect Symbol With Exact Options  MIME_BAD_EXTENSION  exe

Zip Double Bad Extension
  Scan File  ${RSPAMD_TESTDIR}/messages/zip-doublebad.eml
  ...  Settings=${SETTINGS_MIMETYPES}
  Expect Symbol With Exact Options  MIME_DOUBLE_BAD_EXTENSION  .pdf.exe

Next-to-last Double Bad Extension
  Scan File  ${RSPAMD_TESTDIR}/messages/next2last-doublebad.eml
  ...  Settings=${SETTINGS_MIMETYPES}
  Expect Symbol With Exact Options  MIME_DOUBLE_BAD_EXTENSION  .scr.xz

Date is followed by Bad Extension
  Scan File  ${RSPAMD_TESTDIR}/messages/rar-date-bad-ext.eml
  ...  Settings=${SETTINGS_MIMETYPES}
  Expect Symbol With Exact Options  MIME_BAD_EXTENSION  scr
  Do Not Expect Symbol  MIME_DOUBLE_BAD_EXTENSION

Dotted file name is followed by Bad Extension
  Scan File  ${RSPAMD_TESTDIR}/messages/bad_ext.dotted_file_name.eml
  ...  Settings=${SETTINGS_MIMETYPES}
  Expect Symbol With Exact Options  MIME_BAD_EXTENSION  exe
  Do Not Expect Symbol  MIME_DOUBLE_BAD_EXTENSION

Dotted numbers in parentheses is followed by Bad Extension
  Scan File  ${RSPAMD_TESTDIR}/messages/next2last-digits_in_parens.eml
  ...  Settings=${SETTINGS_MIMETYPES}
  Expect Symbol With Exact Options  MIME_BAD_EXTENSION  msi
  Do Not Expect Symbol  MIME_DOUBLE_BAD_EXTENSION

Dotted numbers in square brackets is followed by Bad Extension
  Scan File  ${RSPAMD_TESTDIR}/messages/next2last-digits_in_brackets.eml
  ...  Settings=${SETTINGS_MIMETYPES}
  Expect Symbol With Exact Options  MIME_BAD_EXTENSION  msi
  Do Not Expect Symbol  MIME_DOUBLE_BAD_EXTENSION

Rar4
  Scan File  ${RSPAMD_TESTDIR}/messages/rar4.eml
  ...  Settings=${SETTINGS_MIMETYPES}
  Expect Symbol With Exact Options  MIME_BAD_EXTENSION  exe

Cloaked Archive Extension
  Scan File  ${RSPAMD_TESTDIR}/messages/f.zip.gz.eml
  ...  Settings=${SETTINGS_MIMETYPES}
  Expect Symbol With Exact Options  MIME_ARCHIVE_IN_ARCHIVE  .zip.gz  zip

Multipart Archive Extension
  Scan File  ${RSPAMD_TESTDIR}/messages/f.zip.001.eml
  ...  Settings=${SETTINGS_MIMETYPES}
  Do Not Expect Symbol  MIME_ARCHIVE_IN_ARCHIVE

Exe file, but name in filename_whitelist
  Scan File  ${RSPAMD_TESTDIR}/messages/exe_attm.eml
  ...  Settings=${SETTINGS_MIMETYPES}
  Do Not Expect Symbol  MIME_BAD_EXTENSION
  Do Not Expect Symbol  MIME_BAD_ATTACHMENT
  Do Not Expect Symbol  MIME_DOUBLE_BAD_EXTENSION

Empty text part should not be treat as html
  Scan File  ${RSPAMD_TESTDIR}/messages/empty-plain-text.eml
  ...  Settings=${SETTINGS_MIMETYPES}
  Do Not Expect Symbol  FORGED_OUTLOOK_HTML
