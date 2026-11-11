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

Zip Unicode Path
  # One file, which 7-Zip and Python show under its Unicode Path name
  Scan File  ${RSPAMD_TESTDIR}/messages/zip-unicode-path.eml
  ...  Settings=${SETTINGS_MIMETYPES}
  Expect Symbol With Exact Options  MIME_BAD_EXTENSION  jar

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

Archive With More Files Than Are Checked
  Scan File  ${RSPAMD_TESTDIR}/messages/archive_many_files.eml
  ...  Settings=${SETTINGS_MIMETYPES}
  Expect Symbol  MIME_TRUNCATED_ARCHIVE
  Do Not Expect Symbol  MIME_UNREADABLE_ARCHIVE

Archive That Cannot Be Read
  Scan File  ${RSPAMD_TESTDIR}/messages/archive_unreadable.eml
  ...  Settings=${SETTINGS_MIMETYPES}
  Expect Symbol  MIME_UNREADABLE_ARCHIVE
  Do Not Expect Symbol  MIME_TRUNCATED_ARCHIVE

Plain Archive Is Neither Truncated Nor Unreadable
  Scan File  ${RSPAMD_TESTDIR}/messages/zip.eml
  ...  Settings=${SETTINGS_MIMETYPES}
  Do Not Expect Symbol  MIME_TRUNCATED_ARCHIVE
  Do Not Expect Symbol  MIME_UNREADABLE_ARCHIVE

Space After Bad Extension In Archive
  Scan File  ${RSPAMD_TESTDIR}/messages/zip_ext_trailing_space.eml
  ...  Settings=${SETTINGS_MIMETYPES}
  Expect Symbol With Exact Options  MIME_BAD_EXTENSION  exe

Stream Suffix After Bad Extension In Archive
  Scan File  ${RSPAMD_TESTDIR}/messages/zip_ext_stream_suffix.eml
  ...  Settings=${SETTINGS_MIMETYPES}
  Expect Symbol With Exact Options  MIME_BAD_EXTENSION  exe

Program In A Document Package
  Scan File  ${RSPAMD_TESTDIR}/messages/zip_package_exe.eml
  ...  Settings=${SETTINGS_MIMETYPES}
  Expect Symbol With Exact Options  MIME_BAD_EXTENSION  exe

Archive Named As A Document
  Scan File  ${RSPAMD_TESTDIR}/messages/zip_named_docx.eml
  ...  Settings=${SETTINGS_MIMETYPES}
  Expect Symbol With Exact Options  MIME_BAD_EXTENSION  exe

Program With An Archive In It
  Scan File  ${RSPAMD_TESTDIR}/messages/sfx_zip.eml
  ...  Settings=${SETTINGS_MIMETYPES}
  Expect Symbol With Option  MIME_BAD_EXTENSION  scr

Program After Other Files In Archive
  Scan File  ${RSPAMD_TESTDIR}/messages/zip_exe_after_files.eml
  ...  Settings={symbols_enabled = [CHECK_ARCHIVES]}
  Expect Symbol  EXE_IN_ARCHIVE
