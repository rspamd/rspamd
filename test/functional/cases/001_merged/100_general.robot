*** Settings ***
Library         ${RSPAMD_TESTDIR}/lib/rspamd.py
Resource        ${RSPAMD_TESTDIR}/lib/rspamd.robot
Variables       ${RSPAMD_TESTDIR}/lib/vars.py

*** Variables ***
${GTUBE}               ${RSPAMD_TESTDIR}/messages/gtube.eml
${ALT_RELATED}         ${RSPAMD_TESTDIR}/messages/alternative-related.eml
${MIXED_RELATED_HTML}  ${RSPAMD_TESTDIR}/messages/mixed-related-html-only.eml
${ALT_NESTED_RFC822}   ${RSPAMD_TESTDIR}/messages/alternative-nested-rfc822.eml
${ALT_EMPTY_RELATED}   ${RSPAMD_TESTDIR}/messages/alternative-empty-related.eml
${MIXED_HTML_ZIP}      ${RSPAMD_TESTDIR}/messages/mixed-html-zip.eml
${SETTINGS_NOSYMBOLS}  {symbols_enabled = []}

*** Test Cases ***
GTUBE
  Scan File  ${GTUBE}
  ...  Settings=${SETTINGS_NOSYMBOLS}
  Expect Symbol  GTUBE

GTUBE - Encrypted
  ${result} =  Run Rspamc  -p  -h  ${RSPAMD_LOCAL_ADDR}:${RSPAMD_PORT_NORMAL}  --key  ${RSPAMD_KEY_PUB1}
  ...  ${GTUBE}  --header=Settings=${SETTINGS_NOSYMBOLS}
  Check Rspamc  ${result}  GTUBE (

GTUBE - Scan File feature
  Scan File By Reference  ${GTUBE}
  ...  Settings=${SETTINGS_NOSYMBOLS}
  Expect Symbol  GTUBE

GTUBE - Scan File feature (encoded)
  ${encoded} =  Encode Filename  ${GTUBE}
  Scan File By Reference  ${encoded}
  ...  Settings=${SETTINGS_NOSYMBOLS}
  Expect Symbol  GTUBE

GTUBE - SPAMC
  ${result} =  Spamc  ${RSPAMD_LOCAL_ADDR}  ${RSPAMD_PORT_NORMAL}  ${GTUBE}
  Should Contain  ${result}  GTUBE

GTUBE - RSPAMC
  ${result} =  Rspamc  ${RSPAMD_LOCAL_ADDR}  ${RSPAMD_PORT_NORMAL}  ${GTUBE}
  Should Contain  ${result}  GTUBE

EMAILS DETECTION 1
  Scan File  ${RSPAMD_TESTDIR}/messages/emails1.eml
  ...  URL-Format=Extended  Settings=${SETTINGS_NOSYMBOLS}
  Expect Email  jim@example.net
  Expect Email  bob@example.net
  Expect Email  rupert@example.net

EMAILS DETECTION ZEROFONT
  Scan File  ${RSPAMD_TESTDIR}/messages/zerofont.eml
  ...  Settings={symbols_enabled = [MANY_INVISIBLE_PARTS, ZERO_FONT]}
  Expect Symbol  MANY_INVISIBLE_PARTS
  Expect Symbol  ZERO_FONT

HTML ONLY - TRUE POSITIVE
  Scan File  ${RSPAMD_TESTDIR}/messages/zerofont.eml
  ...  Settings={symbols_enabled = [MIME_HTML_ONLY]}
  Expect Symbol  MIME_HTML_ONLY

HTML ONLY - TRUE NEGATIVE
  Scan File  ${RSPAMD_TESTDIR}/messages/btc.eml
  ...  Settings={symbols_enabled = [MIME_HTML_ONLY]}
  Do Not Expect Symbol  MIME_HTML_ONLY

HTML ONLY - multipart/related inside alternative
  Scan File  ${ALT_RELATED}
  ...  Settings={symbols_enabled = [MIME_HTML_ONLY]}
  Do Not Expect Symbol  MIME_HTML_ONLY

HTML ONLY - multipart/mixed with related (html only)
  Scan File  ${MIXED_RELATED_HTML}
  ...  Settings={symbols_enabled = [MIME_HTML_ONLY]}
  Expect Symbol  MIME_HTML_ONLY

PARTS DIFFER - multipart/related inside alternative
  Scan File  ${ALT_RELATED}
  ...  Settings={symbols_enabled = [R_PARTS_DIFFER]}
  Expect Symbol  R_PARTS_DIFFER

HTML ONLY - nested message/rfc822 with alternative
  Scan File  ${ALT_NESTED_RFC822}
  ...  Settings={symbols_enabled = [MIME_HTML_ONLY]}
  Expect Symbol  MIME_HTML_ONLY

HTML ONLY - malformed related with no children
  Scan File  ${ALT_EMPTY_RELATED}
  ...  Settings={symbols_enabled = [MIME_HTML_ONLY]}
  Expect Symbol  MIME_HTML_ONLY

HTML ONLY - multipart/mixed with html and non-text attachment
  Scan File  ${MIXED_HTML_ZIP}
  ...  Settings={symbols_enabled = [MIME_HTML_ONLY]}
  Expect Symbol  MIME_HTML_ONLY
