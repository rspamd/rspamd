*** Settings ***
Library         ${RSPAMD_TESTDIR}/lib/rspamd.py
Resource        ${RSPAMD_TESTDIR}/lib/rspamd.robot
Variables       ${RSPAMD_TESTDIR}/lib/vars.py

*** Variables ***
${SETTINGS_SURBL}  {groups_enabled = [rbl]}

*** Test Cases ***
SURBL resolve ip
  Scan File  ${RSPAMD_TESTDIR}/messages/url7.eml
  ...  Settings=${SETTINGS_SURBL}
  Expect Symbol With Exact Options  URIBL_SBL_CSS  8.8.8.9:example.ru:url
  Expect Symbol With Exact Options  URIBL_XBL  8.8.8.8:example.ru:url
  Expect Symbol With Exact Options  URIBL_PBL  8.8.8.8:example.ru:url

SURBL Example.com domain
  Scan File  ${RSPAMD_TESTDIR}/messages/url4.eml
  ...  Settings=${SETTINGS_SURBL}
  Expect Symbol With Exact Options  RSPAMD_URIBL  example.com:url
  Expect Symbol With Exact Options  DBL_SPAM  example.com:url
  Expect Symbol With Exact Options  DBL_PHISH  rspamd.tk:url
  Do Not Expect Symbol  URIBL_BLACK

SURBL Example.net domain
  Scan File  ${RSPAMD_TESTDIR}/messages/url5.eml
  ...  Settings=${SETTINGS_SURBL}
  Expect Symbol  DBL_PHISH
  Do Not Expect Symbol  DBL_SPAM
  Do Not Expect Symbol  RSPAMD_URIBL
  Do Not Expect Symbol  URIBL_BLACK

SURBL Example.org domain
  Scan File  ${RSPAMD_TESTDIR}/messages/url6.eml
  ...  Settings=${SETTINGS_SURBL}
  Expect Symbol  URIBL_BLACK
  Do Not Expect Symbol  DBL_SPAM
  Do Not Expect Symbol  RSPAMD_URIBL
  Do Not Expect Symbol  DBL_PHISH

SURBL Example.ru domain
  Scan File  ${RSPAMD_TESTDIR}/messages/url7.eml
  ...  Settings=${SETTINGS_SURBL}
  Expect Symbol  URIBL_GREY
  Expect Symbol  URIBL_RED
  Do Not Expect Symbol  DBL_SPAM
  Do Not Expect Symbol  RSPAMD_URIBL
  Do Not Expect Symbol  DBL_PHISH
  Do Not Expect Symbol  URIBL_BLACK

SURBL Example.ru ZEN domain
  Scan File  ${RSPAMD_TESTDIR}/messages/url7.eml
  ...  Settings=${SETTINGS_SURBL}
  Expect Symbol  URIBL_SBL_CSS
  Expect Symbol  URIBL_XBL
  Expect Symbol  URIBL_PBL
  Do Not Expect Symbol  URIBL_SBL
  Do Not Expect Symbol  DBL_SPAM
  Do Not Expect Symbol  RSPAMD_URIBL
  Do Not Expect Symbol  DBL_PHISH
  Do Not Expect Symbol  URIBL_BLACK

SURBL Example.com domain image false
  Scan File  ${RSPAMD_TESTDIR}/messages/urlimage.eml
  ...  Settings=${SETTINGS_SURBL}
  Expect Symbol  RSPAMD_URIBL_IMAGES
  Do Not Expect Symbol  DBL_SPAM
  Do Not Expect Symbol  RSPAMD_URIBL
  Do Not Expect Symbol  DBL_PHISH
  Do Not Expect Symbol  URIBL_BLACK

SURBL @example.com mail html
  Scan File  ${RSPAMD_TESTDIR}/messages/mailadr.eml
  ...  Settings=${SETTINGS_SURBL}
  Expect Symbol  RSPAMD_URIBL
  Expect Symbol With Exact Options  DBL_SPAM  example.com:email
  Do Not Expect Symbol  RSPAMD_URIBL_IMAGES
  Do Not Expect Symbol  DBL_PHISH
  Do Not Expect Symbol  URIBL_BLACK

SURBL @example.com mail text
  Scan File  ${RSPAMD_TESTDIR}/messages/mailadr2.eml
  ...  Settings=${SETTINGS_SURBL}
  Expect Symbol  RSPAMD_URIBL
  Expect Symbol With Exact Options  DBL_SPAM  example.com:email
  Do Not Expect Symbol  RSPAMD_URIBL_IMAGES
  Do Not Expect Symbol  DBL_PHISH
  Do Not Expect Symbol  URIBL_BLACK

SURBL example.com not encoded url in subject
  Scan File  ${RSPAMD_TESTDIR}/messages/urlinsubject.eml
  ...  Settings=${SETTINGS_SURBL}
  Expect Symbol  RSPAMD_URIBL
  Expect Symbol  DBL_SPAM
  Do Not Expect Symbol  DBL_PHISH
  Do Not Expect Symbol  URIBL_BLACK

SURBL example.com encoded url in subject
  Scan File  ${RSPAMD_TESTDIR}/messages/urlinsubjectencoded.eml
  ...  Settings=${SETTINGS_SURBL}
  Expect Symbol  RSPAMD_URIBL
  Expect Symbol  DBL_SPAM
  Do Not Expect Symbol  DBL_PHISH
  Do Not Expect Symbol  URIBL_BLACK

WHITELIST
  Scan File  ${RSPAMD_TESTDIR}/messages/whitelist.eml
  ...  Settings=${SETTINGS_SURBL}
  Do Not Expect Symbol  RSPAMD_URIBL
  Do Not Expect Symbol  DBL_SPAM
  Do Not Expect Symbol  RSPAMD_URIBL_IMAGES

EMAILBL full address & domain only
  Scan File  ${RSPAMD_TESTDIR}/messages/emailbltext.eml
  ...  Settings=${SETTINGS_SURBL}
  Expect Symbol  RSPAMD_EMAILBL_FULL
  Expect Symbol  RSPAMD_EMAILBL_DOMAINONLY

EMAILBL full subdomain address
  Scan File  ${RSPAMD_TESTDIR}/messages/emailbltext2.eml
  ...  Settings=${SETTINGS_SURBL}
  Expect Symbol  RSPAMD_EMAILBL_FULL

EMAILBL full subdomain address & domain only
  Scan File  ${RSPAMD_TESTDIR}/messages/emailbltext3.eml
  ...  Settings=${SETTINGS_SURBL}
  Expect Symbol With Exact Options  RSPAMD_EMAILBL_DOMAINONLY  baddomain.com:email
  Expect Symbol With Exact Options  RSPAMD_EMAILBL_FULL  user.subdomain.baddomain.com:email

EMAILBL REPLY TO full address
  Scan File  ${RSPAMD_TESTDIR}/messages/replyto.eml
  ...  Settings=${SETTINGS_SURBL}
  Expect Symbol  RSPAMD_EMAILBL_FULL
  Do Not Expect Symbol  RSPAMD_EMAILBL_DOMAINONLY

EMAILBL REPLY TO domain only
  Scan File  ${RSPAMD_TESTDIR}/messages/replyto2.eml
  ...  Settings=${SETTINGS_SURBL}
  Expect Symbol  RSPAMD_EMAILBL_DOMAINONLY
  Do Not Expect Symbol  RSPAMD_EMAILBL_FULL

EMAILBL REPLY TO full subdomain address
  Scan File  ${RSPAMD_TESTDIR}/messages/replytosubdomain.eml
  ...  Settings=${SETTINGS_SURBL}
  Expect Symbol  RSPAMD_EMAILBL_FULL
  Do Not Expect Symbol  RSPAMD_EMAILBL_DOMAINONLY

SURBL IDN domain
  Scan File  ${RSPAMD_TESTDIR}/messages/url8.eml
  ...  Settings=${SETTINGS_SURBL}
  Expect Symbol  RSPAMD_URIBL
  Expect Symbol  DBL_SPAM
  Do Not Expect Symbol  DBL_PHISH
  Do Not Expect Symbol  URIBL_BLACK

SURBL IDN Punycode domain
  Scan File  ${RSPAMD_TESTDIR}/messages/url9.eml
  ...  Settings=${SETTINGS_SURBL}
  Expect Symbol  RSPAMD_URIBL
  Expect Symbol  DBL_SPAM
  Do Not Expect Symbol  DBL_PHISH
  Do Not Expect Symbol  URIBL_BLACK

SURBL html entity&shy
  Scan File  ${RSPAMD_TESTDIR}/messages/url10.eml
  ...  Settings=${SETTINGS_SURBL}
  Expect Symbol  RSPAMD_URIBL

SURBL url compose map 1
  Scan File  ${RSPAMD_TESTDIR}/messages/url11.eml
  ...  Settings=${SETTINGS_SURBL}
  Expect Symbol With Exact Options  BAD_SUBDOMAIN  clean.dirty.sanchez.com:url

SURBL url compose map 2
  Scan File  ${RSPAMD_TESTDIR}/messages/url12.eml
  ...  Settings=${SETTINGS_SURBL}
  Expect Symbol With Exact Options  BAD_SUBDOMAIN  4.very.dirty.sanchez.com:url

SURBL url compose map 3
  Scan File  ${RSPAMD_TESTDIR}/messages/url13.eml
  ...  Settings=${SETTINGS_SURBL}
  Expect Symbol With Exact Options  BAD_SUBDOMAIN  41.black.sanchez.com:url
