*** Settings ***
Suite Setup     Rspamd Setup
Suite Teardown  Rspamd Teardown
Library         ${RSPAMD_TESTDIR}/lib/rspamd.py
Resource        ${RSPAMD_TESTDIR}/lib/rspamd.robot
Variables       ${RSPAMD_TESTDIR}/lib/vars.py

*** Variables ***
${CONFIG}                         ${RSPAMD_TESTDIR}/configs/merged.conf
${RSPAMD_EXTERNAL_RELAY_ENABLED}  true
${RSPAMD_SCOPE}                   Suite

*** Test Cases ***
EXTERNAL RELAY AUTHENTICATED
  Scan File  ${RSPAMD_TESTDIR}/messages/received5.eml
  ...  Settings={symbols_enabled [EXTERNAL_RELAY_TEST, EXTERNAL_RELAY_AUTHENTICATED]}
  ...  IP=8.8.8.8  User=user@example.net
  Expect Symbol With Exact Options  EXTERNAL_RELAY_TEST
  ...  IP=192.0.2.1  HOSTNAME=mail.example.org  HELO=mail.example.org

EXTERNAL RELAY COUNT
  Scan File  ${RSPAMD_TESTDIR}/messages/received4.eml
  ...  Settings={symbols_enabled [EXTERNAL_RELAY_TEST, EXTERNAL_RELAY_COUNT]}
  ...  IP=8.8.8.8
  Expect Symbol With Exact Options  EXTERNAL_RELAY_TEST
  ...  IP=151.18.193.131  HOSTNAME=ca-18-193-131.service.infuturo.it
  ...  HELO=ca-18-193-131.service.infuturo.it

EXTERNAL RELAY HOSTNAME MAP
  Scan File  ${RSPAMD_TESTDIR}/messages/received6.eml
  ...  Settings={symbols_enabled [EXTERNAL_RELAY_TEST, EXTERNAL_RELAY_HOSTNAME_MAP]}
  ...  Hostname=lame.example.net  IP=192.0.2.10
  Expect Symbol With Exact Options  EXTERNAL_RELAY_TEST
  ...  IP=192.0.2.1  HOSTNAME=mail.example.org  HELO=mail.example.org

EXTERNAL RELAY LOCAL
  Scan File  ${RSPAMD_TESTDIR}/messages/ham.eml
  ...  Settings={symbols_enabled [EXTERNAL_RELAY_TEST, EXTERNAL_RELAY_LOCAL]}
  ...  IP=127.0.0.1
  Expect Symbol With Exact Options  EXTERNAL_RELAY_TEST
  ...  IP=4.31.198.44  HOSTNAME=mail.ietf.org  HELO=mail.ietf.org
