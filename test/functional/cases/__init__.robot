*** Settings ***
Suite Setup     Export Global Variables
Library         ../lib/rspamd.py
Variables       ../lib/vars.py

*** Keywords ***
Export Global Variables
  ${TESTDIR} =  Get Test Directory
  Set Global Variable  ${RSPAMADM}  ${TESTDIR}/../../src/rspamadm/rspamadm
  Set Global Variable  ${RSPAMC}  ${TESTDIR}/../../src/client/rspamc
  Set Global Variable  ${RSPAMD}  ${TESTDIR}/../../src/rspamd
  Set Global Variable  ${TESTDIR}
