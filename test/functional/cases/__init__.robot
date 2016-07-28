*** Settings ***
Suite Setup     Export Global Variables
Library         ../lib/rspamd.py
Variables       ../lib/vars.py

*** Keywords ***
Export Global Variables
  ${TESTDIR} =  Get Test Directory
  ${RSPAMADM} =  Get Rspamadm
  ${RSPAMC} =  Get Rspamc
  ${RSPAMD} =  Get Rspamd
  Set Global Variable  ${RSPAMADM}
  Set Global Variable  ${RSPAMC}
  Set Global Variable  ${RSPAMD}
  Set Global Variable  ${TESTDIR}
