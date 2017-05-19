*** Settings ***
Suite Setup     Export Global Variables
Library         ../lib/rspamd.py
Variables       ../lib/vars.py

*** Keywords ***
Export Global Variables
  ${TESTDIR} =  Get Test Directory
  ${TOPDIR} =  Get Top Dir
  ${RSPAMADM} =  Get Rspamadm
  ${RSPAMC} =  Get Rspamc
  ${RSPAMD} =  Get Rspamd
  ${INSTALLROOT} =  Get Install Root
  Set Global Variable  ${INSTALLROOT}
  Set Global Variable  ${RSPAMADM}
  Set Global Variable  ${RSPAMC}
  Set Global Variable  ${RSPAMD}
  Set Global Variable  ${TESTDIR}
  Set Global Variable  ${TOPDIR}
