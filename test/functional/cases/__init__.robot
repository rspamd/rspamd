*** Settings ***
Suite Setup  Export Global Variables
Library      ../lib/rspamd.py
Variables    ../lib/vars.py

*** Keywords ***
Export Global Variables
	${TESTDIR} =         Get Test Directory
	Set Global Variable  ${KEY_PUB1}
	Set Global Variable  ${KEY_PVT1}
	Set Global Variable  ${LOCAL_ADDR}
	Set Global Variable  ${PORT_CONTROLLER}
	Set Global Variable  ${PORT_NORMAL}
	Set Global Variable  ${RSPAMC}  ${TESTDIR}/../../src/client/rspamc
	Set Global Variable  ${RSPAMD}  ${TESTDIR}/../../src/rspamd
	Set Global Variable  ${RSPAMD_GROUP}
	Set Global Variable  ${RSPAMD_USER}
	Set Global Variable  ${TESTDIR}
