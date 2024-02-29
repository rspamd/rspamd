*** Settings ***
Suite Setup     Rspamadm Setup
Suite Teardown  Rspamadm Teardown
Library         Process
Library         ../lib/rspamd.py

*** Test Cases ***
Config Test
  ${result} =  Rspamadm  configtest
  Should Match Regexp  ${result.stderr}  ^$
  Should Match Regexp  ${result.stdout}  ^syntax OK$
  Should Be Equal As Integers  ${result.rc}  0

Config Help
  ${result} =  Rspamadm  confighelp
  Should Match Regexp  ${result.stderr}  ^$
  Should Be Equal As Integers  ${result.rc}  0

Simple interpreter
  ${handle} =  Start Process  ${RSPAMADM}  lua  stdin=PIPE
  ${result} =  Write to stdin  ${handle}  1+1
  Should Be Equal As Strings  ${result}  2\n
  Wait For Process  ${handle}

Simple interpreter, two results
  ${handle} =  Start Process  ${RSPAMADM}  lua  stdin=PIPE
  ${result} =  Write to stdin  ${handle}  1+1, 2 * 5
  Should Be Equal  ${result}  2\n10\n
  Wait For Process  ${handle}

Process message callback
  ${handle} =  Start Process  ${RSPAMADM}  lua  stdin=PIPE
  ${result} =  Write to stdin  ${handle}  .load ${RSPAMD_TESTDIR}/lua/rspamadm/test_message_callback.lua\n.message message_callback ${RSPAMD_TESTDIR}/messages/empty_part.eml
  Should Contain  ${result}  n parts = 2
  Should Contain  ${result}  1\n2\n4\n6
  Wait For Process  ${handle}

Lua batch mode
  ${result} =  Rspamadm  lua  -b  ${RSPAMD_TESTDIR}/lua/rspamadm/test_batch.lua
  Should Be Equal  ${result.stderr}  hello world
  Should Match Regexp  ${result.stdout}  ^$
  Should Be Equal As Integers  ${result.rc}  0

Verbose mode
  ${result} =  Rspamadm  -v  lua  ${RSPAMD_TESTDIR}/lua/rspamadm/test_verbose.lua
  Should Match Regexp  ${result.stderr}  ^$
  Should Match Regexp  ${result.stdout}  hello world\n
  Should Be Equal As Integers  ${result.rc}  0

*** Keywords ***
Rspamadm Setup
  ${RSPAMADM_TMPDIR} =  Make Temporary Directory
  Set Suite Variable  ${RSPAMADM_TMPDIR}

Rspamadm Teardown
  Cleanup Temporary Directory  ${RSPAMADM_TMPDIR}

Rspamadm
  [Arguments]  @{args}
  ${result} =  Run Process  ${RSPAMADM}
  ...  --var\=TMPDIR\=${RSPAMADM_TMPDIR}
  ...  --var\=DBDIR\=${RSPAMADM_TMPDIR}
  ...  --var\=LOCAL_CONFDIR\=/nonexistent
  ...  @{args}
  [Return]  ${result}
