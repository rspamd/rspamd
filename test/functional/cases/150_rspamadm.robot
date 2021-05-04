*** Settings ***
Library         Process
Library         ../lib/rspamd.py

Suite Teardown    Terminate All Processes    kill=True

*** Test Cases ***
Config Test
  ${result} =  Run Process  ${RSPAMADM}  configtest
  Should Match Regexp  ${result.stderr}  ^$
  Should Match Regexp  ${result.stdout}  ^syntax OK$
  Should Be Equal As Integers  ${result.rc}  0

Config Help
  ${result} =  Run Process  ${RSPAMADM}  confighelp
  Should Match Regexp  ${result.stderr}  ^$
  Should Be Equal As Integers  ${result.rc}  0

Simple interpreter
  ${handle} =  Start Process  ${RSPAMADM}  lua
  ${result} =  Write to stdin  ${handle}  1+1
  Should Be Equal As Strings  ${result}  2\n

Simple interpreter, two results
  ${handle} =  Start Process  ${RSPAMADM}  lua
  ${result} =  Write to stdin  ${handle}  1+1, 2 * 5
  Should Be Equal  ${result}  2\n10\n

Process message callback
  ${handle} =  Start Process  ${RSPAMADM}  lua
  ${result} =  Write to stdin  ${handle}  .load ${RSPAMD_TESTDIR}/lua/rspamadm/test_message_callback.lua\n.message message_callback ${RSPAMD_TESTDIR}/messages/empty_part.eml
  Should Contain  ${result}  n parts = 2
  Should Contain  ${result}  1\n2\n4\n6

Lua batch mode
  ${result} =  Run Process  ${RSPAMADM}  lua  -b  ${RSPAMD_TESTDIR}/lua/rspamadm/test_batch.lua
  Should Match Regexp  ${result.stderr}  ^$
  Should Be Equal As Integers  ${result.rc}  0
  Should Be Equal  ${result.stdout}  hello world

