*** Settings ***
Suite Setup     Rspamadm Setup
Suite Teardown  Rspamadm Teardown
Library         ${RSPAMD_TESTDIR}/lib/rspamd.py
Resource        ${RSPAMD_TESTDIR}/lib/rspamd.robot

*** Variables ***
${TEXT}                text
${KEY}                 12345678901234567890123456789012
${NONCE}               9pyeEd986hrjcpozCIZ41jEo6dCDbgjg
${ENCRYPTED_TEXT}      8KGF6VLI7vnweUdR8FuQZuT+ID8=
${PYTHON_SCRIPT}       ${RSPAMD_TESTDIR}/../../utils/encrypt_decrypt_header.py

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
  
SecretBox test encrypt/decrypt
  ${result} =  Rspamadm  secret_box  encrypt  -t  ${TEXT}  -k  ${KEY}  -n  ${NONCE}
  Should Match Regexp  ${result.stderr}  ^$
  Should Be Equal As Strings  ${result.stdout}  ${NONCE}${ENCRYPTED_TEXT}
  ${result1} =  Rspamadm  secret_box  decrypt  -t  ${ENCRYPTED_TEXT}  -k  ${KEY}  -n  ${NONCE}
  Should Match Regexp  ${result.stderr}  ^$
  Should Be Equal As Strings  ${result1.stdout}  ${TEXT}

SecretBox test python encrypt/decrypt
  ${result} =  Run Process  python3  ${PYTHON_SCRIPT}  encrypt  --text  ${TEXT}  --key  ${KEY}  --nonce  ${NONCE}
  Should Match Regexp  ${result.stderr}  ^$
  Should Be Equal As Strings  ${result.stdout}  ${NONCE}${ENCRYPTED_TEXT}
  ${result1} =  Run Process  python  ${PYTHON_SCRIPT}  decrypt  --encrypted_text  ${NONCE}${ENCRYPTED_TEXT}  --key  ${KEY}
  Should Match Regexp  ${result.stderr}  ^$
  Should Be Equal As Strings  ${result1.stdout}  ${TEXT}
  
SecretBox test encrypt python decrypt rspamadm
  ${result} =  Run Process  python3  ${PYTHON_SCRIPT}  encrypt  --text  ${TEXT}  --key  ${KEY}  --nonce  ${NONCE}
  ${result1} =  Rspamadm  secret_box  decrypt  -t  ${result.stdout}  -k  ${KEY}
  Should Match Regexp  ${result.stderr}  ^$
  Should Be Equal As Strings  ${TEXT}  ${result1.stdout}

SecretBox test encrypt rspamadm decrypt python
  ${result} =  Rspamadm  secret_box  encrypt  -t  ${TEXT}  -k  ${KEY}  -n  ${NONCE}
  ${result1} =  Run Process  python3  ${PYTHON_SCRIPT}  decrypt  --encrypted_text  ${result.stdout}  --key  ${KEY}
  Should Match Regexp  ${result.stderr}  ^$
  Should Be Equal As Strings  ${TEXT}  ${result1.stdout}
