*** Settings ***
Suite Setup     Rspamadm Setup
Suite Teardown  Rspamadm Teardown
Library         ${RSPAMD_TESTDIR}/lib/rspamd.py
Resource        ${RSPAMD_TESTDIR}/lib/rspamd.robot
Variables       ${RSPAMD_TESTDIR}/lib/vars.py
Test Timeout    1 minute

*** Variables ***
${TEXT}                text
${KEY}                 12345678901234567890123456789012
${NONCE}               9pyeEd986hrjcpozCIZ41jEo6dCDbgjg
${ENCRYPTED_TEXT}      8KGF6VLI7vnweUdR8FuQZuT+ID8=
${PYTHON_SCRIPT}       ${RSPAMD_TESTDIR}/../../utils/encrypt_decrypt_header.py

*** Test Cases ***
MIME HTML Structure Has Bounded Content Previews
  ${body} =  Evaluate  '<span>' + 'x' * 4095 + chr(0x20ac) + '</span>' + ('<span>' + 'x' * 5000) * 300
  ${message} =  Catenate  SEPARATOR=\n  Content-Type: text/html; charset=utf-8  ${EMPTY}  ${body}
  Create File  ${RSPAMADM_TMPDIR}/nested.eml  ${message}
  ${result} =  Rspamadm  mime  -j  extract  --html  --structure  ${RSPAMADM_TMPDIR}/nested.eml
  Should Be Equal As Integers  ${result.rc}  0  msg=${result.stderr}
  ${tags} =  Evaluate  list(json.loads($result.stdout).values())[0][0]  modules=json
  ${lengths} =  Evaluate  [len(t.get('content', '').encode('utf-8')) for t in $tags]
  Should Be True  max($lengths) <= 4096
  Should Be True  sum($lengths) <= 1024 * 1024
  Should Be True  any(t.get('content_truncated') for t in $tags)
  Should Be True  any(t.get('content_length') == 4098 and len(t['content']) == 4095 for t in $tags)

MIME HTML Structure Serializes URL Extras
  ${message} =  Catenate  SEPARATOR=\n
  ...  Content-Type: text/html
  ...  ${EMPTY}
  ...  <a href="https://example.com/path">Click here</a>
  Create File  ${RSPAMADM_TMPDIR}/url.eml  ${message}
  ${result} =  Rspamadm  mime  -j  extract  --html  --structure  ${RSPAMADM_TMPDIR}/url.eml
  Should Be Equal As Integers  ${result.rc}  0  msg=${result.stderr}
  ${tags} =  Evaluate  list(json.loads($result.stdout).values())[0][0]  modules=json
  Should Be True  any(t.get('extra') == 'https://example.com/path' and t['content'] == 'Click here' for t in $tags)

MIME Bayes Tokens Keep Alternative Body With Injected Text
  # The SVG text is injected before the similar alternatives, which still
  # must be tokenized once
  ${result} =  Rspamadm  mime  stat  -b  ${RSPAMD_TESTDIR}/messages/alternative-svg-text.eml
  Should Be Equal As Integers  ${result.rc}  0  msg=${result.stderr}
  Should Contain  ${result.stdout}  "spreadsheet"
  Should Contain  ${result.stdout}  "orchestra"

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

Interpreter does not keep the results of a line
  [Documentation]  The values returned by a line are printed, then nothing
  ...              holds them: the weak table loses the table returned by the
  ...              second line
  ${input} =  Catenate  SEPARATOR=\n
  ...  w = setmetatable({}, {__mode = 'v'})
  ...  (function() local t = {} w[1] = t return t end)()
  ...  (function() collectgarbage() collectgarbage() return w[1] ~= nil end)()
  Create File  ${RSPAMADM_TMPDIR}/repl_gc.txt  ${input}\n
  ${result} =  Run Process  ${RSPAMADM}  lua  -b  stdin=${RSPAMADM_TMPDIR}/repl_gc.txt
  Should Be Equal As Integers  ${result.rc}  0  msg=${result.stderr}
  Should Be Equal  ${result.stdout}  {}\nfalse

Interpreter served over HTTP
  [Documentation]  /exec replies with the values that the code returns, or
  ...              with its error. No rspamd runs in this suite, so the port
  ...              of its scanner is free
  ${handle} =  Start Process  ${RSPAMADM}  lua  -S  ${RSPAMD_LOCAL_ADDR}:${RSPAMD_PORT_NORMAL}
  ...  stdout=${RSPAMADM_TMPDIR}/serve.stdout  stderr=${RSPAMADM_TMPDIR}/serve.stderr
  Wait Until Keyword Succeeds  30x  0.2s  TCP Connect  ${RSPAMD_LOCAL_ADDR}  ${RSPAMD_PORT_NORMAL}
  @{result} =  HTTP  POST  ${RSPAMD_LOCAL_ADDR}  ${RSPAMD_PORT_NORMAL}  /exec  return 1, {a = 1}
  Should Be Equal As Integers  ${result}[0]  200
  ${reply} =  Evaluate  json.loads($result[1])  modules=json
  Should Be Equal  ${reply}  ${{ [1, {'a': 1}] }}
  @{result} =  HTTP  POST  ${RSPAMD_LOCAL_ADDR}  ${RSPAMD_PORT_NORMAL}  /exec  error('exec fails on purpose')
  Should Contain  ${result}[1]  exec fails on purpose
  @{result} =  HTTP  POST  ${RSPAMD_LOCAL_ADDR}  ${RSPAMD_PORT_NORMAL}  /exec  local x = 5
  Should Be Equal As Integers  ${result}[0]  200
  ${reply} =  Evaluate  json.loads($result[1])  modules=json
  Should Be Equal  ${reply}  ${{ [] }}
  [Teardown]  Terminate Process  ${handle}

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

Password Check Via Env Correct
  ${enc} =  Rspamadm  pw  -p  nq1
  ${result} =  Run Process  ${RSPAMADM}  pw  -c  -p  ${enc.stdout}  env:RSPAMADM_PASSWORD=nq1
  Should Contain  ${result.stdout}  password correct
  Should Be Equal As Integers  ${result.rc}  0

Password Check Via Env Wrong
  ${enc} =  Rspamadm  pw  -p  nq1
  ${result} =  Run Process  ${RSPAMADM}  pw  -c  -p  ${enc.stdout}  env:RSPAMADM_PASSWORD=wrongpassword
  Should Contain  ${result.stdout}  password incorrect
  Should Be Equal As Integers  ${result.rc}  1

SecretBox rspamadm encrypt/decrypt
  ${result} =  Rspamadm  secret_box  -B  encrypt  -t  ${TEXT}  -k  ${KEY}  -n  ${NONCE}
  Should Match Regexp  ${result.stderr}  ^$
  Should Be Equal As Strings  ${result.stdout}  ${NONCE}${ENCRYPTED_TEXT}
  ${result1} =  Rspamadm  secret_box  -B  decrypt  -t  ${ENCRYPTED_TEXT}  -k  ${KEY}  -n  ${NONCE}
  Should Match Regexp  ${result.stderr}  ^$
  Should Be Equal As Strings  ${result1.stdout}  ${TEXT}

SecretBox python encrypt/decrypt
  ${result} =  Run Process  python3  ${PYTHON_SCRIPT}  -B  encrypt  -t  ${TEXT}  -k  ${KEY}  -n  ${NONCE}
  Should Match Regexp  ${result.stderr}  ^$
  Should Be Equal As Strings  ${result.stdout}  ${NONCE}${ENCRYPTED_TEXT}
  ${result1} =  Run Process  python3  ${PYTHON_SCRIPT}  -B  decrypt  -t  ${NONCE}${ENCRYPTED_TEXT}  -k  ${KEY}
  Should Match Regexp  ${result.stderr}  ^$
  Should Be Equal As Strings  ${result1.stdout}  ${TEXT}

SecretBox encrypt python with nonce decrypt rspamadm
  ${result} =  Run Process  python3  ${PYTHON_SCRIPT}  -B  encrypt  -t  ${TEXT}  -k  ${KEY}  -n  ${NONCE}
  ${result1} =  Rspamadm  secret_box  -B  decrypt  -t  ${result.stdout}  -k  ${KEY}
  Should Match Regexp  ${result.stderr}  ^$
  Should Be Equal As Strings  ${TEXT}  ${result1.stdout}

SecretBox encrypt python without nonce decrypt rspamadm
  ${result} =  Run Process  python3  ${PYTHON_SCRIPT}  -B  encrypt  -t  ${TEXT}  -k  ${KEY}
  ${result1} =  Rspamadm  secret_box  -B  decrypt  -t  ${result.stdout}  -k  ${KEY}
  Should Match Regexp  ${result.stderr}  ^$
  Should Be Equal As Strings  ${TEXT}  ${result1.stdout}

SecretBox encrypt rspamadm with nonce decrypt python
  ${result} =  Rspamadm  secret_box  -B  encrypt  -t  ${TEXT}  -k  ${KEY}  -n  ${NONCE}
  ${result1} =  Run Process  python3  ${PYTHON_SCRIPT}  -B  decrypt  -t  ${result.stdout}  -k  ${KEY}
  Should Match Regexp  ${result.stderr}  ^$
  Should Be Equal As Strings  ${TEXT}  ${result1.stdout}

SecretBox encrypt rspamadm without nonce decrypt python
  ${result} =  Rspamadm  secret_box  -B  encrypt  -t  ${TEXT}  -k  ${KEY}
  ${result1} =  Run Process  python3  ${PYTHON_SCRIPT}  -B  decrypt  -t  ${result.stdout}  -k  ${KEY}
  Should Match Regexp  ${result.stderr}  ^$
  Should Be Equal As Strings  ${TEXT}  ${result1.stdout}
