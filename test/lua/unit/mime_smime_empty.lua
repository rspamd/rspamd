--[[
Regression test: SMIME signed-data wrapping an empty pkcs7-data must not crash
the MIME parser.

The base64 payload below decodes to a PKCS#7 ContentInfo of type
pkcs7-signedData whose inner encapsulated content is pkcs7-data with a
zero-length OCTET STRING. Before the fix, the parser allocated a zero-length
buffer for the inner content and recursed into rspamd_mime_process_multipart_node
with start == NULL (g_malloc(0) → NULL under always_malloc mempool mode),
dereferencing NULL on the first byte check.

This test exercises the SMIME inner-content extraction path. To deterministically
reproduce the original NULL deref, run with VALGRIND=1 in the environment, which
forces the rspamd mempool into always_malloc mode (matches the customer's crash
signature).
]]

context("MIME SMIME empty pkcs7-data", function()
  local rspamd_task = require "rspamd_task"

  test("pkcs7-mime with empty inner data must not crash parser", function()
    local msg = "From: sender@example.com\r\n" ..
        "To: rcpt@example.com\r\n" ..
        "Subject: smime empty\r\n" ..
        "MIME-Version: 1.0\r\n" ..
        "Content-Type: application/pkcs7-mime; smime-type=signed-data; name=\"smime.p7m\"\r\n" ..
        "Content-Transfer-Encoding: base64\r\n" ..
        "Content-Disposition: attachment; filename=\"smime.p7m\"\r\n" ..
        "\r\n" ..
        "MCcGCSqGSIb3DQEHAqAaMBgCAQExADAPBgkqhkiG9w0BBwGgAgQAMQA=\r\n"

    local res, task = rspamd_task.load_from_string(msg, rspamd_config)
    assert_true(res, "failed to load message")

    -- The crash was in rspamd_mime_process_multipart_node; reaching
    -- this point without a SIGSEGV is the assertion.
    task:process_message()
    task:destroy()
  end)
end)
