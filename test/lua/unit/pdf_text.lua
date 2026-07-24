-- Regression test for PDF text extraction line breaks.
-- The `Td`/`TD` text positioning operators must render a newline when they move
-- to a new text line (non-zero vertical displacement). Otherwise consecutive
-- lines get concatenated, e.g. "...June 1, 2026." + "You may obtain..." becomes
-- "2026.You", which the URL parser then mis-detects as the URL http://2026.you.

context("PDF content text extraction", function()
  local rspamd_task = require "rspamd_task"
  local rspamd_util = require "rspamd_util"
  local rspamd_test_helper = require "rspamd_test_helper"

  rspamd_test_helper.init_url_parser()
  local cfg = rspamd_util.config_from_ucl(rspamd_test_helper.default_config(),
      "INIT_URL,INIT_LIBS,INIT_SYMCACHE,INIT_VALIDATE,INIT_PRELOAD_MAPS")

  -- A minimal uncompressed PDF whose content stream separates two lines with
  -- `0 -14 Td`. See test/lua/unit/pdf_text.lua header for the rationale.
  local message = [[
From: sender@example.com
To: rcpt@example.com
Subject: pdf td line breaks
MIME-Version: 1.0
Content-Type: application/pdf; name="test.pdf"
Content-Transfer-Encoding: base64
Content-Disposition: attachment; filename="test.pdf"

JVBERi0xLjQKJeLjz9MKMSAwIG9iago8PCAvVHlwZSAvQ2F0YWxvZyAvUGFnZXMg
MiAwIFIgPj4KZW5kb2JqCjIgMCBvYmoKPDwgL1R5cGUgL1BhZ2VzIC9LaWRzIFsz
IDAgUl0gL0NvdW50IDEgPj4KZW5kb2JqCjMgMCBvYmoKPDwgL1R5cGUgL1BhZ2Ug
L1BhcmVudCAyIDAgUiAvTWVkaWFCb3ggWzAgMCA2MTIgNzkyXSAvQ29udGVudHMg
NCAwIFIgL1Jlc291cmNlcyA8PCAvRm9udCA8PCAvRjEgNSAwIFIgPj4gPj4gPj4K
ZW5kb2JqCjQgMCBvYmoKPDwgL0xlbmd0aCAxNjEgPj4Kc3RyZWFtCnEKQlQKL0Yx
IDEwIFRmCjcyIDcyMCBUZApbKFJlcG9ydHMgb24gRm9ybSA4LUsgZmlsZWQgb24g
TWF5IDEsIDIwMjYgYW5kIEp1bmUgMSwgMjAyNi4pXVRKCjAgLTE0IFRkClsoWW91
IG1heSBvYnRhaW4gYSBjb3B5IG9mIHRoZXNlIGZpbGluZ3MgYXQgbm8gY29zdC4p
XVRKCkVUClEKZW5kc3RyZWFtCmVuZG9iago1IDAgb2JqCjw8IC9UeXBlIC9Gb250
IC9TdWJ0eXBlIC9UeXBlMSAvQmFzZUZvbnQgL0hlbHZldGljYSA+PgplbmRvYmoK
eHJlZgowIDYKMDAwMDAwMDAwMCA2NTUzNSBmIAowMDAwMDAwMDE1IDAwMDAwIG4g
CjAwMDAwMDAwNjQgMDAwMDAgbiAKMDAwMDAwMDEyMSAwMDAwMCBuIAowMDAwMDAw
MjQ3IDAwMDAwIG4gCjAwMDAwMDA0NTggMDAwMDAgbiAKdHJhaWxlcgo8PCAvUm9v
dCAxIDAgUiAvU2l6ZSA2ID4+CnN0YXJ0eHJlZgo1MjgKJSVFT0YK
]]

  local function injected_pdf_text(task)
    for _, p in ipairs(task:get_parts(true) or {}) do
      if p:is_injected() and p:is_text() then
        local tp = p:get_text()
        if tp then
          return tostring(tp:get_content())
        end
      end
    end
    return nil
  end

  test("Td line breaks produce newlines, not joined text", function()
    local res, task = rspamd_task.load_from_string(message, cfg)
    assert_true(res, "failed to load message")
    task:process_message()

    local text = injected_pdf_text(task)
    -- Sanity: the PDF text must have been extracted at all
    assert_not_nil(text, "no text was extracted from the PDF part")
    assert_not_nil(text:find("You may obtain", 1, true),
        "expected extracted PDF text to contain the second line")

    -- The two lines must not be concatenated across the `Td` line break.
    -- Joining them yields "2026.You", which the URL parser mis-detects as the
    -- URL http://2026.you -- the false positive that motivated this fix.
    assert_nil(text:find("2026.You", 1, true),
        "PDF Td line break was dropped: lines were joined ('2026.You')")

    task:destroy()
  end)
end)
