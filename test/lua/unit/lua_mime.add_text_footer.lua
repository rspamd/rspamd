--[[
Boundary handling in lua_mime.add_text_footer.

Regression coverage for the boundary stack desynchronising when the part walk
returns from a nested part to a shallower one: the walk closed a fixed number of
boundaries (one, or two in the former multipart/related special case) rather than
every level it had actually left behind. Once the stack drifted,
`boundaries[#boundaries]` named an unrelated boundary and a closing delimiter for
the top-level one was emitted into the middle of the body. Everything after that
point is epilogue per RFC 2046, so attachments were still in the byte stream but
unreachable to any strict parser -- silently, with the message growing rather
than shrinking.

Each case asserts the same three invariants rather than exact bytes, so the tests
stay meaningful if footer placement or encoding changes:
  * exactly one top-level closing delimiter
  * every part appears before it
  * the footer is still applied

Assertions live in the test bodies rather than in the helpers: telescope injects
assert_* into the environment of the test function only, so a helper defined at
context scope would see them as nil.
]]

context("lua_mime.add_text_footer", function()
  local rspamd_task = require "rspamd_task"
  local rspamd_util = require "rspamd_util"
  local rspamd_test_helper = require "rspamd_test_helper"
  local lua_mime = require "lua_mime"

  rspamd_test_helper.init_url_parser()
  local cfg = rspamd_util.config_from_ucl(rspamd_test_helper.default_config(),
      "INIT_URL,INIT_LIBS,INIT_SYMCACHE,INIT_VALIDATE,INIT_PRELOAD_MAPS")

  local html_footer = '<p>FOOTERMARKER</p>'
  local text_footer = 'FOOTERMARKER'

  -- Reassemble the body the same way rspamadm mime does: bare strings get a
  -- newline appended, table entries carry an explicit "add a newline" flag.
  local function body_to_string(rewrite)
    local buf = {}

    for _, o in ipairs(rewrite.out) do
      if type(o) == 'string' then
        buf[#buf + 1] = o
        buf[#buf + 1] = rewrite.newline_s
      elseif type(o) == 'table' then
        buf[#buf + 1] = tostring(o[1])

        if o[2] then
          buf[#buf + 1] = rewrite.newline_s
        end
      else
        buf[#buf + 1] = tostring(o)
      end
    end

    return table.concat(buf)
  end

  local function count_substr(haystack, needle)
    local n = 0
    local pos = 1

    while true do
      local s, e = string.find(haystack, needle, pos, true)

      if not s then
        break
      end

      n = n + 1
      pos = e + 1
    end

    return n
  end

  -- Apply the footer and return a list of everything wrong with the result, so
  -- the test body can assert on it. Empty list means the message is intact.
  local function footer_problems(message, markers)
    local res, task = rspamd_task.load_from_string(message, cfg)

    if not res or not task then
      return { 'failed to load message' }
    end

    task:process_message()

    local rewrite = lua_mime.add_text_footer(task, html_footer, text_footer)

    if not rewrite or not rewrite.out then
      task:destroy()
      return { 'add_text_footer did not rewrite the message' }
    end

    local body = body_to_string(rewrite)
    task:destroy()

    local problems = {}
    local n_close = count_substr(body, '--outerbnd--')

    if n_close ~= 1 then
      problems[#problems + 1] = string.format(
          'expected exactly one top-level closing delimiter, got %d', n_close)
    end

    local close = string.find(body, '--outerbnd--', 1, true)

    if not close then
      problems[#problems + 1] = 'top-level boundary is never closed'
    else
      for _, marker in ipairs(markers) do
        local pos = string.find(body, marker, 1, true)

        if not pos then
          problems[#problems + 1] = string.format('part %s is missing entirely',
              marker)
        elseif pos > close then
          problems[#problems + 1] = string.format(
              'part %s lands after the top-level closing delimiter at %d/%d, ' ..
                  'so it is RFC 2046 epilogue and unreachable',
              marker, close, #body)
        end
      end
    end

    if not string.find(body, 'FOOTERMARKER', 1, true) then
      problems[#problems + 1] = 'footer was not applied'
    end

    return problems
  end

  -- multipart/related sitting directly under the top-level multipart/mixed, with
  -- an attachment after it. Three parts, no message/rfc822 nesting -- the
  -- smallest shape that desynchronises the stack.
  local msg_mixed_related = [[
From: sender@example.com
To: rcpt@example.com
Subject: mixed over related with a trailing attachment
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="outerbnd"

--outerbnd
Content-Type: multipart/related; boundary="relbnd"

--relbnd
Content-Type: text/html; charset=utf-8
Content-Transfer-Encoding: 7bit

<html><body><p>Hello</p><img src="cid:img@example.com"></body></html>

--relbnd
Content-Type: image/png
Content-Transfer-Encoding: base64
Content-ID: <img@example.com>

iVBORw0KGgo=

--relbnd--

--outerbnd
Content-Type: application/pdf
Content-Transfer-Encoding: base64
Content-Disposition: attachment; filename="ATTACHMENTMARKER.pdf"

cGF5bG9hZCBkYXRhCg==

--outerbnd--
]]

  -- The same message with a text/plain alternative pushing multipart/related one
  -- level down. This is the shape addressed by the earlier multipart/related
  -- special case, and it must keep working now that the special case is gone.
  local msg_mixed_alt_related = [[
From: sender@example.com
To: rcpt@example.com
Subject: mixed over alternative over related with a trailing attachment
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="outerbnd"

--outerbnd
Content-Type: multipart/alternative; boundary="altbnd"

--altbnd
Content-Type: text/plain; charset=utf-8
Content-Transfer-Encoding: 7bit

PLAINMARKER

--altbnd
Content-Type: multipart/related; boundary="relbnd"

--relbnd
Content-Type: text/html; charset=utf-8
Content-Transfer-Encoding: 7bit

<html><body><p>Hello</p><img src="cid:img@example.com"></body></html>

--relbnd
Content-Type: image/png
Content-Transfer-Encoding: base64
Content-ID: <img@example.com>

iVBORw0KGgo=

--relbnd--

--altbnd--

--outerbnd
Content-Type: application/pdf
Content-Transfer-Encoding: base64
Content-Disposition: attachment; filename="ATTACHMENTMARKER.pdf"

cGF5bG9hZCBkYXRhCg==

--outerbnd--
]]

  -- A forwarded message whose body nests multipart/related one level deeper,
  -- followed by a further top-level attachment. Two levels are left behind when
  -- the walk returns to the outer container.
  local msg_nested_rfc822 = [[
From: forwarder@example.com
To: rcpt@example.com
Subject: forwarded bundle
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="outerbnd"

--outerbnd
Content-Type: text/plain; charset=utf-8
Content-Transfer-Encoding: 7bit

INTROMARKER

--outerbnd
Content-Type: message/rfc822
Content-Transfer-Encoding: 8bit
Content-Disposition: attachment; filename="nested.eml"
MIME-Version: 1.0

From: inner@example.com
To: rcpt@example.com
Subject: nested message
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="innerbnd"

--innerbnd
Content-Type: multipart/related; boundary="relbnd"

--relbnd
Content-Type: text/html; charset=utf-8
Content-Transfer-Encoding: 7bit

<html><body><p>Nested</p><img src="cid:img@example.com"></body></html>

--relbnd
Content-Type: image/png
Content-Transfer-Encoding: base64
Content-ID: <img@example.com>

iVBORw0KGgo=

--relbnd--

--innerbnd
Content-Type: text/plain; charset=utf-8
Content-Transfer-Encoding: base64
Content-Disposition: attachment; filename="INNERMARKER.txt"

cGF5bG9hZCBkYXRhCg==

--innerbnd--

--outerbnd
Content-Type: application/pdf
Content-Transfer-Encoding: base64
Content-Disposition: attachment; filename="ATTACHMENTMARKER.pdf"

cGF5bG9hZCBkYXRhCg==

--outerbnd--
]]

  test("multipart/mixed over multipart/related keeps a trailing attachment reachable",
      function()
        local problems = footer_problems(msg_mixed_related, { 'ATTACHMENTMARKER' })
        assert_equal(0, #problems, table.concat(problems, '; '))
      end)

  test("multipart/alternative between mixed and related is not regressed",
      function()
        local problems = footer_problems(msg_mixed_alt_related,
            { 'PLAINMARKER', 'ATTACHMENTMARKER' })
        assert_equal(0, #problems, table.concat(problems, '; '))
      end)

  test("nested message/rfc822 unwinds every level it leaves behind",
      function()
        local problems = footer_problems(msg_nested_rfc822,
            { 'INTROMARKER', 'INNERMARKER', 'ATTACHMENTMARKER' })
        assert_equal(0, #problems, table.concat(problems, '; '))
      end)
end)
