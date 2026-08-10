--[[
Boundary handling in lua_mime.remove_attachments.

Regression coverage for the same defect fixed in add_text_footer: the part walk
closed a single boundary when returning from a nested part to a shallower one,
rather than every level it had actually left behind. One level is enough for a
return of depth 2 -> 1, which is why the flat and single-nesting shapes always
worked, but a return of depth 3 -> 1 leaves the intermediate boundary on the
stack. Its closing delimiter is then emitted by the final unwind loop, after the
part that follows -- so it lands inside that part's body as literal text.

Reachable in production through `rspamadm mime strip`.

Each case asserts structural invariants rather than exact bytes:
  * every boundary is closed exactly once
  * every inner boundary closes before the trailing top-level part begins
  * kept text survives and the attachment is gone

Assertions live in the test bodies rather than in the helpers: telescope injects
assert_* into the environment of the test function only, so a helper defined at
context scope would see them as nil.
]]

context("lua_mime.remove_attachments", function()
  local rspamd_task = require "rspamd_task"
  local rspamd_util = require "rspamd_util"
  local rspamd_test_helper = require "rspamd_test_helper"
  local lua_mime = require "lua_mime"

  rspamd_test_helper.init_url_parser()
  local cfg = rspamd_util.config_from_ucl(rspamd_test_helper.default_config(),
      "INIT_URL,INIT_LIBS,INIT_SYMCACHE,INIT_VALIDATE,INIT_PRELOAD_MAPS")

  -- Reassemble the body the way rspamadm mime strip does.
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

  -- Strip attachments and return everything wrong with the result. `inner` is
  -- the list of boundaries nested below the top level; each must be closed
  -- before TRAILINGMARKER, the kept part that follows the nested subtree.
  local function strip_problems(message, inner)
    local res, task = rspamd_task.load_from_string(message, cfg)

    if not res or not task then
      return { 'failed to load message' }
    end

    task:process_message()

    local rewrite = lua_mime.remove_attachments(task, {})

    if not rewrite or not rewrite.out then
      task:destroy()
      return { 'remove_attachments did not rewrite the message' }
    end

    local body = body_to_string(rewrite)
    task:destroy()

    local problems = {}

    if not string.find(body, 'TRAILINGMARKER', 1, true) then
      problems[#problems + 1] = 'the trailing text part is missing entirely'
      return problems
    end

    if string.find(body, 'application/pdf', 1, true) then
      problems[#problems + 1] = 'the attachment was not removed'
    end

    local trailing = string.find(body, 'TRAILINGMARKER', 1, true)

    for _, b in ipairs(inner) do
      local close = '--' .. b .. '--'
      local n = count_substr(body, close)

      if n ~= 1 then
        problems[#problems + 1] = string.format(
            'expected exactly one closing delimiter for %s, got %d', b, n)
      end

      local pos = string.find(body, close, 1, true)

      if pos and pos > trailing then
        problems[#problems + 1] = string.format(
            'closing delimiter for %s lands at %d, after the trailing part at ' ..
                '%d, so it is literal text inside that part rather than a delimiter',
            b, pos, trailing)
      end
    end

    if count_substr(body, '--outerbnd--') ~= 1 then
      problems[#problems + 1] = 'expected exactly one top-level closing delimiter'
    end

    return problems
  end

  -- Control: nothing nested, so there is never more than one level to unwind.
  local msg_flat = [[
From: sender@example.com
To: rcpt@example.com
Subject: flat mixed
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="outerbnd"

--outerbnd
Content-Type: text/plain; charset=us-ascii

TRAILINGMARKER

--outerbnd
Content-Type: application/pdf
Content-Transfer-Encoding: base64
Content-Disposition: attachment; filename="doc.pdf"

JVBERi0xLjQKJcOkw7zDtsOfCg==

--outerbnd--
]]

  -- Return of depth 2 -> 1: a single pop is still sufficient here, so this
  -- shape passed both before and after the fix.
  local msg_one_level = [[
From: sender@example.com
To: rcpt@example.com
Subject: related then trailing text
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="outerbnd"

--outerbnd
Content-Type: multipart/related; boundary="relbnd"

--relbnd
Content-Type: text/html; charset=us-ascii

<html><body>html body</body></html>

--relbnd--
--outerbnd
Content-Type: text/plain; charset=us-ascii

TRAILINGMARKER

--outerbnd
Content-Type: application/pdf
Content-Transfer-Encoding: base64
Content-Disposition: attachment; filename="doc.pdf"

JVBERi0xLjQKJcOkw7zDtsOfCg==

--outerbnd--
]]

  -- Return of depth 3 -> 1: the smallest shape that leaves a boundary behind.
  local msg_two_levels = [[
From: sender@example.com
To: rcpt@example.com
Subject: alternative over related then trailing text
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="outerbnd"

--outerbnd
Content-Type: multipart/alternative; boundary="altbnd"

--altbnd
Content-Type: text/plain; charset=us-ascii

alternative plain

--altbnd
Content-Type: multipart/related; boundary="relbnd"

--relbnd
Content-Type: text/html; charset=us-ascii

<html><body>html body</body></html>

--relbnd--
--altbnd--
--outerbnd
Content-Type: text/plain; charset=us-ascii

TRAILINGMARKER

--outerbnd
Content-Type: application/pdf
Content-Transfer-Encoding: base64
Content-Disposition: attachment; filename="doc.pdf"

JVBERi0xLjQKJcOkw7zDtsOfCg==

--outerbnd--
]]

  -- Return of depth 4 -> 1: the number of boundaries left behind grows with
  -- nesting depth, so both altbnd and midbnd leak here.
  local msg_three_levels = [[
From: sender@example.com
To: rcpt@example.com
Subject: three levels then trailing text
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="outerbnd"

--outerbnd
Content-Type: multipart/mixed; boundary="midbnd"

--midbnd
Content-Type: multipart/alternative; boundary="altbnd"

--altbnd
Content-Type: text/plain; charset=us-ascii

alternative plain

--altbnd
Content-Type: multipart/related; boundary="relbnd"

--relbnd
Content-Type: text/html; charset=us-ascii

<html><body>html body</body></html>

--relbnd--
--altbnd--
--midbnd--
--outerbnd
Content-Type: text/plain; charset=us-ascii

TRAILINGMARKER

--outerbnd
Content-Type: application/pdf
Content-Transfer-Encoding: base64
Content-Disposition: attachment; filename="doc.pdf"

JVBERi0xLjQKJcOkw7zDtsOfCg==

--outerbnd--
]]

  test("flat multipart/mixed is unaffected", function()
    local problems = strip_problems(msg_flat, {})
    assert_equal(#problems, 0, table.concat(problems, '; '))
  end)

  test("single level of nesting closes cleanly", function()
    local problems = strip_problems(msg_one_level, { 'relbnd' })
    assert_equal(#problems, 0, table.concat(problems, '; '))
  end)

  test("two levels of nesting unwind before the trailing part", function()
    local problems = strip_problems(msg_two_levels, { 'relbnd', 'altbnd' })
    assert_equal(#problems, 0, table.concat(problems, '; '))
  end)

  test("three levels of nesting unwind before the trailing part", function()
    local problems = strip_problems(msg_three_levels,
        { 'relbnd', 'altbnd', 'midbnd' })
    assert_equal(#problems, 0, table.concat(problems, '; '))
  end)
end)
