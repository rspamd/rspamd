-- MIME address list parser tests (rspamd_email_address_from_mime via util.parse_mail_address)

context("MIME address list parser", function()
  local util = require "rspamd_util"
  local fun = require "fun"

  -- Each case: {input, {expected entries}}; every expected entry is a subset
  -- match over addr/user/domain/name/valid
  local cases = {
    -- Single addresses
    { 'a@example.com',
      { { addr = 'a@example.com', user = 'a', domain = 'example.com', valid = true } } },
    { '<a@example.com>',
      { { addr = 'a@example.com', valid = true } } },
    { 'A Name <a@example.com>',
      { { addr = 'a@example.com', name = 'A Name', valid = true } } },
    { '"Quoted Name" <a@example.com>',
      { { addr = 'a@example.com', name = 'Quoted Name', valid = true } } },
    { 'a@example.com (ignored comment)',
      { { addr = 'a@example.com', valid = true } } },
    { 'Тест <a@example.com>',
      { { addr = 'a@example.com', name = 'Тест', valid = true } } },

    -- Comma-separated lists
    { 'a@example.com,b@example.org',
      { { addr = 'a@example.com', valid = true },
        { addr = 'b@example.org', valid = true } } },
    { 'a@example.com, b@example.org',
      { { addr = 'a@example.com', valid = true },
        { addr = 'b@example.org', valid = true } } },
    { 'A <a@x.com>, B <b@y.com>',
      { { addr = 'a@x.com', name = 'A', valid = true },
        { addr = 'b@y.com', name = 'B', valid = true } } },
    { 'a@x.com,,b@y.com',
      { { addr = 'a@x.com', valid = true },
        { addr = 'b@y.com', valid = true } } },
    { 'a@x.com,',
      { { addr = 'a@x.com', valid = true } } },

    -- Semicolon-separated lists: not an RFC 5322 list separator, but a
    -- pervasive real-world (Outlook-style) convention treated like a comma
    { 'user1@example.com;user2@example.com',
      { { addr = 'user1@example.com', user = 'user1', valid = true },
        { addr = 'user2@example.com', user = 'user2', valid = true } } },
    { 'user1@example.com; user2@example.com',
      { { addr = 'user1@example.com', valid = true },
        { addr = 'user2@example.com', valid = true } } },
    { 'A <a@x.com>; B <b@y.com>',
      { { addr = 'a@x.com', name = 'A', valid = true },
        { addr = 'b@y.com', name = 'B', valid = true } } },
    { 'a@x.com, b@y.com; c@z.com',
      { { addr = 'a@x.com', valid = true },
        { addr = 'b@y.com', valid = true },
        { addr = 'c@z.com', valid = true } } },
    { 'a@x.com;',
      { { addr = 'a@x.com', valid = true } } },

    -- Separators in display names: quoted ones are preserved, unquoted ones
    -- drop the leading part of the phrase (same for ',' and ';')
    { '"Semi; Name" <a@x.com>',
      { { addr = 'a@x.com', name = 'Semi; Name', valid = true } } },
    { 'Semi; Name <a@x.com>',
      { { addr = 'a@x.com', name = 'Name', valid = true } } },
    { 'Comma, Name <a@x.com>',
      { { addr = 'a@x.com', name = 'Name', valid = true } } },

    -- Group constructs: members are extracted, the group display name is
    -- currently glued to the first member (heuristic parse), the trailing
    -- ';' terminates the last member cleanly
    { 'mygroup: a@x.com, b@y.com;',
      { { domain = 'x.com' },
        { addr = 'b@y.com', user = 'b', domain = 'y.com', valid = true } } },

    -- No addresses at all: a single fake entry holding the text as the name
    { 'Undisclosed recipients',
      { { addr = '', name = 'Undisclosed recipients' } } },

    -- Empty group: no members, no entries (same as `undisclosed-recipients:,')
    { 'undisclosed-recipients:;', {} },
  }

  -- Only the number of parsed entries is stable for these
  local count_only_cases = {
    -- Semicolon inside a quoted string must not split the element
    { '"quoted;semi"@example.com', 1 },
  }

  fun.each(function(case)
    test("Parse MIME addr list: " .. case[1], function()
      local res = util.parse_mail_address(case[1])
      local nexpected = #case[2]

      if nexpected == 0 then
        assert_true(res == nil or #res == 0,
            string.format('expected no addresses, got %s', res and #res or 0))
        return
      end

      assert_not_nil(res, 'should parse ' .. case[1])
      assert_equal(#res, nexpected,
          string.format('expected %s addresses, got %s', nexpected, #res))

      for i, expected in ipairs(case[2]) do
        local got = res[i]
        for k, ex in pairs(expected) do
          if k == 'valid' then
            assert_equal(got.flags.valid or false, ex,
                string.format('[%d] validity mismatch for %s', i, case[1]))
          else
            assert_equal(got[k], ex,
                string.format('[%d] field %s mismatch for %s', i, k, case[1]))
          end
        end
      end
    end)
  end, cases)

  fun.each(function(case)
    test("Parse MIME addr list (count): " .. case[1], function()
      local res = util.parse_mail_address(case[1])
      assert_not_nil(res, 'should parse ' .. case[1])
      assert_equal(#res, case[2],
          string.format('expected %s addresses, got %s', case[2], #res))
    end)
  end, count_only_cases)
end)
