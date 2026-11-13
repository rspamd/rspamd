--[[
Copyright (c) 2022, Vsevolod Stakhov <vsevolod@rspamd.com>
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this
list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice,
this list of conditions and the following disclaimer in the documentation
and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
]]--

context("Headers folding unit test", function()
  local util = require("rspamd_util")
    -- {header, value}, "expected result"
  local cases = {
    {{"test", "test"}, "test"},
    {{"test1", "_abc _def _ghi _fdjhfd _fhdjkfh _dkhkjd _fdjkf _dshfdks _fhdjfdkhfk _dshfds _fdsjk _fdkhfdks _fdsjf _dkf"},
     "_abc _def _ghi _fdjhfd _fhdjkfh _dkhkjd _fdjkf _dshfdks\r\n\t_fhdjfdkhfk _dshfds _fdsjk _fdkhfdks _fdsjf _dkf"
    },
    {{"Test1", "_abc _def _ghi _fdjhfd _fhdjkfh _dkhaaaaaaaaaaakjdfdjkfdshfdksfhdjfdkhfkdshfdsfdsjkfdkhfdksfdsjf _dkf"},
     "_abc _def _ghi _fdjhfd _fhdjkfh\r\n\t_dkhaaaaaaaaaaakjdfdjkfdshfdksfhdjfdkhfkdshfdsfdsjkfdkhfdksfdsjf\r\n\t_dkf"
    },
    {{"Content-Type", "multipart/mixed; boundary=\"---- =_NextPart_000_01BDBF1F.DA8F77EE\"hhhhhhhhhhhhhhhhhhhhhhhhh fjsdhfkjsd fhdjsfhkj"},
     "multipart/mixed; boundary=\"---- =_NextPart_000_01BDBF1F.DA8F77EE\"hhhhhhhhhhhhhhhhhhhhhhhhh\r\n\tfjsdhfkjsd fhdjsfhkj"
    },
    {{"Content-Type", "multipart/mixed; boundary=\"---- =_NextPart_000_01BDBF1F.DA8F77EE\"hkjhgkfhgfhgf\"hfkjdhf fhjf fghjghf fdshjfhdsj\" hgjhgfjk"},
     "multipart/mixed; boundary=\"---- =_NextPart_000_01BDBF1F.DA8F77EE\"hkjhgkfhgfhgf\"hfkjdhf fhjf fghjghf fdshjfhdsj\" hgjhgfjk"
    },
    {{"Content-Type", "Content-Type: multipart/mixed; boundary=\"---- =_NextPart_000_01BDBF1F.DA8F77EE\" abc def ghfdgfdsgj fdshfgfsdgfdsg hfsdgjfsdg fgsfgjsg"},
     "Content-Type: multipart/mixed; boundary=\"---- =_NextPart_000_01BDBF1F.DA8F77EE\" abc\r\n\tdef ghfdgfdsgj fdshfgfsdgfdsg hfsdgjfsdg fgsfgjsg"
    },
    {{"X-Spam-Symbols", "Returnpath_BL2,HFILTER_FROM_BOUNCE,R_PARTS_DIFFER,R_IP_PBL,R_ONE_RCPT,R_googleredir,R_TO_SEEMS_AUTO,R_SPF_NEUTRAL,R_PRIORITY_3,RBL_SPAMHAUS_PBL,HFILTER_MID_NOT_FQDN,MISSING_CTE,R_HAS_URL,RBL_SPAMHAUS_CSS,RBL_SPAMHAUS_XBL,BAYES_SPAM,RECEIVED_RBL10", ','},
     "Returnpath_BL2,\r\n\tHFILTER_FROM_BOUNCE,\r\n\tR_PARTS_DIFFER,\r\n\tR_IP_PBL,\r\n\tR_ONE_RCPT,\r\n\tR_googleredir,\r\n\tR_TO_SEEMS_AUTO,\r\n\tR_SPF_NEUTRAL,\r\n\tR_PRIORITY_3,\r\n\tRBL_SPAMHAUS_PBL,\r\n\tHFILTER_MID_NOT_FQDN,\r\n\tMISSING_CTE,\r\n\tR_HAS_URL,\r\n\tRBL_SPAMHAUS_CSS,\r\n\tRBL_SPAMHAUS_XBL,\r\n\tBAYES_SPAM,\r\n\tRECEIVED_RBL10"
    },
  }
  local function escape_spaces(str)
    str = string.gsub(str, '[\r\n]+', '<NL>')
    str = string.gsub(str, '[ ]', '<SP>')
    str = string.gsub(str, '[\t]', '<TB>')

    return str
  end
  for i,c in ipairs(cases) do
    test("Headers folding: " .. i, function()
      local fv = util.fold_header(c[1][1], c[1][2], 'crlf', c[1][3])
      assert_not_nil(fv)
      assert_equal(fv, c[2], string.format("'%s' doesn't match with '%s'",
              escape_spaces(c[2]), escape_spaces(fv)))
    end)
  end
end)

context("Unstructured header folding unit test", function()
  local util = require("rspamd_util")

  local function unfold(str)
    return (string.gsub(str, '\r?\n', ''))
  end

  test("folds before existing whitespace and keeps it", function()
    local words = {}
    for i = 1, 10 do
      words[i] = string.format('w%09d', i)
    end
    local folded = util.fold_header_unstructured('X', table.concat(words, ' '))
    assert_equal(folded, table.concat(words, ' ', 1, 6) .. '\r\n ' .. table.concat(words, ' ', 7, 10))
  end)

  test("never folds after a comma or turns whitespace into a tab", function()
    local value = 'Report for 1,000,000 messages from host-alpha,host-beta,host-gamma,' ..
        'host-delta,host-epsilon'
    local folded = util.fold_header_unstructured('Subject', value, 'lf')
    assert_equal(folded, 'Report for 1,000,000 messages from\n ' ..
        'host-alpha,host-beta,host-gamma,host-delta,host-epsilon')
    assert_equal(unfold(folded), value)
    -- the structured folder adds a tab after a comma for the same value
    assert_not_equal(unfold(util.fold_header('Subject', value, 'lf')), value)
  end)

  test("tabs, existing folds and long words are kept", function()
    local long = string.rep('x', 100)
    assert_equal(util.fold_header_unstructured('X', 'a\tb'), 'a\tb')
    assert_equal(util.fold_header_unstructured('X', 'first\r\n second'), 'first\r\n second')
    assert_equal(util.fold_header_unstructured('X', long), long)
    assert_equal(util.fold_header_unstructured('X', 'short ' .. long .. ' end', 'lf'),
        'short\n ' .. long .. '\n end')
  end)

  -- Every line, the first one with its "Name: " prefix, fits `limit`
  local function lines_fit(name, folded, limit)
    local first = true
    for line in string.gmatch(folded .. '\r\n', '(.-)\r\n') do
      local len = #line + (first and #name + 2 or 0)
      first = false
      if len > limit then
        return false, line
      end
    end
    return true
  end

  test("a long whitespace run is split to keep lines within 998 octets", function()
    local value = 'a' .. string.rep(' ', 10) .. string.rep('b', 990)
    local folded = util.fold_header_unstructured('Subject', value)
    assert_equal(unfold(folded), value)
    assert_true(lines_fit('Subject', folded, 998))
    -- the continuation keeps all the whitespace it can
    assert_equal(folded, 'a  \r\n' .. string.rep(' ', 8) .. string.rep('b', 990))
  end)

  test("a whitespace run is split to keep lines within fold_max", function()
    local value = 'a' .. string.rep(' ', 50) .. string.rep('b', 40)
    local folded = util.fold_header_unstructured('X', value)
    assert_equal(unfold(folded), value)
    assert_true(lines_fit('X', folded, 76))
    assert_equal(folded, 'a' .. string.rep(' ', 14) .. '\r\n' .. string.rep(' ', 36) .. string.rep('b', 40))
  end)

  test("short whitespace runs move whole to the continuation line", function()
    local folded = util.fold_header_unstructured('X', string.rep('a', 60) .. '  ' .. string.rep('b', 20))
    assert_equal(folded, string.rep('a', 60) .. '\r\n  ' .. string.rep('b', 20))
  end)

  test("long words and runs never break the 998 octets limit when they fit", function()
    math.randomseed(6293)
    for _ = 1, 300 do
      local parts = {}
      for i = 1, math.random(1, 6) do
        local word = string.rep('w', math.random(1, 900))
        if i > 1 then
          word = string.rep(math.random() < 0.5 and ' ' or '\t', math.random(1, 60)) .. word
        end
        parts[#parts + 1] = word
      end
      local value = table.concat(parts)
      local folded = util.fold_header_unstructured('Subject', value)
      assert_equal(unfold(folded), value)
      local ok, line = lines_fit('Subject', folded, 998)
      assert_true(ok, line and #line)
    end
  end)

  test("unfolding always gives the value back", function()
    math.randomseed(6292)
    local alphabet = 'abcdefghij,;.=?-_'
    for _ = 1, 500 do
      local parts = {}
      for i = 1, math.random(1, 40) do
        local len = math.random(1, 30)
        local chars = {}
        for j = 1, len do
          local k = math.random(1, #alphabet)
          chars[j] = string.sub(alphabet, k, k)
        end
        parts[#parts + 1] = table.concat(chars)
        if i > 1 then
          parts[#parts] = (math.random() < 0.2 and '\t' or ' ') .. parts[#parts]
        end
      end
      local value = table.concat(parts)
      local folded = util.fold_header_unstructured('Subject', value, 'crlf')
      assert_equal(unfold(folded), value)
      for line in string.gmatch(folded .. '\r\n', '(.-)\r\n') do
        local first_line_extra = (#line == #folded or line == string.match(folded, '^[^\r]*')) and 9 or 0
        -- a line only overflows if it holds a single word longer than a line
        if #line + first_line_extra > 76 then
          assert_nil(string.find(line, '%S[ \t]+%S'), line)
        end
      end
    end
  end)
end)
