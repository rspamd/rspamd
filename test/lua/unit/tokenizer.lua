context("Text tokenization test", function()
  local util = require "rspamd_util"
  local logger = require "rspamd_logger"

  local cases = {
    {"Lorem ipsum dolor sit amet, consectetur adipiscing elit. Integer mattis, nibh",
     {"Lorem", "ipsum", "dolor", "sit", "amet", "consectetur", "adipiscing", "elit",
      "Integer", "mattis", "nibh"
     }
    },
    {"Հետաքրքրվողների համար ոտորև ներկայացված",
     {"Հետաքրքրվողների", "համար", "ոտորև", "ներկայացված"}
    },
    {"", {}},
    {",,,,,", {}},
    {"word,,,,,word    ", {"word", "word"}},
    {"word", {"word"}},
    {",,,,word,,,", {"word"}}
  }

  for i,c in ipairs(cases) do
    test("Tokenize simple " .. i, function()
      local w = util.tokenize_text(c[1])
      if #c[2] == 0 then
        assert_equal(#w, 0, "must not have tokens " .. c[1])
      else
        assert_not_nil(w, "must tokenize " .. c[1])

        for i,wrd in ipairs(w) do
          assert_equal(wrd, c[2][i])
        end
      end
    end)
  end

  cases = {
    {"word https://example.com/path word",
     {{5, 24}},
     {"word", "!!EX!!", "word"}
    },
    {"համար https://example.com/path համար",
     {{11, 24}},
     {"համար", "!!EX!!", "համար"}
    },
    {"word https://example.com/path https://example.com/path word",
     {{5, 24}, {30, 24}},
     {"word", "!!EX!!", "!!EX!!", "word"}
    },
    {"word https://example.com/path https://example.com/path",
     {{5, 24}, {30, 24}},
     {"word", "!!EX!!", "!!EX!!"}
    },
    {"https://example.com/path https://example.com/path word",
     {{0, 24}, {25, 24}},
     {"!!EX!!", "!!EX!!", "word"}
    },
    {"https://example.com/path https://example.com/path",
     {{0, 24}, {25, 24}},
     {"!!EX!!", "!!EX!!"}
    },
    {",,,,https://example.com/path https://example.com/path    ",
     {{4, 24}, {29, 24}},
     {"!!EX!!", "!!EX!!"}
    },
  }

  for i,c in ipairs(cases) do
    test("Tokenize with exceptions " .. i, function()
      local w = util.tokenize_text(c[1], c[2])
      if #c[3] == 0 then
        assert_equal(#w, 0, "must not have tokens " .. c[1])
      else
        assert_not_nil(w, "must tokenize " .. c[1])
        for i,wrd in ipairs(w) do
          assert_equal(wrd, c[3][i])
        end
      end
    end)
  end

end)