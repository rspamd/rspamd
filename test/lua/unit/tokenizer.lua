context("Text tokenization test", function()
  local util = require "rspamd_util"
  local logger = require "rspamd_logger"
  test("Tokenize simple text", function()
    local cases = {
      {"Lorem ipsum dolor sit amet, consectetur adipiscing elit. Integer mattis, nibh",
        {"Lorem", "ipsum", "dolor", "sit", "amet", "consectetur", "adipiscing", "elit",
        "Integer", "mattis", "nibh"
        }
      },
    }
    
    for _,c in ipairs(cases) do
      local w = util.tokenize_text(c[1])
      assert_not_nil(w, "cannot tokenize " .. c[1])
      
      for i,wrd in ipairs(w) do
        logger.infox('%1:%2', i, wrd)
        assert_equal(wrd, c[2][i])
      end
    end
  end)
end)