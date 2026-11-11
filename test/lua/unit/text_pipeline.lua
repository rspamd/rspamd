-- Words, languages and limits of a text part

context("Text pipeline", function()
  local rspamd_task = require "rspamd_task"
  local rspamd_regexp = require "rspamd_regexp"
  local rspamd_util = require "rspamd_util"
  local lua_mime = require "lua_mime"

  local function load(body, ctype)
    local msg = "From: a@example.com\r\nSubject: t\r\nContent-Type: " .. (ctype or "text/plain") ..
        "; charset=utf-8\r\n\r\n" .. body .. "\r\n"
    local ok, task = rspamd_task.load_from_string(msg, rspamd_config)
    if not ok then
      error('cannot load the message')
    end
    task:process_message()
    return task
  end

  -- Everything that a test needs of the first text part
  local function inspect(body, ctype)
    local task = load(body, ctype)
    local part = task:get_text_parts()[1]
    local res = {
      words = part:get_words('norm'),
      nwords = part:get_words_count(),
      stats = part:get_stats(),
      language = part:get_language(),
    }
    task:destroy()
    return res
  end

  local english = string.rep("The quick brown fox jumps over the lazy dog while the other animals " ..
      "watch from the hill and wonder about the weather today. ", 18)

  -- Words

  test("A long text tells that its words are a sample", function()
    local words = {}
    for i = 1, 20000 do
      words[i] = 'word' .. i
    end
    local res = inspect(table.concat(words, ' '))
    assert_true(res.nwords < 20000)
    assert_true(res.stats.words_sampled)
    assert_false(res.stats.words_truncated)

    res = inspect("just a few words here")
    assert_false(res.stats.words_sampled)
    assert_false(res.stats.words_truncated)
  end)

  local zwsp = '\226\128\139'

  test("Zero width characters do not move a link over the words after it", function()
    local html = '<html><body><p>alpha' .. zwsp .. ' beta' .. zwsp .. ' gamma' .. zwsp .. ' delta' .. zwsp ..
        ' epsilon' .. zwsp .. '</p><a href="http://evil.example.com/x">http://good.example.com/</a>' ..
        ' tail1 tail2 tail3 tail4 tail5 tail6</body></html>'
    local res = inspect(html, 'text/html')
    local seen = {}
    for _, w in ipairs(res.words) do
      seen[w] = true
    end
    for i = 1, 6 do
      assert_true(seen['tail' .. i], 'tail' .. i .. ' is lost')
    end
  end)

  test("A zero width character at the start of a line is removed", function()
    local res = inspect(zwsp .. "first line\r\n" .. zwsp .. "second line\r\n" .. zwsp .. zwsp .. "third line")
    assert_equal(6, #res.words)
    for _, w in ipairs(res.words) do
      assert_true(#w > 0, 'an empty word')
    end
  end)

  test("filter_words does not fail on the placeholder of an url", function()
    local task = load("hello visit http://example.com/path now ok")
    local part = task:get_text_parts()[1]
    local re = rspamd_regexp.create_cached('/.*/')
    local full = part:filter_words(re, 'full')
    local stem = part:filter_words(re, 'stem')
    task:destroy()
    assert_equal(#stem, #full)
  end)

  -- Languages

  local has_languages = pcall(function()
    rspamd_config:init_subsystem('langdet')
  end)

  if has_languages and inspect(english).language == 'en' then
    local single = {
      { 'a Greek letter', '\206\177' },
      { 'a kana', '\227\129\130' },
      { 'an ideograph', '\228\184\173' },
      { 'a Georgian letter', '\225\131\144' },
      { 'a few Greek letters', '\206\177\206\178\206\179\206\180 \206\181\206\182' },
    }

    for _, c in ipairs(single) do
      test("The language of a text is not decided by " .. c[1], function()
        assert_equal('en', inspect(english .. " " .. c[2]).language)
      end)
    end

    test("Stop words of another language added to a text do not make it that language", function()
      local dutch = " de het een van en in is dat op te zijn voor met die niet aan er maar om ook als"
      assert_equal('en', inspect(english .. dutch).language)
    end)

    local scripts = {
      { 'el', "Η γρήγορη καφέ αλεπού πηδάει πάνω από το τεμπέλικο σκυλί. " },
      { 'ja', "これは日本語の文章です。今日は天気がいいですね。" },
      { 'zh-CN', "这是一个中文句子。今天天气很好。我们去公园散步吧。" },
      { 'ko', "이것은 한국어 문장입니다. 오늘 날씨가 좋습니다. " },
      { 'he', "זהו משפט בעברית. מזג האוויר היום נעים מאוד. " },
    }

    for _, c in ipairs(scripts) do
      test("A text in its script is " .. c[1], function()
        assert_equal(c[1], inspect(string.rep(c[2], 10)).language)
      end)
    end

    test("The language of a text is the same on every scan", function()
      local ambiguous = string.rep("water in de winter is warm en de hand is open ", 12)
      local first = inspect(ambiguous).language
      for _ = 1, 20 do
        inspect(english)
      end
      assert_equal(first, inspect(ambiguous).language)
    end)
  end

  -- Text for external services

  test("extract_text_limited does not choke on a run of spaces", function()
    local task = load("Hello" .. string.rep(' ', 200000) .. "world and some more words here")
    local t0 = rspamd_util.get_ticks()
    local res = lua_mime.extract_text_limited(task, { max_bytes = 6144, max_words = 1024 })
    local spent = rspamd_util.get_ticks() - t0
    task:destroy()
    assert_true(spent < 2, string.format('%.2f seconds', spent))
    assert_not_nil(res.text:find('Hello', 1, true))
  end)

  test("extract_text_limited keeps the start of a first line that is over the limit", function()
    local line = string.rep("word ", 4000)
    local task = load(line)
    local res = lua_mime.extract_text_limited(task, { max_bytes = 6144, max_words = 100000 })
    task:destroy()
    assert_true(#res.text > 5000, tostring(#res.text))
    assert_true(#res.text <= 6144)
    assert_true(res.truncated)
  end)

  test("extract_text_limited leaves a short text as it is", function()
    local task = load("  one line here  \r\nand another one\r\n")
    local res = lua_mime.extract_text_limited(task, { max_bytes = 6144, max_words = 1024 })
    task:destroy()
    assert_not_nil(res.text:find('one line here', 1, true))
    assert_not_nil(res.text:find('and another one', 1, true))
    assert_false(res.truncated or false)
  end)
end)
