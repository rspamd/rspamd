
context("extract_text_limited", function()
  local rspamd_task = require "rspamd_task"
  local rspamd_util = require "rspamd_util"
  local rspamd_test_helper = require "rspamd_test_helper"
  local lua_mime = require "lua_mime"

  rspamd_test_helper.init_url_parser()
  local cfg = rspamd_util.config_from_ucl(rspamd_test_helper.default_config(),
      "INIT_URL,INIT_LIBS,INIT_SYMCACHE,INIT_VALIDATE,INIT_PRELOAD_MAPS")

  local message = [[
Subject: Re: Test
From: user@example.com
Content-Type: text/plain; charset=utf-8

Top post content.
This is the important part.

On 2023-01-01 10:00, old@example.com wrote:
> Quoted reply level 1
> > Quoted reply level 2
> > More quoted text
> Some more level 1 text

----- Original Message -----
From: old@example.com
Sent: 2023-01-01 09:00
To: user@example.com

Old message content here.

--
Best regards,
Signature User
]]

  test("extract_text_limited basic", function()
    local res, task = rspamd_task.load_from_string(message, cfg)
    assert_true(res, "failed to load message")
    task:process_message()

    local result = lua_mime.extract_text_limited(task, {})
    assert_not_nil(result.text)
    -- Should contain everything by default (except maybe signature if default rules apply?)
    -- Based on specs, we need to implement heurstics first.
    -- Assuming defaults are loose or we need to check what they are.
    -- Task says "smart_trim - Enable all heuristics". So default should be off?
    -- "Options: ... strip_quotes ... smart_trim" implies defaults are false.

    task:destroy()
  end)

  test("extract_text_limited strip_quotes", function()
    local res, task = rspamd_task.load_from_string(message, cfg)
    assert_true(res)
    task:process_message()

    local result = lua_mime.extract_text_limited(task, { strip_quotes = true })
    assert_not_nil(result.text)
    -- Quoted lines starting with > should be removed
    assert_nil(result.text:find("> Quoted reply level 1"))

    task:destroy()
  end)

  test("extract_text_limited strip_reply_headers", function()
    local res, task = rspamd_task.load_from_string(message, cfg)
    assert_true(res)
    task:process_message()

    local result = lua_mime.extract_text_limited(task, { strip_reply_headers = true })
    assert_not_nil(result.text)
    -- Reply headers should trigger skip_rest, so content after them shouldn't appear
    assert_nil(result.text:find("Old message content here"))

    task:destroy()
  end)

  test("extract_text_limited strip_signatures", function()
    local res, task = rspamd_task.load_from_string(message, cfg)
    assert_true(res)
    task:process_message()

    local result = lua_mime.extract_text_limited(task, { strip_signatures = true })
    assert_not_nil(result.text)
    -- Should strip "-- \nBest regards..." and everything after
    assert_nil(result.text:find("Signature User"))

    task:destroy()
  end)

  test("extract_text_limited max_words", function()
    local res, task = rspamd_task.load_from_string(message, cfg)
    assert_true(res)
    task:process_message()

    local result = lua_mime.extract_text_limited(task, { max_words = 2 })
    assert_not_nil(result.text)
    assert_true(result.truncated)
    -- "Top post" are 2 words.
    -- result might be "Top post" or similar depending on tokenization

    task:destroy()
  end)

    test("extract_text_limited max_bytes", function()
    local res, task = rspamd_task.load_from_string(message, cfg)
    assert_true(res)
    task:process_message()

    local result = lua_mime.extract_text_limited(task, { max_bytes = 10 })
    assert_not_nil(result.text)
    assert_true(result.truncated)
    assert_true(#result.text <= 10)

    task:destroy()
  end)

  test("extract_text_limited smart_trim", function()
    local res, task = rspamd_task.load_from_string(message, cfg)
    assert_true(res)
    task:process_message()

    local result = lua_mime.extract_text_limited(task, { smart_trim = true })
    assert_not_nil(result.text)
    -- Quoted lines should be removed
    assert_nil(result.text:find("> Quoted reply level 1"))
    -- Signature content should be removed (after --)
    assert_nil(result.text:find("Signature User"))
    -- Top content should remain
    assert_not_nil(result.text:find("Top post content"))

    task:destroy()
  end)

end)
