context("task:get_urls_filtered", function()
  local rspamd_task = require("rspamd_task")
  local logger = require("rspamd_logger")
  local test_helper = require("rspamd_test_helper")

  -- Initialises the tld list; without it every url carries the `no_tld` flag
  -- and the missing-flags case below cannot be reproduced.
  test_helper.init_url_parser()

  local html_msg = [[
From: test@example.com
To: nobody@example.com
Subject: test
Content-Type: text/html

<html><body><a href="https://example.com/test">Click here</a></body></html>
]]

  local text_msg = [[
From: test@example.com
To: nobody@example.com
Subject: test
Content-Type: text/plain

visit https://example.com/test now
]]

  -- assertions are only injected into test() bodies, so this helper returns
  -- nil instead of asserting and every caller checks the result itself
  local function load(msg)
    local res, task = rspamd_task.load_from_string(msg, rspamd_config)
    if not res then
      return nil
    end
    task:process_message()
    return task
  end

  -- Urls extracted from html parts carry no flags at all. The no-argument
  -- form means "include everything", so they must not be filtered out.
  test("no arguments returns urls from an html part", function()
    local task = load(html_msg)
    assert_not_nil(task, "failed to load message")
    local urls = task:get_urls_filtered()

    assert_equal(1, #urls,
        logger.slog('expected 1 url from the html part, got %s', #urls))
    assert_equal("https://example.com/test", urls[1]:get_text())
  end)

  test("no arguments returns urls from a text part", function()
    local task = load(text_msg)
    assert_not_nil(task, "failed to load message")
    local urls = task:get_urls_filtered()

    assert_equal(1, #urls,
        logger.slog('expected 1 url from the text part, got %s', #urls))
  end)

  -- get_urls() has never applied the include filter, so the two must agree
  -- when no filtering has been asked for.
  test("no arguments agrees with get_urls", function()
    for _, msg in ipairs({ html_msg, text_msg }) do
      local task = load(msg)
      assert_not_nil(task, "failed to load message")
      assert_equal(#task:get_urls(), #task:get_urls_filtered(),
          "get_urls and unfiltered get_urls_filtered must agree")
    end
  end)

  -- An explicit exclude list still has to work, and must not resurrect the
  -- bug by way of the include mask staying at ~0U.
  test("exclude list still filters", function()
    -- the html part url carries no flags, so no exclude list can match it
    local html_task = load(html_msg)
    assert_not_nil(html_task, "failed to load message")
    assert_equal(1, #html_task:get_urls_filtered(nil, { 'subject' }),
        "excluding an unrelated flag must keep the url")

    -- the text part url carries `text`, so excluding it must drop the url
    local task = load(text_msg)
    assert_not_nil(task, "failed to load message")
    assert_equal(1, #task:get_urls_filtered(nil, { 'subject' }),
        "excluding an unrelated flag must keep the url")
    assert_equal(0, #task:get_urls_filtered(nil, { 'text' }),
        "excluding the url's own flag must drop it")
  end)

  -- An explicit include list keeps its original meaning: only urls carrying
  -- at least one of the requested flags come back.
  test("explicit include list only returns matching urls", function()
    local task = load(text_msg)
    assert_not_nil(task, "failed to load message")

    assert_equal(1, #task:get_urls_filtered({ 'text' }),
        "the text part url carries the `text` flag")
    assert_equal(0, #task:get_urls_filtered({ 'obscured' }),
        "no url carries the `obscured` flag")
  end)
end)
