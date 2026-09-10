context("Injected text and HTML parts", function()
  local rspamd_task = require "rspamd_task"
  local test_helper = require "rspamd_test_helper"

  test_helper.init_url_parser()

  local msg = [[
From: test@example.com
To: nobody@example.com
Subject: test
Content-Type: text/plain

Original body.
]]

  local function url_set(urls)
    local result = {}
    for _, url in ipairs(urls or {}) do result[url:get_host()] = true end
    return result
  end

  local function injected_part(task)
    local parts = task:get_parts(true)
    return parts[#parts]
  end

  test("injected HTML goes through the HTML parser with part URLs", function()
    local res, task = rspamd_task.load_from_string(msg, rspamd_config)
    assert_true(res, "failed to load message")
    task:process_message()

    assert_true(task:inject_part('html',
        '<html><body><a href="https://linked.example.com/login">Sign in</a>' ..
        '<p>or visit http://visible.example.com/now</p></body></html>'))

    local part = injected_part(task)
    assert_not_nil(part)
    assert_true(part:is_text())
    local ctype, csubtype = part:get_type()
    assert_equal(ctype, 'text')
    assert_equal(csubtype, 'html')
    assert_true(part:get_text():is_html())

    local part_urls = url_set(part:get_urls())
    assert_equal(part_urls['linked.example.com'], true, 'href URL missing from the part')
    assert_equal(part_urls['visible.example.com'], true, 'visible URL missing from the part')
    local task_urls = url_set(task:get_urls())
    assert_equal(task_urls['linked.example.com'], true)
    assert_equal(task_urls['visible.example.com'], true)
    assert_not_nil(tostring(part:get_text():get_content()):find('Sign in', 1, true))
    assert_equal(tostring(part:get_text():get_content()):find('<a ', 1, true), nil)
  end)

  test("injected text keeps its URLs on the part", function()
    local res, task = rspamd_task.load_from_string(msg, rspamd_config)
    assert_true(res, "failed to load message")
    task:process_message()

    assert_true(task:inject_part('text', 'plain text with http://plain.example.com/x inside'))
    local part = injected_part(task)
    local ctype, csubtype = part:get_type()
    assert_equal(ctype, 'text')
    assert_equal(csubtype, 'plain')
    assert_equal(url_set(part:get_urls())['plain.example.com'], true)
    assert_equal(url_set(task:get_urls())['plain.example.com'], true)
  end)

  test("rejects unknown part types", function()
    local res, task = rspamd_task.load_from_string(msg, rspamd_config)
    assert_true(res, "failed to load message")
    task:process_message()
    assert_false(task:inject_part('image', 'not an image'))
  end)
end)
