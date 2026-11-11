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

  local function text_task(content)
    local res, task = rspamd_task.load_from_string([[
From: test@example.com
To: nobody@example.com
Subject: test
Content-Type: text/plain; charset=utf-8

]] .. content, rspamd_config)
    assert(res, "failed to load message")
    task:process_message()
    return task
  end

  local samples = {
    'Wireless internet connects drivers across countries without roaming fees. ' ..
        'Portable devices provide navigation music messages video calls and remote work.',
    'Conexión inalámbrica para teléfonos y ordenadores. ' ..
        'Navegación música batería señal países comunicación información.'
  }

  for _, kind in ipairs({'text', 'html'}) do
    for i, sample in ipairs(samples) do
      test("injected " .. kind .. " prepares statistical words " .. i, function()
        local original = text_task(sample)
        local task = text_task('')
        local content = kind == 'html' and ('<html><body><p>' .. sample ..
            '</p></body></html>') or sample
        assert_true(task:inject_part(kind, content))

        local expected = original:get_text_parts()[1]
        local actual = injected_part(task):get_text()
        local words = actual:get_words('stem')
        assert_true(#words > 0, 'injected words have no stems')
        assert_rspamd_table_eq({actual = words, expect = expected:get_words('stem')})
        assert_equal(actual:get_words_count(), expected:get_words_count())
      end)
    end
  end

  test("different injected text produces different statistical words", function()
    local first = text_task('')
    local second = text_task('')
    assert_true(first:inject_part('text', samples[1]))
    assert_true(second:inject_part('text', samples[2]))
    local first_words = injected_part(first):get_text():get_words('stem')
    local second_words = injected_part(second):get_text():get_words('stem')
    assert_true(#first_words > 0)
    assert_true(#second_words > 0)
    assert_not_equal(table.concat(first_words, ','), table.concat(second_words, ','))
  end)

  test("injection preserves averaged message word statistics", function()
    local task = text_task('A cat sat beside several extraordinary machines.')
    local pool = task:get_mempool()
    local avg = pool:get_variable('avg_words_len', 'double')
    local short = pool:get_variable('short_words_cnt', 'double')
    local original = task:get_text_parts()[1]
    local original_words = original:get_words('stem')
    local original_count = original:get_words_count()
    assert_not_nil(avg)
    assert_not_nil(short)

    for _, kind in ipairs({'text', 'html'}) do
      assert_true(task:inject_part(kind, samples[1]))
      assert_equal(pool:get_variable('avg_words_len', 'double'), avg)
      assert_equal(pool:get_variable('short_words_cnt', 'double'), short)
      assert_rspamd_table_eq({actual = original:get_words('stem'), expect = original_words})
      assert_equal(original:get_words_count(), original_count)
    end
  end)

  test("injection during MIME processing is finalized once", function()
    local content = require "lua_content"
    local saved = content.maybe_process_mime_part
    local seen, early_words, injected
    local res, task = rspamd_task.load_from_string([[
From: test@example.com
To: nobody@example.com
Subject: test
Content-Type: application/octet-stream

Extractor input.
]], rspamd_config)
    assert_true(res, "failed to load message")

    content.maybe_process_mime_part = function(part, current_task)
      seen = true
      assert_true(current_task:inject_part('text', samples[1], part))
      injected = injected_part(current_task):get_text()
      early_words = #injected:get_words('stem')
    end
    local ok, err = pcall(task.process_message, task)
    content.maybe_process_mime_part = saved
    assert_true(ok, err)
    assert_true(seen, 'content extractor was not called')
    assert_equal(early_words, 0, 'early injection must use the regular finalization loop')

    local original = text_task(samples[1])
    local expected = original:get_text_parts()[1]
    assert_rspamd_table_eq({actual = injected:get_words('stem'),
        expect = expected:get_words('stem')})
    assert_equal(injected:get_words_count(), expected:get_words_count())
  end)

  test("empty injected text has no statistical words", function()
    for _, content in ipairs({'', '   ', '... !!!'}) do
      local task = text_task(samples[1])
      assert_true(task:inject_part('text', content))
      local part = injected_part(task):get_text()
      assert_equal(#part:get_words('stem'), 0)
      assert_equal(part:get_words_count(), 0)
    end
  end)

  test("rejects unknown part types", function()
    local res, task = rspamd_task.load_from_string(msg, rspamd_config)
    assert_true(res, "failed to load message")
    task:process_message()
    assert_false(task:inject_part('image', 'not an image'))
  end)
end)
