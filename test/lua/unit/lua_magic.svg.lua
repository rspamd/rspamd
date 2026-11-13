context("Standalone SVG detection", function()
  local magic = require "lua_magic"
  local task_module = require "rspamd_task"
  local svg = require "rspamd_svg"
  local helper = require "rspamd_test_helper"

  helper.init_url_parser()

  local function detect(content)
    return magic.detect({ get_content = function() return content end })
  end

  local valid = {
    '<svg xmlns="http://www.w3.org/2000/svg"><rect width="10"/></svg>',
    '\239\187\191<?xml version="1.0"?>\n<!-- picture --><svg/>\n<!-- end -->',
    '<!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd"><svg/>',
    '<s:svg xmlns:s="http://www.w3.org/2000/svg"/>',
  }
  for i, content in ipairs(valid) do
    test("accepts standalone SVG " .. i, function()
      assert_equal(detect(content), 'svg')
    end)
  end

  local invalid = {
    '<div>hello</div><svg/>',
    '<svg/><div>hello</div>',
    '<svg/>outside',
    'outside<svg/>',
    '<svg/><svg/>',
    '<svg><rect></svg>',
    '<!DOCTYPE svg><div>hello</div>',
    '<svg xmlns="urn:other"/>',
    '<svg/><![CDATA[ ]]>',
    '<SVG/>',
    '<svg width=10/>',
  }
  for i, content in ipairs(invalid) do
    test("rejects non-standalone SVG " .. i, function()
      assert_not_equal(detect(content), 'svg')
    end)
  end

  test("requires a root even without a magic signature", function()
    assert_false(svg.is_document(''))
    assert_false(svg.is_document('<!-- no root -->'))
  end)

  test("bounds standalone document validation", function()
    local accepted, err = svg.is_document('<svg>' .. string.rep('<g>', 128) ..
        string.rep('</g>', 128) .. '</svg>')
    assert_false(accepted)
    assert_not_nil(err:find('depth limit', 1, true))
    accepted, err = svg.is_document('<svg>' .. string.rep(' ', 4 * 1024 * 1024) .. '</svg>')
    assert_false(accepted)
    assert_not_nil(err:find('input limit', 1, true))
  end)

  local fragments = {
    '<div>hello</div><SVG width=10></SVG>',
    '<svg/><div>hello</div>',
    '<!DOCTYPE svg><div>hello</div>',
    '<svg>' .. string.rep(' ', 4096) .. '</svg><div>hello</div>',
    '<svg>' .. string.rep('<g>', 128) .. string.rep('</g>', 128) .. '</svg>',
  }
  for i, fragment in ipairs(fragments) do
    test("extracts HTML URLs beside SVG " .. i, function()
      local ok, task = task_module.load_from_string(
          'From: test@example.com\nTo: test@example.net\nContent-Type: text/html\n\n' ..
          fragment .. '<a href="https://linked.example.com/">Link</a>', rspamd_config)
      assert_true(ok)
      task:process_message()
      local part = task:get_parts()[1]
      assert_equal(part:get_detected_ext(), 'html')
      assert_true(part:is_text())
      assert_true(part:get_text():is_html())
      local found = false
      for _, url in ipairs(task:get_urls() or {}) do
        if url:get_host() == 'linked.example.com' then found = true end
      end
      task:destroy()
      assert_true(found, 'HTML link was not extracted')
    end)
  end
end)
