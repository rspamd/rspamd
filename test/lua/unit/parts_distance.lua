context("Alternative parts distance", function()
  local rspamd_task = require "rspamd_task"
  local lua_mime = require "lua_mime"

  -- Exercise the production MIME parsing, word preparation and distance path.
  -- All inputs are below the approximate-comparison limit of 8192 words.
  local function process_parts(plain, html)
    local message = table.concat({
      'From: sender@example.com',
      'To: recipient@example.com',
      'Subject: Alternative distance test',
      'MIME-Version: 1.0',
      'Content-Type: multipart/alternative; boundary="parts-distance"',
      '',
      '--parts-distance',
      'Content-Type: text/plain; charset=utf-8',
      '',
      plain,
      '--parts-distance',
      'Content-Type: text/html; charset=utf-8',
      '',
      '<html><body>' .. html .. '</body></html>',
      '--parts-distance--',
      '',
    }, '\r\n')

    local res, task = rspamd_task.load_from_string(message, rspamd_config)
    assert(res, "failed to load message")
    local processed = task:process_message()
    local pool = task:get_mempool()
    local distance = pool:get_variable('parts_distance', 'double')
    local total_words = pool:get_variable('total_words', 'int')
    local parts = task:get_text_parts()
    local nparts = #parts
    local distinct = lua_mime.get_distinct_text_parts(task)
    local ndistinct = #distinct
    local retained_html = ndistinct == 1 and distinct[1]:is_html()
    task:destroy()

    assert(processed, "failed to process message")
    assert(nparts == 2, "expected two text parts")
    assert(distance ~= nil, "parts_distance missing")
    return distance, total_words, ndistinct, retained_html
  end

  -- Replacement costs 2; insertion and deletion cost 1. The stored distance
  -- is that cost divided by the sum of both word counts, not the maximum.
  local cases = {
    {
      name = 'identical single words',
      first = 'alpha', second = 'alpha', total = 2, distance = 0,
    },
    {
      name = 'different single words',
      first = 'alpha', second = 'omega', total = 2, distance = 1,
    },
    {
      name = 'identical sequences',
      first = 'alpha beta gamma', second = 'alpha beta gamma',
      total = 6, distance = 0,
    },
    {
      name = 'completely different sequences of equal length',
      first = 'alpha beta gamma', second = 'delta omega sigma',
      total = 6, distance = 1,
    },
    {
      name = 'completely different sequences of unequal length',
      first = 'alpha beta', second = 'delta omega sigma',
      total = 5, distance = 1,
    },
    {
      name = 'one replacement',
      first = 'alpha beta gamma', second = 'alpha delta gamma',
      total = 6, distance = 2 / 6,
    },
    {
      name = 'insertion or deletion at the beginning',
      first = 'beta gamma', second = 'alpha beta gamma',
      total = 5, distance = 1 / 5,
    },
    {
      name = 'insertion or deletion in the middle',
      first = 'alpha gamma', second = 'alpha beta gamma',
      total = 5, distance = 1 / 5,
    },
    {
      name = 'insertion or deletion at the end',
      first = 'alpha beta', second = 'alpha beta gamma',
      total = 5, distance = 1 / 5,
    },
    {
      name = 'word order affects the distance',
      first = 'alpha beta gamma', second = 'beta gamma alpha',
      total = 6, distance = 2 / 6,
    },
    {
      name = 'repeated words preserve sequence alignment',
      first = 'alpha beta alpha', second = 'alpha alpha beta',
      total = 6, distance = 2 / 6,
    },
  }

  for _, case in ipairs(cases) do
    test(case.name, function()
      -- Swapping plain and HTML must preserve the result, including cases
      -- that exchange insertion and deletion.
      for _, swap in ipairs({false, true}) do
        local plain = swap and case.second or case.first
        local html = swap and case.first or case.second
        local distance, total = process_parts(plain, html)
        assert_equal(case.total, total)
        assert_true(math.abs(distance - case.distance) < 1e-12)
        assert_true(distance >= 0 and distance <= 1)
      end
    end)
  end

  test("distinct text consumer keeps HTML for identical alternatives", function()
    local distance, _, ndistinct, retained_html =
        process_parts('alpha beta gamma', 'alpha beta gamma')
    assert_equal(0, distance)
    assert_equal(1, ndistinct)
    assert_true(retained_html)
  end)

  test("distinct text consumer keeps both different alternatives", function()
    local distance, _, ndistinct =
        process_parts('alpha beta gamma', 'delta omega sigma')
    assert_equal(1, distance)
    assert_equal(2, ndistinct)
  end)
end)
