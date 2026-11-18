-- Precise symbol timings: selected items (by name, by group of a virtual
-- child, with a failing condition and an unknown name) and the report
-- postfilter that verifies task:get_symbols_profile() and exposes every
-- verified property as a symbol option.

local rspamd_util = require "rspamd_util"

-- Synchronous selected symbol burning CPU for at least 20 ms
rspamd_config:register_symbol({
  name = 'PROF_SYNC',
  score = 0.1,
  group = 'profgrp_sync',
  callback = function(task)
    local start = os.clock()
    local x = 0
    while os.clock() - start < 0.02 do
      x = x + 1
    end
    task:insert_result('PROF_SYNC', 1.0, tostring(x > 0))
  end,
})

-- Asynchronous callback parent without a group; finishes from a timer. The
-- timer is relative to the cached loop time, which can be stale, so the real
-- elapsed time is measured with a real clock and stored on the task; the
-- report compares the profiled time against it instead of a constant.
local cb_id = rspamd_config:register_symbol({
  name = 'PROF_CB',
  type = 'callback',
  callback = function(task)
    local t0 = rspamd_util.get_time()
    task:add_timer(0.1, function()
      task:cache_set('prof_cb_real_ms', (rspamd_util.get_time() - t0) * 1000.0)
      task:insert_result('PROF_VIRT', 1.0)
    end)
  end,
})

-- Its virtual child carries the selected group
rspamd_config:register_symbol({
  name = 'PROF_VIRT',
  type = 'virtual',
  score = 0.1,
  group = 'profgrp',
  parent = cb_id,
})

-- Not selected
rspamd_config:register_symbol({
  name = 'PROF_OTHER',
  score = 0.1,
  callback = function(task)
    task:insert_result('PROF_OTHER', 1.0)
  end,
})

-- Selected, but its condition is false so it never runs
rspamd_config:register_symbol({
  name = 'PROF_COND',
  score = 0.1,
  callback = function(task)
    task:insert_result('PROF_COND', 1.0)
  end,
})
rspamd_config:add_condition('PROF_COND', function()
  return false
end)

rspamd_config:register_profiled_symbols({
  groups = { 'profgrp' },
  symbols = { 'PROF_SYNC', 'PROF_COND', 'PROF_REPORT', 'NO_SUCH_SYMBOL' },
})

local function find(prof, name)
  local res = {}
  for i, n in ipairs(prof.names) do
    if n == name then
      table.insert(res, i)
    end
  end
  return res
end

rspamd_config:register_symbol({
  name = 'PROF_REPORT',
  type = 'postfilter',
  score = 0.0,
  flags = 'nostat',
  callback = function(task)
    local function check(name, ok, observed)
      if ok then
        task:insert_result('PROF_REPORT', 0.0, name)
      else
        task:insert_result('PROF_REPORT', 0.0,
            'FAIL_' .. name .. '=' .. tostring(observed))
      end
    end

    local prof = task:get_symbols_profile()
    if not prof then
      task:insert_result('PROF_REPORT', 0.0, 'FAIL_no_profile=nil')
      return
    end

    -- Synchronous item
    local s = find(prof, 'PROF_SYNC')
    local si = s[1]
    check('sync_ok', #s == 1 and prof.times[si] >= 15 and prof.flags[si] == 0
        and prof.sync_times[si] == prof.times[si],
        #s == 1 and (prof.times[si] .. '/' .. prof.sync_times[si] .. '/' .. prof.flags[si])
            or ('count ' .. #s))

    -- Asynchronous parent of a virtual symbol, reported once under its name
    local a = find(prof, 'PROF_CB')
    local ai = a[1]
    local real_ms = task:cache_get('prof_cb_real_ms')
    check('async_ok', #a == 1 and real_ms ~= nil and prof.times[ai] >= real_ms - 2
        and prof.flags[ai] % 2 == 1
        and prof.sync_times[ai] < prof.times[ai],
        #a == 1 and (prof.times[ai] .. '/' .. prof.sync_times[ai] .. '/' .. prof.flags[ai]
            .. '/real=' .. tostring(real_ms))
            or ('count ' .. #a))
    check('virt_absent', #find(prof, 'PROF_VIRT') == 0, #find(prof, 'PROF_VIRT'))

    check('other_absent', #find(prof, 'PROF_OTHER') == 0, #find(prof, 'PROF_OTHER'))
    check('cond_absent', #find(prof, 'PROF_COND') == 0, #find(prof, 'PROF_COND'))
    check('self_absent', #find(prof, 'PROF_REPORT') == 0, #find(prof, 'PROF_REPORT'))

    local n = #prof.names
    check('arrays_equal_length', #prof.times == n and #prof.sync_times == n
        and #prof.flags == n, n .. '/' .. #prof.times .. '/' .. #prof.sync_times
        .. '/' .. #prof.flags)

    -- all = true reports unselected items too, when they are timed (they are
    -- not on a normal scan, so only the selected ones can be there)
    local all = task:get_symbols_profile({ all = true })
    check('all_superset', all ~= nil and #all.names >= n, all and #all.names)
    if all then
      -- Which one is expected depends on the request; the test asserts it
      if #find(all, 'PROF_OTHER') > 0 then
        task:insert_result('PROF_REPORT', 0.0, 'all_other_present')
      else
        task:insert_result('PROF_REPORT', 0.0, 'all_other_absent')
      end
      check('all_self_absent', #find(all, 'PROF_REPORT') == 0, #find(all, 'PROF_REPORT'))
    end

    local hit = task:get_symbols_profile({ min_time = 10 })
    check('min_time_hit', type(hit) == 'table', type(hit))
    local miss = task:get_symbols_profile({ min_time = 100000 })
    check('min_time_miss', miss == nil, type(miss))

    local ok = pcall(task.get_symbols_profile, task, 'bad')
    check('bad_opts_error', not ok, ok)
  end,
})
