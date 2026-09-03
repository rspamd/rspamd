-- Symbols cache ordering: prefilter levels, filters hoisted by prefilter
-- dependencies, passthrough handling and the score limit.
-- Every symbol inserts its result only when the ordering it relies on holds,
-- so the robot suite merely checks for the presence of symbols.

local function resolve_then(task, cb)
  -- An asynchronous operation attached to the current symbol (the test config
  -- has a fake DNS record for this name)
  task:get_resolver():resolve_a({
    task = task,
    name = 'example.com',
    callback = function()
      cb()
    end,
  })
end

local function has_all(task, ...)
  for _, sym in ipairs({ ... }) do
    if not task:has_symbol(sym) then
      return false
    end
  end

  return true
end

-- Top priority prefilter finishes (asynchronously) before the medium ones start
rspamd_config:register_symbol({
  name = 'ORD_PRE_TOP',
  type = 'prefilter',
  priority = 10,
  score = 1.0,
  flags = 'nostat',
  callback = function(task)
    resolve_then(task, function()
      task:insert_result('ORD_PRE_TOP', 1.0)
    end)
  end,
})

-- Medium prefilter: observes the top one
rspamd_config:register_symbol({
  name = 'ORD_PRE_MED_A',
  type = 'prefilter',
  priority = 5,
  score = 1.0,
  flags = 'nostat',
  callback = function(task)
    if has_all(task, 'ORD_PRE_TOP') then
      task:insert_result('ORD_PRE_MED_A', 1.0)
    end
  end,
})

-- Runs after the whole medium level (hoisted filters included); sets a
-- pre-result when asked, which stops the filters stage
rspamd_config:register_symbol({
  name = 'ORD_PRE_LOW',
  type = 'prefilter',
  priority = 4,
  score = 1.0,
  flags = 'nostat',
  callback = function(task)
    if has_all(task, 'ORD_PRE_MED_A', 'ORD_PRE_MED_B', 'ORD_FILTER_DEP', 'ORD_FILTER_DEP2') then
      task:insert_result('ORD_PRE_LOW', 1.0)
    end

    if task:get_request_header('X-Passthrough') then
      task:set_pre_result('soft reject', 'ordering test passthrough', 'symcache_order')
    end
  end,
})

-- Two chained filters: ORD_PRE_MED_B depends on ORD_FILTER_DEP, so both are
-- hoisted to the prefilter stage (medium level)
rspamd_config:register_symbol({
  name = 'ORD_FILTER_DEP2',
  type = 'normal',
  score = 1.0,
  flags = 'nostat',
  callback = function(task)
    resolve_then(task, function()
      task:insert_result('ORD_FILTER_DEP2', 1.0)
    end)
  end,
})

rspamd_config:register_symbol({
  name = 'ORD_FILTER_DEP',
  type = 'normal',
  score = 1.0,
  flags = 'nostat',
  callback = function(task)
    resolve_then(task, function()
      -- The option tells whether the depending prefilter has already run
      local opt = task:has_symbol('ORD_PRE_MED_B') and 'after_pre' or 'before_pre'
      task:insert_result('ORD_FILTER_DEP', 1.0, opt)
    end)
  end,
})
rspamd_config:register_dependency('ORD_FILTER_DEP', 'ORD_FILTER_DEP2')

rspamd_config:register_symbol({
  name = 'ORD_PRE_MED_B',
  type = 'prefilter',
  priority = 5,
  score = 1.0,
  flags = 'nostat',
  callback = function(task)
    if has_all(task, 'ORD_PRE_TOP', 'ORD_FILTER_DEP', 'ORD_FILTER_DEP2') then
      task:insert_result('ORD_PRE_MED_B', 1.0)
    end
  end,
})
rspamd_config:register_dependency('ORD_PRE_MED_B', 'ORD_FILTER_DEP')

-- A plain filter starts after all prefilters, hoisted filters included
rspamd_config:register_symbol({
  name = 'ORD_FILTER_PLAIN',
  type = 'normal',
  score = 1.0,
  flags = 'nostat',
  callback = function(task)
    if has_all(task, 'ORD_PRE_MED_A', 'ORD_PRE_MED_B', 'ORD_FILTER_DEP', 'ORD_FILTER_DEP2') then
      task:insert_result('ORD_FILTER_PLAIN', 1.0)
    end
  end,
})

-- Runs even after a pre-result
rspamd_config:register_symbol({
  name = 'ORD_FILTER_IGNORE',
  type = 'normal',
  score = 1.0,
  flags = 'nostat,ignore_passthrough',
  callback = function(task)
    task:insert_result('ORD_FILTER_IGNORE', 1.0)
  end,
})

-- Score limit: ORD_FILTER_BIG exceeds the reject threshold when asked, so
-- ORD_FILTER_AFTER (which waits for it) must be skipped
rspamd_config:register_symbol({
  name = 'ORD_FILTER_BIG',
  type = 'normal',
  score = 200000.0,
  flags = 'nostat',
  callback = function(task)
    if task:get_request_header('X-Limit') then
      task:insert_result('ORD_FILTER_BIG', 1.0)
    end
  end,
})

rspamd_config:register_symbol({
  name = 'ORD_FILTER_AFTER',
  type = 'normal',
  score = 1.0,
  flags = 'nostat',
  callback = function(task)
    task:insert_result('ORD_FILTER_AFTER', 1.0)
  end,
})
rspamd_config:register_dependency('ORD_FILTER_AFTER', 'ORD_FILTER_BIG')

-- Postfilters: a lower priority runs first; a weak dependency on a skipped
-- symbol proceeds while a hard one is skipped as well
rspamd_config:register_symbol({
  name = 'ORD_POST_LOW',
  type = 'postfilter',
  priority = 1,
  score = 1.0,
  flags = 'nostat',
  callback = function(task)
    task:insert_result('ORD_POST_LOW', 1.0)
  end,
})

rspamd_config:register_symbol({
  name = 'ORD_POST_HIGH',
  type = 'postfilter',
  priority = 9,
  score = 1.0,
  flags = 'nostat',
  callback = function(task)
    if has_all(task, 'ORD_POST_LOW') then
      task:insert_result('ORD_POST_HIGH', 1.0)
    end
  end,
})

rspamd_config:register_symbol({
  name = 'ORD_POST_WEAK',
  type = 'postfilter',
  priority = 1,
  score = 1.0,
  flags = 'nostat',
  callback = function(task)
    task:insert_result('ORD_POST_WEAK', 1.0)
  end,
})
rspamd_config:register_dependency('ORD_POST_WEAK', 'ORD_FILTER_AFTER')

rspamd_config:register_symbol({
  name = 'ORD_POST_HARD',
  type = 'postfilter',
  priority = 1,
  score = 1.0,
  flags = 'nostat',
  callback = function(task)
    task:insert_result('ORD_POST_HARD', 1.0)
  end,
})
rspamd_config:register_dependency('ORD_POST_HARD', 'ORD_FILTER_AFTER', true)
