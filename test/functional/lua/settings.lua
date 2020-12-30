rspamd_config:register_symbol({
  name = 'SIMPLE_PRE',
  score = 1.0,
  priority = 9, -- after settings
  group = 'a',
  type = 'prefilter',
  callback = function()
    return true, 'Fires always'
  end
})

rspamd_config:register_symbol({
  name = 'SIMPLE_POST',
  score = 1.0,
  type = 'postfilter',
  group = 'c',
  callback = function()
    return true, 'Fires always'
  end
})

local id = rspamd_config:register_symbol({
  name = 'SIMPLE_TEST',
  score = 1.0,
  group = 'b',
  callback = function(task)
    task:insert_result('SIMPLE_VIRTUAL', 1.0)
    task:insert_result('SIMPLE_VIRTUAL1', 1.0)
    return true, 'Fires always'
  end
})

rspamd_config:register_symbol({
  name = 'SIMPLE_VIRTUAL',
  type = 'virtual',
  score = 1.0,
  group = 'vg',
  parent = id,
})

rspamd_config:register_symbol({
  name = 'SIMPLE_VIRTUAL1',
  type = 'virtual',
  forbidden_ids = 'id_virtual,id_virtual_group',
  allowed_ids = 'id_virtual1',
  score = 1.0,
  group = 'vg',
  parent = id,
})

id = rspamd_config:register_symbol({
  name = 'DEP_REAL',
  callback = function(task)
    task:insert_result('DEP_VIRTUAL', 1.0)
    return true
  end,
  score = 1.0,
})

rspamd_config:register_symbol({
  name = 'DEP_VIRTUAL',
  parent = id,
  type = 'virtual',
  allowed_ids = 'id_virtual1',
  score = 1.0,
})

rspamd_config:register_dependency('DEP_VIRTUAL', 'EXPLICIT_VIRTUAL1')