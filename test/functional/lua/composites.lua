rspamd_config:register_symbol({
  name = 'EXPRESSIONS_B',
  score = 1.0,
  callback = function()
    return true, 'Fires always'
  end
})

rspamd_config:register_symbol({
  name = 'POLICY_REMOVE_WEIGHT_A',
  score = 1.0,
  callback = function()
    return true, 'Fires always'
  end
})
rspamd_config:register_symbol({
  name = 'POLICY_REMOVE_WEIGHT_B',
  score = 1.0,
  callback = function()
    return true, 'Fires always'
  end
})
rspamd_config:register_symbol({
  name = 'POLICY_FORCE_REMOVE_A',
  score = 1.0,
  callback = function()
    return true, 'Fires always'
  end
})
rspamd_config:register_symbol({
  name = 'POLICY_FORCE_REMOVE_B',
  score = 1.0,
  callback = function()
    return true, 'Fires always'
  end
})
rspamd_config:register_symbol({
  name = 'POLICY_LEAVE_A',
  score = 1.0,
  callback = function()
    return true, 'Fires always'
  end
})
rspamd_config:register_symbol({
  name = 'POLICY_LEAVE_B',
  score = 1.0,
  callback = function()
    return true, 'Fires always'
  end
})

rspamd_config:register_symbol({
  name = 'DEFAULT_POLICY_REMOVE_WEIGHT_A',
  score = 1.0,
  callback = function()
    return true, 'Fires always'
  end
})
rspamd_config:register_symbol({
  name = 'DEFAULT_POLICY_REMOVE_WEIGHT_B',
  score = 1.0,
  callback = function()
    return true, 'Fires always'
  end
})
rspamd_config:register_symbol({
  name = 'DEFAULT_POLICY_REMOVE_SYMBOL_A',
  score = 1.0,
  callback = function()
    return true, 'Fires always'
  end
})
rspamd_config:register_symbol({
  name = 'DEFAULT_POLICY_REMOVE_SYMBOL_B',
  score = 1.0,
  callback = function()
    return true, 'Fires always'
  end
})
rspamd_config:register_symbol({
  name = 'DEFAULT_POLICY_LEAVE_A',
  score = 1.0,
  callback = function()
    return true, 'Fires always'
  end
})
rspamd_config:register_symbol({
  name = 'DEFAULT_POLICY_LEAVE_B',
  score = 1.0,
  callback = function()
    return true, 'Fires always'
  end
})

rspamd_config:register_symbol({
  name = 'POSITIVE_A',
  score = -1.0,
  group = "positive",
  callback = function()
    return true, 'Fires always'
  end
})
rspamd_config:register_symbol({
  name = 'NEGATIVE_A',
  score = -1.0,
  group = "negative",
  callback = function()
    return true, 'Fires always'
  end
})
rspamd_config:register_symbol({
  name = 'NEGATIVE_B',
  score = 1.0,
  group = "negative",
  callback = function()
    return true, 'Fires always'
  end
})
rspamd_config:register_symbol({
  name = 'ANY_A',
  score = -1.0,
  group = "any",
  callback = function()
    return true, 'Fires always'
  end
})

rspamd_config:register_symbol({
  name = 'OPTS',
  score = -1.0,
  group = "any",
  callback = function(task)
    local lua_util = require "lua_util"
    local woot = lua_util.str_split(tostring(task:get_request_header('opts') or ''), ',')

    if woot and #woot > 0 and #woot[1] > 0 then
      return true, 1.0, woot
    end
  end
})
