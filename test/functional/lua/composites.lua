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

-- Composites with per-symbol Lua conditions; the auxiliary symbols fire only
-- when the `opts` request header is present to keep the exact score
-- assertions of the plain scan intact
local function has_opts(task)
  local h = task:get_request_header('opts')
  return h and #tostring(h) > 0
end

rspamd_config:register_symbol({
  name = 'COND_SYM_A',
  score = 1.0,
  callback = function(task)
    if has_opts(task) then
      return true, 1.0, 'a-opt1', 'a-opt2'
    end
  end
})
rspamd_config:register_symbol({
  name = 'COND_SYM_B',
  score = 1.0,
  callback = function(task)
    if has_opts(task) then
      return true, 1.0, 'b-opt1'
    end
  end
})
rspamd_config:register_symbol({
  name = 'COND_POSTFILTER_SYM',
  type = 'postfilter',
  score = 1.0,
  callback = function(task)
    if has_opts(task) then
      task:insert_result('COND_POSTFILTER_SYM', 1.0, 'post-opt')
    end
  end
})

rspamd_config:add_composite('COND_TRUE', {
  expression = 'COND_SYM_A & COND_SYM_B',
  score = 5.0,
  policy = 'leave',
  conditions = {
    COND_SYM_A = function(_, sym)
      if not sym or sym.name ~= 'COND_SYM_A' then
        return false
      end
      for _, o in ipairs(sym.options or {}) do
        if o == 'a-opt2' then
          return true
        end
      end
      return false
    end,
  },
})

rspamd_config:add_composite('COND_FALSE', {
  expression = 'COND_SYM_A & COND_SYM_B',
  score = 5.0,
  policy = 'leave',
  conditions = {
    COND_SYM_B = function()
      return false
    end,
  },
})

-- Join on a shared option value between two independent symbols
rspamd_config:add_composite('COND_JOIN', {
  expression = 'OPTS & COND_SYM_B',
  score = 5.0,
  policy = 'leave',
  conditions = {
    OPTS = function(task, sym)
      local other = task:get_symbol('COND_SYM_B')
      if not other then
        return false
      end
      local seen = {}
      for _, o in ipairs(other[1].options or {}) do
        seen[o] = true
      end
      for _, o in ipairs(sym.options or {}) do
        if seen[o] then
          return true
        end
      end
      return false
    end,
  },
})

-- Numeric return is used as the atom weight in the expression
rspamd_config:add_composite('COND_WEIGHT', {
  expression = 'COND_SYM_A + COND_SYM_B > 5',
  score = 5.0,
  policy = 'leave',
  conditions = {
    COND_SYM_A = function()
      return 10
    end,
  },
})

rspamd_config:add_composite('COND_WEIGHT_MISS', {
  expression = 'COND_SYM_A + COND_SYM_B > 5',
  score = 5.0,
  policy = 'leave',
  conditions = {
    COND_SYM_A = function()
      return 2
    end,
  },
})

-- The condition consults a postfilter symbol invisible to the expression;
-- depends_on defers the composite to the second pass
rspamd_config:add_composite('COND_DEPENDS', {
  expression = 'COND_SYM_A',
  score = 5.0,
  policy = 'leave',
  depends_on = { 'COND_POSTFILTER_SYM' },
  conditions = {
    COND_SYM_A = function(task)
      return task:get_symbol('COND_POSTFILTER_SYM') ~= nil
    end,
  },
})
