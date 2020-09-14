local logger = require "rspamd_logger"
local telescope = require "telescope"
local util  = require 'lua_util'

local function rspamd_assert_equals(tbl)
  return tbl.expect == tbl.actual
end

local function rspamd_assert_equals_msg(_, tbl)
  return logger.slog(
    "Failed asserting that \n  (actual)   : %1 \n equals to\n  (expected) : %2",
    tbl.actual, tbl.expect
  )
end

local function rspamd_assert_table_equals(tbl)
  return util.table_cmp(tbl.expect, tbl.actual)
end

local function rspamd_assert_table_equals_sorted(tbl)
  local expect = util.deepcopy(tbl.expect)
  local actual = util.deepcopy(tbl.actual)
  util.deepsort(expect)
  util.deepsort(actual)
  return util.table_cmp(expect, actual)
end

local function table_keys_sorted(t)
  local keys = {}

  for k,_ in pairs(t) do
    table.insert(keys, k)
  end
  table.sort(keys)
  return keys;
end

local function format_line(level, key, v_expect, v_actual)
  local prefix
  if v_expect == v_actual then
    prefix = string.rep(' ', level * 2 + 1)
    return string.format("%s[%s] = %s", prefix, tostring(key), tostring(v_expect))
  else
    prefix = string.rep(' ', level * 2)
    local ret = {}
    if v_expect then
      ret[#ret + 1] = string.format("-%s[%s] = %s: %s", prefix, tostring(key), type(v_expect), tostring(v_expect))
    end
    if v_actual then
      ret[#ret + 1] = string.format("+%s[%s] = %s: %s", prefix, tostring(key), type(v_actual), tostring(v_actual))
    end
    return table.concat(ret, "\n")
  end
end

local function format_table_begin(level, key)
  local prefix = string.rep(' ', level * 2 + 1)
  return string.format("%s[%s] = {", prefix, tostring(key))
end

local function format_table_end(level)
  local prefix = string.rep(' ', level * 2 + 1)
  return string.format("%s}", prefix)
end

local function rspamd_assert_table_diff_msg(_, tbl)
  local avoid_loops = {}
  local msg = rspamd_assert_equals_msg(_, tbl)

  local diff = {}
  local function recurse(expect, actual, level)
    if avoid_loops[actual] then
      return
    end
    avoid_loops[actual] = true

    local keys_expect = table_keys_sorted(expect)
    local keys_actual = table_keys_sorted(actual)

    local i_k_expect, i_v_expect = next(keys_expect)
    local i_k_actual, i_v_actual = next(keys_actual)

    while i_k_expect and i_k_actual do
      local v_expect = expect[i_v_expect]
      local v_actual = actual[i_v_actual]

      if i_v_expect == i_v_actual then
        -- table keys are the same: compare values
        if type(v_expect) == 'table' and type(v_actual) == 'table' then
          if util.table_cmp(v_expect, v_actual) then
            -- we use the same value for 'actual' and 'expect' as soon as they're equal and don't bother us
            diff[#diff + 1] = format_line(level, i_v_expect, v_expect, v_expect)
          else
            diff[#diff + 1] = format_table_begin(level, i_v_expect)
            recurse(v_expect, v_actual, level + 1)
            diff[#diff + 1] = format_table_end(level)
          end
        else
          diff[#diff + 1] = format_line(level, i_v_expect, v_expect, v_actual)
        end

        i_k_expect, i_v_expect = next(keys_expect, i_k_expect)
        i_k_actual, i_v_actual = next(keys_actual, i_k_actual)
      elseif tostring(v_actual) > tostring(v_expect) then
        diff[#diff + 1] = format_line(level, i_v_expect, v_expect, nil)
        i_k_expect, i_v_expect = next(keys_expect, i_k_expect)
      else
        diff[#diff + 1] = format_line(level, i_v_actual, nil, v_actual)
        i_k_actual, i_v_actual = next(keys_actual, i_k_actual)
      end

    end

    while i_k_expect do
      local v_expect = expect[i_v_expect]
      diff[#diff + 1] = format_line(level, i_v_expect, v_expect, nil)
      i_k_expect, i_v_expect = next(keys_expect, i_k_expect)
    end

    while i_k_actual do
      local v_actual = actual[i_v_actual]
      diff[#diff + 1] = format_line(level, i_v_actual, nil, v_actual)
      i_k_actual, i_v_actual = next(keys_actual, i_k_actual)
    end
  end
  recurse(tbl.expect, tbl.actual, 0)

  return string.format("%s\n===== diff (-expect, +actual) ======\n%s", msg, table.concat(diff, "\n"))
end

telescope.make_assertion("rspamd_eq",       rspamd_assert_equals_msg, rspamd_assert_equals)
-- telescope.make_assertion("rspamd_table_eq", rspamd_assert_equals_msg, rspamd_assert_table_equals)
telescope.make_assertion("rspamd_table_eq", rspamd_assert_table_diff_msg, rspamd_assert_table_equals)
telescope.make_assertion("rspamd_table_eq_sorted", rspamd_assert_table_diff_msg,
    rspamd_assert_table_equals_sorted)

