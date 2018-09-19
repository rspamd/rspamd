local logger = require "rspamd_logger"
local telescope = require "telescope"
local util  = require 'lua_util'

local function rspamd_assert_equals(tbl)
  return tbl.expect == tbl.actual
end

local function rspamd_assert_equals_msg(_, tbl)
  return logger.slog(
    "Failed asserting that \n  (actual)   %1 \n equals to\n  (expected) %2",
    tbl.actual, tbl.expect
  )
end

local function rspamd_assert_table_equals(tbl)
  return util.table_cmp(tbl.expect, tbl.actual)
end

telescope.make_assertion("rspamd_eq",       rspamd_assert_equals_msg, rspamd_assert_equals)
telescope.make_assertion("rspamd_table_eq", rspamd_assert_equals_msg, rspamd_assert_table_equals)
