-- Stand-in for modules that ask greylist.lua for a custom delay of one message
-- (request API). Inert unless the `Grey-Test` request header asks for it:
--   long, short - delay of 10 / 6 seconds requested by `testmod`
--   plain       - classic forced greylisting, as mx_check asks for it
--   override    - another module sets a pre-result after greylisting ran
local lua_util = require "lua_util"
local lua_greylist = require "lua_greylist"

local function test_options(task)
  return lua_util.str_split(tostring(task:get_request_header('Grey-Test') or ''), ',')
end

rspamd_config:register_symbol({
  type = 'postfilter',
  name = 'GREY_TEST_FORCE',
  priority = lua_util.symbols_priorities.medium,
  callback = function(task)
    for _, opt in ipairs(test_options(task)) do
      if opt == 'long' or opt == 'short' then
        lua_greylist.request(task, { module = 'testmod', body = opt == 'long' and 10 or 6 })
      elseif opt == 'plain' then
        lua_greylist.request_classic(task)
      elseif opt == 'meta' then
        lua_greylist.request(task, { module = 'metamod', meta = 10 })
      end
    end
  end
})
rspamd_config:register_dependency('GREYLIST_SAVE', 'GREY_TEST_FORCE')

rspamd_config:register_symbol({
  type = 'postfilter',
  name = 'GREY_TEST_OVERRIDE',
  flags = 'ignore_passthrough',
  priority = lua_util.symbols_priorities.medium,
  callback = function(task)
    for _, opt in ipairs(test_options(task)) do
      if opt == 'override' then
        task:set_pre_result('reject', 'override', 'grey_test')
      end
    end
  end
})
rspamd_config:register_dependency('GREY_TEST_OVERRIDE', 'GREYLIST_SAVE')
