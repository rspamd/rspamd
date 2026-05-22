-- Functional test for the structured lua.local.d/{maps,selectors,regexps}
-- loader (lua_extras). Stages a small tree under TMPDIR and calls
-- lua_extras.load_extras() to register a map, a deferred selector that
-- captures rspamd_maps[name] in its factory, and a regexp using that
-- selector through the regexp DSL. The companion robot test then asserts
-- the symbol fires only when the From-domain is present in the map.

local lua_extras = require "lua_extras"

local tmpdir = os.getenv('TMPDIR') or '/tmp'
local base = tmpdir .. '/lua_extras_test'

-- Always start clean
os.execute('rm -rf "' .. base .. '"')
os.execute('mkdir -p "' .. base .. '/maps" "' .. base .. '/selectors" "' .. base .. '/regexps"')

local function write_file(path, content)
  local f = assert(io.open(path, 'w'))
  f:write(content)
  f:close()
end

-- Map data
local map_list = base .. '/local_domains.list'
write_file(map_list, 'example.com\nlocal.test\n')

-- Map definition
write_file(base .. '/maps/test_extras.lua', string.format([[
return {
  example_local_domains = {
    type = 'set',
    description = 'TEST: local domains',
    url = '%s',
  },
}
]], map_list))

-- Deferred selector capturing the map ref at registration time. This is the
-- whole point of the two-phase loader: by the time this factory runs, the
-- map above has already been registered and rspamd_maps[name] is populated.
write_file(base .. '/selectors/test_extras.lua', [[
local lua_extras = require "lua_extras"
return {
  test_extras_local_domain = lua_extras.deferred(function()
    local domains = rspamd_maps.example_local_domains
    return {
      description = 'TEST: From-domain when present in example_local_domains map',
      re_selector = true,
      get_value = function(task)
        local from = task:get_from('mime')
        local dom = from and from[1] and from[1].domain or nil
        if dom and domains and domains:get_key(dom) then
          return dom, 'string'
        end
        return nil
      end,
    }
  end),
}
]])

-- Regexp symbol firing when the deferred selector resolves a non-nil value.
write_file(base .. '/regexps/test_extras.lua', [[
return {
  TEST_EXTRAS_LOCAL_FROM = {
    re = 'test_extras_local_domain=/.+/{selector}',
    score = 0.1,
    description = 'TEST: From present in example_local_domains map',
  },
}
]])

-- Trigger the structured loader on our staged tree.
lua_extras.load_extras(rspamd_config, base)
