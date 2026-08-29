context("Lua maps expressions test", function()
  local lua_maps_expressions = require "lua_maps_expressions"

  local function make_test_cfg(registered)
    return {
      register_dependency = function(_, source, destination)
        table.insert(registered, { source, destination })
      end,
    }
  end

  test("registers own_symbol dependency for symbol() selectors", function()
    local registered = {}
    local test_cfg = make_test_cfg(registered)

    local combined = lua_maps_expressions.create(test_cfg, {
      rules = {
        dep_rule = {
          selector = "symbol('MAPEXPR_DEP_ONE')",
          map = { 'value' },
          type = 'set',
        },
      },
      expression = 'dep_rule',
    }, 'test_maps_expressions', 'MAPEXPR_CONSUMER')

    assert_not_nil(combined)
    assert_equal(#registered, 1)
    assert_equal(registered[1][1], 'MAPEXPR_CONSUMER')
    assert_equal(registered[1][2], 'MAPEXPR_DEP_ONE')
  end)

  test("does not register any dependency without own_symbol", function()
    local registered = {}
    local test_cfg = make_test_cfg(registered)

    local combined = lua_maps_expressions.create(test_cfg, {
      rules = {
        dep_rule = {
          selector = "symbol('MAPEXPR_DEP_TWO')",
          map = { 'value' },
          type = 'set',
        },
      },
      expression = 'dep_rule',
    }, 'test_maps_expressions')

    assert_not_nil(combined)
    assert_equal(#registered, 0)
  end)

  test("does not register dependencies when the object cannot be built", function()
    local registered = {}
    local test_cfg = make_test_cfg(registered)

    -- expression references an undefined atom, so create() bails out with no dependency registered
    local combined = lua_maps_expressions.create(test_cfg, {
      rules = {
        dep_rule = {
          selector = "symbol('MAPEXPR_DEP_THREE')",
          map = { 'value' },
          type = 'set',
        },
      },
      expression = 'undefined_rule',
    }, 'test_maps_expressions', 'MAPEXPR_CONSUMER')

    assert_nil(combined)
    assert_equal(#registered, 0)
  end)
end)
