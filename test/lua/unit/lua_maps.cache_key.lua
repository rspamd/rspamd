-- Maps built from the same url list must not be shared across map types:
-- the cache key has to include the effective type of the map.
context("lua_maps - map cache key", function()
  local lua_maps = require "lua_maps"

  local function url_list()
    return { 'key value', 'other' }
  end

  test("same url list with different types yields different maps", function()
    local m_set = lua_maps.map_add_from_ucl(url_list(), 'set', 'cache key set map')
    local m_hash = lua_maps.map_add_from_ucl(url_list(), 'hash', 'cache key hash map')

    assert_not_nil(m_set)
    assert_not_nil(m_hash)
    assert_not_equal(m_set, m_hash)
    -- A hash map splits 'key value' into a kv pair, a set keeps the whole line
    assert_equal(m_hash:get_key('key'), 'value')
    assert_nil(m_set:get_key('key'))
    assert_true(m_set:get_key('key value'))
  end)

  test("same url list with the same type reuses the map", function()
    local first = lua_maps.map_add_from_ucl(url_list(), 'set', 'cache key set map')
    local second = lua_maps.map_add_from_ucl(url_list(), 'set', 'cache key set map again')

    assert_not_nil(first)
    assert_equal(first, second)
  end)

  test("inline and empty maps use the same callback contract as native maps", function()
    for _, values in ipairs({ { 'key value' }, {} }) do
      local map = lua_maps.map_add_from_ucl(values, 'hash', 'callback map')

      for _, key in ipairs({ 'key', 'missing' }) do
        local calls = 0
        local context = {}
        map:get_key(key, function(found, result, code, ctx)
          calls = calls + 1
          assert_equal(context, ctx)

          if key == 'key' and #values > 0 then
            assert_true(found)
            assert_equal('value', result)
            assert_equal(200, code)
          else
            assert_false(found)
            assert_equal(404, code)
          end
        end, context)
        assert_equal(1, calls)
      end
    end
  end)

  test("inline map digests distinguish values and effective types", function()
    local first = lua_maps.map_add_from_ucl({ 'key value' }, 'hash', 'first digest')
    local same = lua_maps.map_add_from_ucl({ 'key value' }, 'hash', 'same digest')
    local changed = lua_maps.map_add_from_ucl({ 'key other' }, 'hash', 'changed digest')
    local set = lua_maps.map_add_from_ucl({ 'key value' }, 'set', 'set digest')
    assert_equal(first:get_data_digest(), same:get_data_digest())
    assert_not_equal(first:get_data_digest(), changed:get_data_digest())
    assert_not_equal(first:get_data_digest(), set:get_data_digest())
  end)

  test("type prefix inside the list defines the effective type", function()
    -- `hash;` overrides whatever type the caller asked for, so requests for
    -- different types on the same prefixed list must converge on one map
    local function prefixed()
      return { 'hash;key value' }
    end
    local m_set = lua_maps.map_add_from_ucl(prefixed(), 'set', 'cache key prefixed map')
    local m_glob = lua_maps.map_add_from_ucl(prefixed(), 'glob', 'cache key prefixed map again')

    assert_not_nil(m_set)
    assert_equal(m_set, m_glob)
    assert_equal(m_set:get_key('key'), 'value')
  end)
end)
