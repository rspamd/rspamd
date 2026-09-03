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
