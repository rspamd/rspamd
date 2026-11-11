local rspamd_ip = require 'rspamd_ip'
local lua_util = require 'lua_util'

context('Fuzzy count scan address pinning', function()
  local function scan(address, saved_server)
    local requests, checkpoints = {}, {}
    local addr = rspamd_ip.from_string(address)
    assert(addr:is_valid())
    local selections = 0
    local upstream = {
      get_name = function() return 'redis.example' end,
      get_addr = function()
        selections = selections + 1
        return addr
      end,
    }
    local params = {
      read_servers = {
        get_upstream_round_robin = function() return upstream end,
        all_upstreams = function() return { upstream } end,
      },
    }
    local tick, now = nil, 1000
    local saved_config = rspamd_config
    local originals = {}
    local mocks = {
      rspamd_util = {
        get_hostname = function() return 'test' end,
        get_ticks = function() return now end,
        get_time = function() return now end,
      },
      rspamd_logger = {
        infox = function() end,
        warnx = function() end,
        errx = function() end,
      },
      lua_redis = {
        load_redis_script_from_file = function() return 1 end,
        exec_redis_script = function(_, _, cb, _, args)
          if args[1] == 'start' then
            if saved_server then
              cb(nil, { 'resume', 'redis.example', saved_server, '42', '7', '3', '999', '' })
            else
              cb(nil, { 'fresh' })
            end
          else
            checkpoints[#checkpoints + 1] = args
            cb(nil, 1)
          end
          return true
        end,
        request = function(_, attrs, req)
          requests[#requests + 1] = { host = attrs.host, cursor = req[2], upstream = attrs.upstream }
          attrs.callback(nil, { #requests == 1 and '17' or '0', { 'digest' } })
          return true
        end,
      },
    }
    for name, mock in pairs(mocks) do
      originals[name] = package.loaded[name]
      package.loaded[name] = mock
    end
    _G.rspamd_config = {
      add_periodic = function(_, _, _, cb) tick = cb end,
    }
    local ok, err = pcall(function()
      local scanner = dofile(lua_util.join_path(rspamd_paths.LUALIBDIR, 'lua_fuzzy_redis.lua'))
      assert(scanner.lua_fuzzy_redis_start_count_scan(params, {}, 'fuzzy', {
        stats_sample = 0, checkpoint_interval = 0, duty_cycle = 1,
      }))
      for _ = 1, 3 do
        tick()
        now = now + 1
      end
    end)
    _G.rspamd_config = saved_config
    for name in pairs(mocks) do
      package.loaded[name] = originals[name]
    end
    assert(ok, err)
    assert(#requests == 2, 'expected two SCAN batches')
    assert(requests[1].upstream == upstream)
    assert(type(requests[1].host) == 'userdata', 'SCAN host must remain address userdata')
    assert(requests[1].host:is_valid())
    assert(requests[1].host == requests[2].host)
    assert(requests[2].cursor == '17')
    assert(checkpoints[1][1] == 'checkpoint')
    assert(checkpoints[2][1] == 'finish')
    return requests[1], checkpoints, selections, addr
  end

  for _, address in ipairs({ '/tmp/redis.sock', '127.0.0.1:6380', '[::1]:6381' }) do
    test('fresh scan retains address userdata: ' .. address, function()
      local request, checkpoints, selections, addr = scan(address)
      assert_equal(addr, request.host)
      assert_equal('0', request.cursor)
      assert_equal(1, selections)
      assert_equal(addr:to_string(true), checkpoints[1][6])
    end)

    test('resumed scan restores its pinned address: ' .. address, function()
      local server = rspamd_ip.from_string(address):to_string(true)
      -- The upstream would select a different address; the saved cursor must
      -- continue on the exact endpoint recorded in its checkpoint.
      local request, checkpoints, selections = scan('127.0.0.2:6390', server)
      assert_equal(server, request.host:to_string(true))
      assert_equal('42', request.cursor)
      assert_equal(0, selections)
      assert_equal(server, checkpoints[1][6])
      assert_equal('9', checkpoints[2][7])
    end)
  end

  test('invalid checkpoint address starts a fresh scan', function()
    local request, _, selections = scan('127.0.0.1:6380', 'invalid address')
    assert_equal('127.0.0.1:6380', request.host:to_string(true))
    assert_equal('0', request.cursor)
    assert_equal(1, selections)
  end)
end)
