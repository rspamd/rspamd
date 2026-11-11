local lua_util = require 'lua_util'

context('Fuzzy Redis update ordering', function()
  local function with_backend(f, mode, version_mode)
    local requests, versions, results, stored = {}, {}, {}, {}
    local original = package.loaded.lua_redis
    package.loaded.lua_redis = {
      load_redis_script_from_file = function() return 1 end,
      exec_redis_script = function(_, _, cb, keys, args)
        requests[#requests + 1] = { cb = cb, keys = keys, args = args }
        if mode == 'reject' then
          return false
        elseif mode == 'sync_error' then
          cb('test failure', nil)
        elseif mode == 'sync_ok' then
          cb(nil, 1)
        end
        return true
      end,
      redis_make_request_taskless = function(_, _, _, _, _, cb, _, args)
        versions[#versions + 1] = { cb = cb, key = args[1] }
        if version_mode == 'reject' then
          return false
        elseif version_mode == 'sync' then
          cb(nil, 1)
        end
        return true
      end,
    }
    local ok, err = pcall(function()
      local backend = dofile(lua_util.join_path(rspamd_paths.LUALIBDIR, 'lua_fuzzy_redis.lua'))
      local update = backend.lua_fuzzy_redis_init({})
      local function submit(updates, on_complete)
        update({}, 'fuzzy', updates, 'source', 3600, function(success)
          results[#results + 1] = success
          if on_complete then on_complete(success) end
        end)
      end
      local function complete(i, failure)
        local req = requests[i]
        assert(req and not req.done)
        req.done = true
        if not failure then
          if req.args[1] == 'del' then
            stored[req.keys[1]] = nil
          elseif req.args[1] == 'add' then
            stored[req.keys[1]] = req.args[2]
          end
        end
        req.cb(failure, 1)
      end
      f(submit, complete, requests, versions, results, stored)
    end)
    package.loaded.lua_redis = original
    assert(ok, err)
  end

  local function op(command, digest, flag)
    return { op = command, digest = digest or 'a', flag = flag or 11,
      value = 1, timestamp = 1000, is_weak = 0 }
  end

  test('delete then add survives reverse completion of independent requests', function()
    with_backend(function(submit, complete, requests, versions, results, stored)
      submit({ op('del', 'a', 13), op('dup'), op('add'), op('add', 'b') })
      assert_equal(2, #requests)
      complete(2)
      assert_equal(0, #versions)
      complete(1)
      assert_equal(3, #requests)
      complete(3)
      assert_equal('11', stored.fuzzya)
      assert_equal('11', stored.fuzzyb)
      assert_equal(1, #versions)
      assert_equal(0, #results)
      versions[1].cb(nil, 1)
      assert_equal(true, results[1])
    end)
  end)

  test('add refresh delete retains order across overlapping batches', function()
    with_backend(function(submit, complete, requests, versions, results, stored)
      submit({ op('add'), op('refresh') })
      submit({ op('del') })
      assert_equal(1, #requests)
      complete(1)
      assert_equal('refresh', requests[2].args[1])
      complete(2)
      assert_equal(2, #requests)
      assert_equal(1, #versions)
      versions[1].cb(nil, 1)
      assert_equal('del', requests[3].args[1])
      complete(3)
      assert_equal(nil, stored.fuzzya)
      assert_equal(2, #versions)
      versions[2].cb(nil, 1)
      assert_equal(2, #results)
    end)
  end)

  test('failed update drains its queue and reports failure once', function()
    with_backend(function(submit, complete, requests, versions, results)
      submit({ op('del'), op('add') })
      complete(1, 'test failure')
      assert_equal(2, #requests)
      complete(2)
      assert_equal(1, #versions)
      versions[1].cb(nil, 1)
      assert_equal(1, #results)
      assert_equal(false, results[1])
    end)
  end)

  test('empty and duplicate-only batches still increment the version', function()
    with_backend(function(submit, _, requests, versions, results)
      submit({})
      submit({ op('dup') })
      assert_equal(0, #requests)
      assert_equal(1, #versions)
      versions[1].cb(nil, 1)
      assert_equal(2, #versions)
      versions[2].cb(nil, 1)
      assert_equal(2, #results)
    end)
  end)

  for _, mode in ipairs({ 'reject', 'sync_error' }) do
    test('long queue handles synchronous failure without recursion: ' .. mode, function()
      with_backend(function(submit, _, requests, versions, results)
        local updates = {}
        for i = 1, 10000 do updates[i] = op('add') end
        submit(updates)
        assert_equal(#updates, #requests)
        assert_equal(1, #versions)
        versions[1].cb(nil, 1)
        assert_equal(1, #results)
        assert_equal(false, results[1])
        -- The drained queue must be reusable by a later batch.
        submit({ op('del') })
        assert_equal(#updates + 1, #requests)
        assert_equal(2, #versions)
      end, mode)
    end)
  end

  test('distinct hashes in the next batch wait for the preceding batch', function()
    with_backend(function(submit, complete, requests, versions, results)
      submit({ op('add', 'a'), op('add', 'b') })
      submit({ op('add', 'c'), op('add', 'd') })
      assert_equal(2, #requests)
      complete(2)
      assert_equal(0, #versions)
      complete(1)
      assert_equal(2, #requests)
      versions[1].cb(nil, 1)
      assert_equal(4, #requests)
      complete(4)
      complete(3)
      versions[2].cb(nil, 1)
      assert_equal(2, #results)
    end)
  end)

  test('reentrant completion preserves the order of waiting batches', function()
    with_backend(function(submit, complete, requests, versions, results)
      submit({ op('add', 'a') }, function() submit({ op('add', 'c') }) end)
      submit({ op('add', 'b') })
      complete(1)
      versions[1].cb(nil, 1)
      assert_equal('fuzzyb', requests[2].keys[1])
      complete(2)
      versions[2].cb(nil, 1)
      assert_equal('fuzzyc', requests[3].keys[1])
      complete(3)
      versions[3].cb(nil, 1)
      assert_equal(3, #results)
    end)
  end)

  test('version request rejection releases the next batch', function()
    with_backend(function(submit, complete, requests, _, results)
      submit({ op('add', 'a') })
      submit({ op('add', 'b') })
      complete(1)
      assert_equal(false, results[1])
      assert_equal(2, #requests)
      complete(2)
      assert_equal(false, results[2])
    end, nil, 'reject')
  end)

  test('many waiting batches finish synchronously without recursion', function()
    with_backend(function(submit, complete, requests, versions, results)
      submit({ op('add') })
      for _ = 1, 10000 do submit({ op('dup') }) end
      assert_equal(1, #requests)
      complete(1)
      assert_equal(10001, #versions)
      assert_equal(10001, #results)
    end, nil, 'sync')
  end)

  test('long repeated chain handles synchronous successes without recursion', function()
    with_backend(function(submit, _, requests, versions, results)
      local updates = {}
      for i = 1, 10000 do updates[i] = op('add') end
      submit(updates)
      assert_equal(#updates, #requests)
      assert_equal(1, #versions)
      versions[1].cb(nil, 1)
      assert_equal(true, results[1])
    end, 'sync_ok')
  end)

  test('binary digest and shingle arguments survive queued dispatch', function()
    with_backend(function(submit, complete, requests)
      local digest = string.rep('\0a', 32)
      local add = op('add', digest, 13)
      add.shingle_keys = { 'fuzzy_1_123', 'fuzzy_2_456' }
      submit({ op('del', digest), add })
      complete(1)
      assert_equal('fuzzy' .. digest, requests[2].keys[1])
      assert_equal('fuzzy_1_123', requests[2].keys[2])
      assert_equal('fuzzy_2_456', requests[2].keys[3])
      assert_equal('add', requests[2].args[1])
      assert_equal('13', requests[2].args[2])
      assert_equal('3600', requests[2].args[4])
      assert_equal('1000', requests[2].args[5])
      assert_equal('0', requests[2].args[6])
      assert_equal(digest, requests[2].args[7])
    end)
  end)
end)
