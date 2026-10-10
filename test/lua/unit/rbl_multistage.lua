context('RBL multistage helpers', function()
  local rbl = require 'plugins/rbl'
  local multistage = require 'lua_multistage'
  local ip = require 'rspamd_ip'

  local function dns_task(accept)
    local cache, facts, requests = {}, {}, {}
    local task = {
      cache_get = function(_, key) return cache[key] end,
      cache_set = function(_, key, value) cache[key] = value end,
      set_check_fact = function(_, key, value) facts[key] = value end,
      get_resolver = function()
        return {
          resolve = function(_, qtype, params)
            requests[#requests + 1] = { qtype = qtype, params = params }

            return accept
          end,
        }
      end,
    }

    return task, facts, requests
  end

  test('connection rewriters work in either registration order', function()
    for _, reverse in ipairs({ false, true }) do
      local edges = {}
      local cfg = { register_dependency = function(_, consumer, rewriter)
        edges[#edges + 1] = consumer .. ':' .. rewriter
      end }

      if reverse then
        multistage.register_connection_rewriter(cfg, 'RELAY')
      end

      multistage.register_connection_consumer(cfg, 'SPF')
      multistage.register_connection_consumer(cfg, 'RBL')
      multistage.register_connection_rewriter(cfg, 'RELAY')
      multistage.register_connection_consumer(cfg, 'SPF')
      table.sort(edges)
      assert_equal('RBL:RELAY,SPF:RELAY', table.concat(edges, ','))
    end
  end)

  test('mixed sources retain envelope eligibility except unrestricted guards', function()
    local early, late, replay = rbl.rule_phases { from = true, urls = true, selector = 'header(From)' }
    assert_true(early and late and replay)
    early, late, replay = rbl.rule_phases { helo = true, received = true, process_script = function() end }
    assert_true(early and late)
    assert_false(replay)
    early, late, replay = rbl.rule_phases { from = true, require_symbols = { 'HEADER' } }
    assert_true(early)
    assert_false(late or replay)
  end)

  test('DNS answers are coalesced and reused by the message phase', function()
    local task, facts, requests = dns_task(true)
    local dns = rbl.dns_session(task, 'rule', true)
    local results = 0
    local function found(ips, err)
      assert_nil(err)
      assert_equal('127.0.0.2', tostring(ips[1]))
      results = results + 1
    end

    dns.query('test.example', true, found)
    dns.query('test.example', true, found)
    dns.finish()
    assert_equal(1, #requests)
    assert_nil(facts.complete)
    requests[1].params.callback(nil, 'test.example', { ip.from_string('127.0.0.2') }, nil)
    assert_true(facts.complete)
    assert_equal(2, results)
    assert_equal('127.0.0.2', facts.answers['test.example'].results[1])
    local late = rbl.dns_session(task, 'rule', false)
    late.query('test.example', true, found)
    late.finish()
    assert_equal(1, #requests)
    assert_equal(3, results)
  end)

  test('DNS submission failure cannot be exported as a completed miss', function()
    local task, facts, requests = dns_task(false)
    local dns = rbl.dns_session(task, 'rule', true)
    dns.query('test.example', false, function() error('unexpected DNS callback') end)
    dns.query('test.example', true, function() error('unexpected DNS callback') end)
    dns.finish()
    assert_equal(2, #requests)
    assert_false(facts.complete)
  end)

  test('changed matcher data invalidates reuse without dropping current results', function()
    local task, facts, requests = dns_task(true)
    local dns = rbl.dns_session(task, 'rule', true)
    local digest = 'first'
    local rule = { returncodes_maps = { HIT = {
      get_data_digest = function() return digest end,
    } } }
    local saved = rbl.matcher_digests(rule)
    local called = false
    dns.query('test.example', true, function()
      called = true

      if saved.HIT ~= rbl.matcher_digests(rule).HIT then
        dns.invalidate()
      end
    end)
    dns.finish()
    digest = 'second'
    requests[1].params.callback(nil, 'test.example', { ip.from_string('127.0.0.2') }, nil)
    assert_true(called)
    assert_false(facts.complete)
  end)

  test('replayed answers require typed IP results and errors', function()
    assert_nil(rbl.decode_answers(false))
    assert_nil(rbl.decode_answers { query = { results = { false }, error = false } })
    assert_nil(rbl.decode_answers { query = { results = { 'invalid' }, error = false } })
    assert_nil(rbl.decode_answers { query = { results = {}, error = 1 } })
    local decoded = rbl.decode_answers { query = { results = { '127.0.0.2' }, error = false } }
    assert_equal('127.0.0.2', tostring(decoded.query.results[1]))
  end)
end)
