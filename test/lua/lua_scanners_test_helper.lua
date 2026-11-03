local common = require "lua_scanners/common"
local rspamd_http = require "rspamd_http"
local rspamd_task = require "rspamd_task"
local lua_redis = require "lua_redis"

local exports = {}

function exports.extend(base, overrides)
  for key, value in pairs(overrides or {}) do
    base[key] = value
  end
  return base
end

function exports.with_mock(module, field, mock, fn)
  local original = module[field]
  module[field] = mock
  local ok, err = xpcall(fn, debug.traceback)
  module[field] = original
  if not ok then
    error(err)
  end
end

-- answers each HTTP request with the next { code, body } response; the last one repeats
function exports.with_http_responses(responses, fn)
  local urls = {}
  exports.with_mock(rspamd_http, 'request', function(options)
    table.insert(urls, options.url)
    local response = responses[math.min(#urls, #responses)]
    options.callback(nil, response[1], response[2] or '', {})
  end, fn)
  return urls
end

function exports.with_redis_cache(fn, initial_value)
  local cached = { value = initial_value }
  exports.with_mock(lua_redis, 'redis_make_request', function(_, _, _, _, callback, command, arguments)
    if command == 'SETEX' then
      cached.value = arguments[3]
      callback(nil)
    else
      assert(command == 'GET')
      callback(nil, cached.value)
    end
    return true
  end, function()
    fn(cached)
  end)
end

function exports.with_redis_value(value, fn)
  exports.with_redis_cache(fn, value)
end

function exports.make_rule(overrides)
  local rule = exports.extend({
    name = 'test_scanner',
    detection_category = 'virus',
    symbol = 'TEST_VIRUS',
    symbol_fail = 'TEST_VIRUS_FAIL',
    symbol_macro = 'TEST_MACRO',
    symbol_encrypted = 'TEST_ENCRYPTED',
    symbol_ignore = 'TEST_VIRUS_IGNORE',
    prefix = 'test_scanner_',
  }, overrides)
  rule.log_prefix = rule.log_prefix or rule.name
  return rule
end

function exports.make_task(cache)
  local task = { cache = cache or {}, results = {}, actions = {}, metric_action = 'no action' }
  function task.cache_get(self, key)
    return self.cache[key]
  end
  function task.cache_set(self, key, value)
    self.cache[key] = value
  end
  function task.insert_result(self, symbol, weight, reason)
    table.insert(self.results, { symbol = symbol, weight = weight, reason = reason })
  end
  function task.get_metric_action(self)
    return self.metric_action
  end
  function task.set_pre_result(self, action, message, module, _, _, flags)
    table.insert(self.actions, { action = action, message = message, module = module, flags = flags })
  end
  return task
end

function exports.make_part(filename)
  return {
    is_text = function()
      return false
    end,
    get_header = function() end,
    get_type_full = function()
      return 'application', 'octet-stream', {}
    end,
    get_detected_ext = function() end,
    get_digest = function()
      return 'test-digest'
    end,
    get_content = function()
      return 'test content'
    end,
    get_filename = function()
      return filename
    end,
  }
end

function exports.make_upstream(ip, events, port)
  local function record(event)
    if events then
      table.insert(events, event .. ':' .. ip)
    end
  end
  return {
    get_addr = function()
      return setmetatable({
        get_port = function()
          return port or 8100
        end,
        to_string = function()
          return ip
        end,
      }, {
        __tostring = function()
          return ip
        end,
      })
    end,
    fail = function()
      record('fail')
    end,
    ok = function()
      record('ok')
    end,
  }
end

function exports.make_upstreams(first, retry)
  local upstreams = { selected = {} }
  function upstreams.get_upstream_by_hash(_, digest)
    table.insert(upstreams.selected, digest)
    return first
  end
  function upstreams.get_upstream_round_robin()
    return retry
  end
  return upstreams
end

function exports.check_cached(task, rule, part)
  return common.condition_check_and_continue(task, 'test content', rule,
    'test-digest', function() error('unexpected uncached scan') end, part)
end

function exports.load_task(cache)
  local loaded, task = rspamd_task.load_from_string(
    'From: sender@example.com\nTo: recipient@example.com\nSubject: score test\n\nTest.\n',
    rspamd_config)
  assert(loaded)
  for key, value in pairs(cache or {}) do
    task:cache_set(key, value)
  end
  return task
end

function exports.load_task_with_attachment()
  local msg = table.concat({
    'From: <sender@example.com>\n',
    'To: <nobody@example.com>\n',
    'Subject: test\n',
    'Content-Type: multipart/mixed; boundary=XXX\n',
    '\n',
    '--XXX\n',
    'Content-Type: text/plain\n',
    '\n',
    'Test message body.\n',
    '--XXX\n',
    'Content-Type: application/octet-stream\n',
    'Content-Disposition: attachment; filename="test.bin"\n',
    'Content-Transfer-Encoding: base64\n',
    '\n',
    'dGVzdCBjb250ZW50\n',
    '--XXX--\n',
  })
  local res, task = rspamd_task.load_from_string(msg, rspamd_config)
  if not res then
    error("failed to load message")
  end
  task:process_message()
  for _, part in ipairs(task:get_parts()) do
    if part:get_filename() then
      return task, part
    end
  end
  error("expected multipart message to contain an attachment part")
end

function exports.register_metric_rule(rule, name)
  for _, definition in pairs(rule.symbols or {}) do
    definition.symbol = name .. '_' .. definition.symbol
  end
  local anchor = name .. '_CHECK'
  local parent = rspamd_config:register_symbol({
    name = anchor,
    type = 'normal',
    score = 0.0,
    callback = function() end,
  })
  common.register_scanner_symbols(parent, anchor, rule, 'test')
  return rule
end

return exports
