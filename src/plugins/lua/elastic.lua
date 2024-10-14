--[[
Copyright (c) 2017, Veselin Iordanov
Copyright (c) 2022, Vsevolod Stakhov <vsevolod@rspamd.com>

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
]]--

local rspamd_logger = require 'rspamd_logger'
local rspamd_http = require "rspamd_http"
local lua_util = require "lua_util"
local rspamd_util = require "rspamd_util"
local ucl = require "ucl"
local upstream_list = require "rspamd_upstream_list"

if confighelp then
  return
end

local N = "elastic"
local connect_prefix = 'http://'
local rspamd_hostname = rspamd_util.get_hostname()
-- supported_distro:
-- from - minimal compatible version supported, including
-- till & till_unknown = true - yet unreleased version, so unknown compitability, excluding
-- hill & till_unknown = false - version is known to be not yet compatible with this module
local supported_distro = {
  elastic = {
    from = '7.8',
    till = '9',
    till_unknown = true,
  },
  opensearch = {
    from = '1',
    till = '3',
    till_unknown = true,
  },
}
local detected_distro = {
  name = nil,
  version = nil,
  supported = false,
}
local states = {
  distro = {
    configured = false,
    errors = 0,
  },
  index_template = {
    configured = false,
    errors = 0,
  },
  index_policy = {
    configured = false,
    errors = 0,
  },
  geoip_pipeline = {
    configured = false,
    errors = 0,
  },
}
local settings = {
  enabled = true,
  version = {
    autodetect_enabled = true,
    autodetect_max_fail  = 12,
    -- override works only if autodetect is disabled
    override = {
      name = 'opensearch',
      version = '2.17',
    }
  },
  limits = {
    max_rows = 500, -- max logs in one bulk req to elastic and first reason to flush buffer
    max_interval = 60, -- seconds, if first log in buffer older then interval - flush buffer
    max_size = 5000000, -- max symbols count in buffer, if reached - flush buffer, f.e: 5000000 ~= 10MB/normal-worker
    max_fail = 3,
  },
  index_template = {
    managed = true,
    name = 'rspamd',
    pattern = '{service}-%Y.%m.%d',
    priority = 0,
    shards_count = 3,
    replicas_count = 1,
    refresh_interval = 5, -- seconds
    dynamic_keyword_ignore_above = 256,
    headers_text_ignore_above = 2048, -- strip headers value and add '...' to the end, set 0 to disable limit
    symbols_nested = false,
    empty_value = 'unknown', -- empty numbers, ips and ipnets are not customizable they will be always 0, :: and ::/128 respectively
  },
  index_policy = {
    enabled = true,
    managed = true,
    name = 'rspamd', -- if you want use custom lifecycle policy, change name and set managed = false
    hot = {
      index_priority = 100,
    },
    warm = {
      enabled = true,
      after = '2d',
      index_priority = 50,
      migrate = true, -- only supported with elastic distro, will not have impact elsewhere
      read_only = true,
      change_replicas = false,
      replicas_count = 1,
      shrink = false,
      shards_count = 1,
      max_gb_per_shard = 0, -- zero - disabled by default, if enabled - shards_count is ignored
      force_merge = true,
      segments_count = 1,
    },
    cold = {
      enabled = true,
      after = '14d',
      index_priority = 0,
      migrate = true, -- only supported with elastic distro, will not have impact elsewhere
      read_only = true,
      change_replicas = false,
      replicas_count = 1,
    },
    delete = {
      enabled = true,
      after = '30d',
    },
  },
  collect_headers = {
    'From',
    'To',
    'Subject',
    'Date',
    'User-Agent',
  },
  extra_collect_headers = {
    -- 'List-Id',
    -- 'X-Mailer',
  },
  geoip = {
    enabled = true,
    managed = true,
    pipeline_name = 'rspamd-geoip',
  },
  periodic_interval = 5.0,
  timeout = 5.0,
  use_https = false,
  no_ssl_verify = false,
  use_gzip = true,
  use_keepalive = true,
  allow_local = false,
  user = nil,
  password = nil,
}

local Queue = {}
Queue.__index = Queue

function Queue:new()
  local obj = {first = 1, last = 0, data = {}}
  setmetatable(obj, self)
  return obj
end

function Queue:push(value)
  self.last = self.last + 1
  self.data[self.last] = value
end

function Queue:length()
  return self.last - self.first + 1
end

function Queue:size()
  local size = 0
  for i = self.first, self.last do
    local row = self.data[i]
    if row ~= nil then
      size = size + #row
    end
  end
  return size
end

function Queue:get(index)
  local real_index = self.first + index - 1
  if real_index <= self.last then
    return self.data[real_index]
  else
    return nil
  end
end

function Queue:get_all()
  local items = {}
  for i = self.first, self.last do
    table.insert(items, self.data[i])
  end
  return items
end

function Queue:pop()
  if self.first > self.last then
    return nil
  end
  local value = self.data[self.first]
  self.data[self.first] = nil
  self.first = self.first + 1
  return value
end

function Queue:get_first(count)
  local items = {}
  count = count or self:length()
  local actual_end = math.min(self.first + count - 1, self.last)
  for i = self.first, actual_end do
    table.insert(items, self.data[i])
  end
  return items
end

function Queue:pop_first(count)
  local popped_items = {}
  count = count or self:length()
  local actual_count = math.min(count, self:length())
  local n = 0
  while n < actual_count do
    local item = self:pop()
    table.insert(popped_items, item)
    n = n + 1
  end
  return popped_items
end

local buffer = {
  logs = Queue:new(),
  errors = 0,
}

local function contains(tbl, val)
  for i=1,#tbl do
    if tbl[i]:lower() == val:lower() then
      return true
    end
  end
  return false
end

local function safe_get(table, ...)
  local value = table
  for _, key in ipairs({...}) do
    if value[key] == nil then
      return nil
    end
    value = value[key]
  end
  return value
end

local function compare_versions(v1, v2)
  -- helper function to extract the numeric version string
  local function extract_numeric_version(version)
    -- remove any trailing characters that are not digits or dots
    version = version:match("^([%.%d]+)")
    local parts = {}
    for part in string.gmatch(version or "", '([^.]+)') do
      table.insert(parts, tonumber(part) or 0)
    end
    return parts
  end

  local v1_parts = extract_numeric_version(v1)
  local v2_parts = extract_numeric_version(v2)
  local max_length = math.max(#v1_parts, #v2_parts)

  -- compare each part of the version strings
  for i = 1, max_length do
    local num1 = v1_parts[i] or 0
    local num2 = v2_parts[i] or 0

    if num1 > num2 then
      return 1  -- v1 is greater than v2
    elseif num1 < num2 then
      return -1 -- v1 is less than v2
    end
    -- if equal, continue to the next part
  end
  return 0 -- versions are equal
end

local function handle_error(action,component,limit)
  if states[component]['errors'] >= limit then
    rspamd_logger.errx(rspamd_config, 'cannot %s elastic %s, failed attempts: %s/%s, stop trying',
      action, component:gsub('_', ' '), states[component]['errors'], limit)
    states[component]['configured'] = true
  else
    states[component]['errors'] = states[component]['errors'] + 1
  end
  return true
end

local function get_received_delay(received_headers)
  local now = math.floor(rspamd_util.get_time())
  local timestamp = 0
  local delay = 0
  for i, received_header in ipairs(received_headers) do
    -- skip first received_header as it's own relay
    if i > 1 and received_header['timestamp'] and received_header['timestamp'] > 0 then
      timestamp = received_header['timestamp']
      break
    end
  end
  if timestamp > 0 then
    delay = now - timestamp
    if delay < 0 then
      delay = 0
    end
  end
  return delay
end

local function create_bulk_json(es_index, logs_to_send)
  local tbl = {}
  for _, row in pairs(logs_to_send) do
    local pipeline = ''
    if settings['geoip']['enabled']then
      pipeline = ',"pipeline":"'.. settings['geoip']['pipeline_name'] .. '"'
    end
    table.insert(tbl, '{"index":{"_index":"' .. es_index .. '"' .. pipeline .. '}}')
    table.insert(tbl, ucl.to_format(row, 'json-compact'))
  end
  table.insert(tbl, '') -- for last \n
  return table.concat(tbl, "\n")
end

local function elastic_send_data(flush_all, task, cfg, ev_base)
  local log_object = task or rspamd_config
  local nlogs_to_send = 0
  local es_index
  local upstream
  local host
  local push_url
  local bulk_json
  local logs_to_send
  if flush_all then
    logs_to_send = buffer['logs']:get_all()
  else
    logs_to_send = buffer['logs']:get_first(settings['limits']['max_rows'])
  end
  nlogs_to_send = #logs_to_send -- actual size can be lower then max_rows
  if nlogs_to_send > 0 then
    es_index = settings['index_template']['name'] .. '-' .. os.date(settings['index_template']['pattern'])

    upstream = settings.upstream:get_upstream_round_robin()
    host = upstream:get_name():gsub(":[1-9][0-9]*$", "")
    local ip_addr = upstream:get_addr():to_string(true)
    push_url = connect_prefix .. ip_addr .. '/' .. es_index .. '/_bulk'

    bulk_json = create_bulk_json(es_index, logs_to_send)
    rspamd_logger.debugm(N, log_object, 'successfully composed payload with %s log lines', nlogs_to_send)
  end

  local function http_callback(err, code, body, _)
    local push_done = false
    local push_errors = false
    if err then
      rspamd_logger.errx(log_object, 'cannot send logs to elastic (%s): %s; failed attempts: %s/%s',
        push_url, err, buffer['errors'], settings['limits']['max_fail'])
    elseif code == 200 then
      local parser = ucl.parser()
      local res, ucl_err = parser:parse_string(body)
      if not ucl_err and res then
        local obj = parser:get_object()
        if not obj['errors'] then
          push_done = true
          rspamd_logger.debugm(N, log_object, 'successfully sent payload with %s logs', nlogs_to_send)
        else
          push_errors = true
          for _, value in pairs(obj['items']) do
            if value['index']['status'] >= 400 then
              if value['index']['error'] then
                if value['index']['error']['type'] and value['index']['error']['reason'] then
                  rspamd_logger.errx(log_object,
                    'cannot send logs to elastic (%s) due to error: %s status, %s type, due to: %s; failed attempts: %s/%s',
                    push_url, value['index']['status'], value['index']['error']['type'], value['index']['error']['reason'],
                    buffer['errors'], settings['limits']['max_fail'])
                end
              end
            end
          end
        end
      else
        rspamd_logger.errx(log_object,
          'cannot parse response from elastic (%s): %s; failed attempts: %s/%s',
          push_url, ucl_err, buffer['errors'], settings['limits']['max_fail'])
      end
    else
      rspamd_logger.errx(log_object,
        'cannot send logs to elastic (%s) due to bad http status code: %s, response: %s; failed attempts: %s/%s',
        push_url, code, body, buffer['errors'], settings['limits']['max_fail'])
    end
    -- proccess results
    if push_done then
      buffer['logs']:pop_first(nlogs_to_send)
      buffer['errors'] = 0
      upstream:ok()
    else
      if buffer['errors'] >= settings['limits']['max_fail'] then
        rspamd_logger.errx(log_object, 'failed to send %s log lines, failed attempts: %s/%s, removing failed logs from bugger',
          nlogs_to_send, buffer['errors'], settings['limits']['max_fail'])
        buffer['logs']:pop_first(nlogs_to_send)
        buffer['errors'] = 0
      else
        buffer['errors'] = buffer['errors'] + 1
      end
      if push_errors then
        upstream:ok() -- we not assume upstream is failed if it return errors in response body
      else
        upstream:fail()
      end
    end
  end

  if nlogs_to_send > 0 then
    local http_request = {
      url = push_url,
      headers = {
        ['Host'] = host,
        ['Content-Type'] = 'application/x-ndjson',
      },
      body = bulk_json,
      method = 'post',
      callback=http_callback,
      gzip = settings.use_gzip,
      keepalive = settings.use_keepalive,
      no_ssl_verify = settings.no_ssl_verify,
      user = settings.user,
      password = settings.password,
      timeout = settings.timeout,
    }
    if task then
      http_request['task'] = task
    else
      http_request['ev_base'] = ev_base
      http_request['config'] = cfg
    end
    return rspamd_http.request(http_request)
  end
end

local function get_header_name(name)
  return 'header_' .. name:lower():gsub('[%s%-]', '_')
end

local function get_general_metadata(task)
  local r = {}
  local empty = settings['index_template']['empty_value']
  local user = task:get_user()
  r.rspamd_server = rspamd_hostname or empty

  r.action = task:get_metric_action() or empty
  r.score = task:get_metric_score()[1] or 0
  r.symbols = task:get_symbols_all()
  for _, symbol in ipairs(r.symbols) do
    symbol.groups = nil -- we don't need groups array in elastic
    if type(symbol.options) == "table" then
      symbol.options = table.concat(symbol.options, "; ")
    end
  end
  r.user = user or empty
  if user then
    r.direction = "Outbound"
  else
    r.direction = "Inbound"
  end
  r.qid = task:get_queue_id() or empty
  r.helo = task:get_helo() or empty
  r.hostname = task:get_hostname() or empty

  r.ip = '::'
  r.is_local = false
  local ip_addr = task:get_ip()
  if ip_addr and ip_addr:is_valid() then
    r.is_local = ip_addr:is_local()
    r.ip = tostring(ip_addr)
  end

  r.sender_ip = '::'
  local origin = task:get_header('X-Originating-IP')
  if origin then
    origin = origin:gsub('%[', ''):gsub('%]', '')
    local rspamd_ip = require "rspamd_ip"
    local origin_ip = rspamd_ip.from_string(origin)
    if origin_ip and origin_ip:is_valid() then
      r.sender_ip = origin -- use string here
    end
  end

  local message_id = task:get_message_id()
  if message_id == 'undef' then
    r.message_id = empty
  else
    r.message_id = message_id
  end
  if task:has_recipients('smtp') then
    local rcpt = task:get_recipients('smtp')
    local l = {}
    for _, a in ipairs(rcpt) do
      table.insert(l, a['addr'])
    end
    r.rcpt = l
  else
    r.rcpt = empty
  end

  r.from_domain = empty
  r.from_user = empty
  if task:has_from('smtp') then
    local from = task:get_from({ 'smtp', 'orig' })[1]
    if from then
      r.from_domain = from['domain']:lower()
      r.from_user = from['user']:lower()
    end
  end

  r.mime_from_domain = empty
  r.mime_from_user = empty
  if task:has_from('mime') then
    local mime_from = task:get_from({ 'mime', 'orig' })[1]
    if mime_from then
      r.mime_from_domain = mime_from['domain']:lower()
      r.mime_from_user = mime_from['user']:lower()
    end
  end

  local settings_id = task:get_settings_id()
  if settings_id then
    -- Convert to string
    local lua_settings = require "lua_settings"
    settings_id = lua_settings.settings_by_id(settings_id)
    if settings_id then
      settings_id = settings_id.name
    end
  end
  if not settings_id then
    settings_id = empty
  end
  r.settings_id = settings_id

  r.asn = {}
  local pool = task:get_mempool()
  r.asn.country = pool:get_variable("country") or empty
  r.asn.asn = pool:get_variable("asn") or 0
  r.asn.ipnet = pool:get_variable("ipnet") or '::/128'

  local function process_header(name)
    local hdr = task:get_header_full(name)
    local headers_text_ignore_above = settings['index_template']['headers_text_ignore_above'] - 3
    if hdr then
      local l = {}
      for _, h in ipairs(hdr) do
        table.insert(l, h.decoded)
      end
      if #l > headers_text_ignore_above and headers_text_ignore_above ~= -3 then
        l = l:sub(1, headers_text_ignore_above) .. '...'
      end
      return l
    else
      return empty
    end
  end

  for _, header in ipairs(settings['collect_headers']) do
    local header_name = get_header_name(header)
    if not r[header_name] then
      r[header_name] = process_header(header)
    end
  end

  for _, header in ipairs(settings['extra_collect_headers']) do
    local header_name = get_header_name(header)
    if not r[header_name] then
      r[header_name] = process_header(header)
    end
  end

  local scan_real = task:get_scan_time()
  scan_real = math.floor(scan_real * 1000)
  if scan_real < 0 then
    rspamd_logger.messagex(task,
        'clock skew detected for message: %s ms real scan time (reset to 0)',
        scan_real)
    scan_real = 0
  end
  r.scan_time = scan_real

  local parts = task:get_text_parts()
  local lang_t = {}
  if parts then
    for _, part in ipairs(parts) do
        local l = part:get_language()
        if l and not contains(lang_t, l) then
          table.insert(lang_t, l)
        end
    end
    if #lang_t > 0 then
      r.language = lang_t
    else
      r.language = empty
    end
    if #lang_t == 1 and lang_t[1] == 'en' then
      r.non_en = false
    else
      r.non_en = true
    end
  end

  local fuzzy_hashes = task:get_mempool():get_variable('fuzzy_hashes', 'fstrings')
  r.fuzzy_hashes = fuzzy_hashes or empty

  r.received_delay = get_received_delay(task:get_received_headers())

  return r
end

local function elastic_collect(task)
  if task:has_flag('skip') then
    return
  end

  if not settings.allow_local and lua_util.is_rspamc_or_controller(task) then
    return
  end

  if not detected_distro['supported'] then
    if buffer['logs']:length() >= settings['limits']['max_rows'] then
      buffer['logs']:pop_first(settings['limits']['max_rows'])
      rspamd_logger.errx(task,
        'elastic distro not supported, deleting %s logs from buffer due to reaching max rows limit',
        settings['limits']['max_rows'])
    end
  end

  local now = tostring(rspamd_util.get_time() * 1000)
  local row = { ['rspamd_meta'] = get_general_metadata(task), ['@timestamp'] = now }
  buffer['logs']:push(row)
  rspamd_logger.debugm(N, task, 'saved log to buffer')
end

local function periodic_send_data(cfg, ev_base)
  local now = tostring(rspamd_util.get_time() * 1000)
  local flush_needed = false

  local nlogs_total = buffer['logs']:length()
  if nlogs_total >= settings['limits']['max_rows'] then
    rspamd_logger.infox(rspamd_config, 'flushing buffer by reaching max rows: %s/%s', nlogs_total, settings['limits']['max_rows'])
    flush_needed = true
  else
    local first_row = buffer['logs']:get(1)
    if first_row then
      local time_diff = now - first_row['@timestamp']
      local time_diff_sec = lua_util.round((time_diff / 1000), 1)
      if time_diff_sec > settings.limits.max_interval then
        rspamd_logger.infox(rspamd_config, 'flushing buffer for %s by reaching max interval, oldest log in buffer written %s sec ago',
          time_diff_sec, first_row['@timestamp'])
        flush_needed = true
      else
        local size = buffer['logs']:size()
        if size >= settings['limits']['max_size'] then
          rspamd_logger.infox(rspamd_config, 'flushing buffer by reaching max size: %s/%s', size, settings['limits']['max_size'])
          flush_needed = true
        end
      end
    end
  end

  if flush_needed then
    elastic_send_data(false, nil, cfg, ev_base)
  end
end

local function configure_geoip_pipeline(cfg, ev_base)
  local upstream = settings.upstream:get_upstream_round_robin()
  local host = upstream:get_name():gsub(":[1-9][0-9]*$", "")
  local ip_addr = upstream:get_addr():to_string(true)
  local geoip_url = connect_prefix .. ip_addr .. '/_ingest/pipeline/' .. settings['geoip']['pipeline_name']
  local geoip_pipeline = {
    description = "Add geoip info for rspamd",
    processors = {
      {
        geoip = {
          field = "rspamd_meta.ip",
          target_field = "rspamd_meta.geoip"
        }
      },
      {
        geoip = {
          field = "rspamd_meta.sender_ip",
          target_field = "rspamd_meta.sender_geoip"
        }
      }
    }
  }

  local function geoip_cb(err, code, body, _)
    if err then
      rspamd_logger.errx(rspamd_config, 'cannot connect to elastic (%s): %s', geoip_url, err)
      upstream:fail()
    elseif code == 200 then
      states['geoip_pipeline']['configured'] = true
      upstream:ok()
    else
      rspamd_logger.errx(rspamd_config,
        'cannot configure elastic geoip pipeline (%s), status code: %s, response: %s',
        geoip_url, code, body)
      upstream:fail()
      handle_error('configure', 'geoip_pipeline', settings['limits']['max_fail'])
    end
  end

  rspamd_http.request({
    url = geoip_url,
    ev_base = ev_base,
    config = cfg,
    callback = geoip_cb,
    headers = {
      ['Host'] = host,
      ['Content-Type'] = 'application/json',
    },
    body = ucl.to_format(geoip_pipeline, 'json-compact'),
    method = 'put',
    gzip = settings.use_gzip,
    keepalive = settings.use_keepalive,
    no_ssl_verify = settings.no_ssl_verify,
    user = settings.user,
    password = settings.password,
    timeout = settings.timeout,
  })
end

local function put_index_policy(cfg, ev_base, upstream, host, policy_url, index_policy_json)
  local function http_callback(err, code, body, _)
    if err then
      rspamd_logger.errx(rspamd_config, 'cannot connect to elastic (%s): %s', policy_url, err)
      upstream:fail()
    elseif code == 200 or code == 201 then
      rspamd_logger.infox(rspamd_config, 'successfully updated elastic index policy: %s', body)
      states['index_policy']['configured'] = true
      upstream:ok()
    else
      rspamd_logger.errx(rspamd_config, 'cannot configure elastic index policy (%s), status code: %s, response: %s', policy_url, code, body)
      upstream:fail()
      handle_error('configure', 'index_policy', settings['limits']['max_fail'])
    end
  end

  rspamd_http.request({
    url = policy_url,
    ev_base = ev_base,
    config = cfg,
    body = index_policy_json,
    headers = {
      ['Host'] = host,
      ['Content-Type'] = 'application/json',
    },
    method = 'put',
    callback = http_callback,
    gzip = settings.use_gzip,
    keepalive = settings.use_keepalive,
    no_ssl_verify = settings.no_ssl_verify,
    user = settings.user,
    password = settings.password,
    timeout = settings.timeout,
  })
end

local function get_index_policy(cfg, ev_base, upstream, host, policy_url, index_policy_json)
  local function http_callback(err, code, body, _)
    if err then
      rspamd_logger.errx(rspamd_config, 'cannot connect to elastic (%s): %s', policy_url, err)
      upstream:fail()
    elseif code == 404 then
      put_index_policy(cfg, ev_base, upstream, host, policy_url, index_policy_json)
    elseif code == 200 then
      local remote_policy_parser = ucl.parser()
      local our_policy_parser = ucl.parser()
      local rp_res, rp_ucl_err = remote_policy_parser:parse_string(body)
      if rp_res and not rp_ucl_err then
        local op_res, op_ucl_err = our_policy_parser:parse_string(index_policy_json)
        if op_res and not op_ucl_err then
          local remote_policy = remote_policy_parser:get_object()
          local our_policy = our_policy_parser:get_object()
          local update_needed = false
          if detected_distro['name'] == 'elastic' then
            local index_policy_name = settings['index_policy']['name']
            local current_phases = safe_get(remote_policy, index_policy_name, 'policy', 'phases')
            if not lua_util.table_cmp(our_policy['policy']['phases'], current_phases) then
              update_needed = true
            end
          elseif detected_distro['name'] == 'opensearch' then
            local current_default_state = safe_get(remote_policy, 'policy', 'default_state')
            local current_ism_index_patterns = safe_get(remote_policy, 'policy', 'ism_template', 1, 'index_patterns')
            local current_states = safe_get(remote_policy, 'policy', 'states')
            if not lua_util.table_cmp(our_policy['policy']['default_state'], current_default_state) then
              update_needed = true
            elseif not lua_util.table_cmp(our_policy['policy']['ism_template'][1]['index_patterns'], current_ism_index_patterns) then
              update_needed = true
            elseif not lua_util.table_cmp(our_policy['policy']['states'], current_states) then
              update_needed = true
            end
          end
          if not update_needed then
            rspamd_logger.infox(rspamd_config, 'elastic index policy is up-to-date')
            states['index_policy']['configured'] = true
          else
            if detected_distro['name'] == 'elastic' then
              put_index_policy(cfg, ev_base, upstream, host, policy_url, index_policy_json)
            elseif detected_distro['name'] == 'opensearch' then
              local seq_no = remote_policy['_seq_no']
              local primary_term = remote_policy['_primary_term']
              if type(seq_no) == 'number' and type(primary_term) == 'number' then
                upstream:ok()
                -- adjust policy url to include seq_no with primary_term
                -- https://opensearch.org/docs/2.17/im-plugin/ism/api/#update-policy
                policy_url = policy_url .. '?if_seq_no=' .. seq_no .. '&if_primary_term=' .. primary_term
                put_index_policy(cfg, ev_base, upstream, host, policy_url, index_policy_json)
              else
                rspamd_logger.errx(rspamd_config,
                  'current elastic index policy (%s) not returned correct seq_no/primary_term, policy will not be updated, response: %s',
                  policy_url, body)
                upstream:fail()
                handle_error('validate current', 'index_policy', settings['limits']['max_fail'])
              end
            end
          end
        else
          rspamd_logger.errx(rspamd_config, 'failed to parse our index policy for elastic: %s', ucl_err)
          upstream:fail()
          handle_error('parse our', 'index_policy', settings['limits']['max_fail'])
        end
      else
        rspamd_logger.errx(rspamd_config, 'failed to parse remote index policy from elastic: %s', ucl_err)
        upstream:fail()
        handle_error('parse remote', 'index_policy', settings['limits']['max_fail'])
      end
    else
      rspamd_logger.errx(rspamd_config,
        'cannot get current elastic index policy (%s), status code: %s, response: %s',
        policy_url, code, body)
      handle_error('get current', 'index_policy', settings['limits']['max_fail'])
      upstream:fail()
    end
  end

  rspamd_http.request({
    url = policy_url,
    ev_base = ev_base,
    config = cfg,
    headers = {
      ['Host'] = host,
      ['Content-Type'] = 'application/json',
    },
    method = 'get',
    callback = http_callback,
    gzip = settings.use_gzip,
    keepalive = settings.use_keepalive,
    no_ssl_verify = settings.no_ssl_verify,
    user = settings.user,
    password = settings.password,
    timeout = settings.timeout,
  })
end

local function configure_index_policy(cfg, ev_base)
  local upstream = settings.upstream:get_upstream_round_robin()
  local host = upstream:get_name():gsub(":[1-9][0-9]*$", "")
  local ip_addr = upstream:get_addr():to_string(true)
  local index_policy_path = nil
  local index_policy = {}
  if detected_distro['name'] == 'elastic' then
    index_policy_path = '/_ilm/policy/'
  elseif detected_distro['name'] == 'opensearch' then
    index_policy_path = '/_plugins/_ism/policies/'
  end
  local policy_url = connect_prefix .. ip_addr .. index_policy_path .. settings['index_policy']['name']

  -- ucl.to_format(obj, 'json') can't manage empty {} objects, it will be treat them as [] in json as result,
  -- so we write {} as '{emty_object}', which allows us to replace '"{emty_object}"' string after convertion to json to '{}'
  local index_policy_json = ''

  -- elastic lifecycle policy with hot state
  if detected_distro['name'] == 'elastic' then
    index_policy = {
      policy = {
        phases = {
          hot = {
            min_age = '0ms',
            actions = {
              set_priority = {
                priority = settings['index_policy']['hot']['index_priority'],
              },
            },
          },
        },
      },
    }
    -- elastic lifecycle warm
    if settings['index_policy']['warm']['enabled'] then
      local warm_obj = {}
      warm_obj['min_age'] = settings['index_policy']['warm']['after']
      warm_obj['actions'] = {
        set_priority = {
          priority = settings['index_policy']['warm']['index_priority'],
        },
      }
      if not settings['index_policy']['warm']['migrate'] then
        warm_obj['actions']['migrate'] = { enabled = false }
      end
      if settings['index_policy']['warm']['read_only'] then
        warm_obj['actions']['readonly'] = '{empty_object}'
      end
      if settings['index_policy']['warm']['change_replicas'] then
        warm_obj['actions']['allocate'] = {
          number_of_replicas = settings['index_policy']['warm']['replicas_count'],
        }
      end
      if settings['index_policy']['warm']['shrink'] then
        if settings['index_policy']['warm']['max_gb_per_shard'] then
          warm_obj['actions']['shrink'] = {
            max_primary_shard_size = settings['index_policy']['warm']['max_gb_per_shard'] .. 'gb',
          }
        else
          warm_obj['actions']['shrink'] = {
            number_of_shards = settings['index_policy']['warm']['shards_count'],
          }
        end
      end
      if settings['index_policy']['warm']['force_merge'] then
        warm_obj['actions']['forcemerge'] = {
          max_num_segments = settings['index_policy']['warm']['segments_count'],
        }
      end
      index_policy['policy']['phases']['warm'] = warm_obj
    end
    -- elastic lifecycle cold
    if settings['index_policy']['cold']['enabled'] then
      local cold_obj = {}
      cold_obj['min_age'] = settings['index_policy']['cold']['after']
      cold_obj['actions'] = {
        set_priority = {
          priority = settings['index_policy']['cold']['index_priority'],
        },
      }
      if not settings['index_policy']['cold']['migrate'] then
        cold_obj['actions']['migrate'] = { enabled = false }
      end
      if settings['index_policy']['cold']['read_only'] then
        cold_obj['actions']['readonly'] = '{empty_object}'
      end
      if settings['index_policy']['cold']['change_replicas'] then
        cold_obj['actions']['allocate'] = {
          number_of_replicas = settings['index_policy']['cold']['replicas_count'],
        }
      end
      index_policy['policy']['phases']['cold'] = cold_obj
    end
    -- elastic lifecycle delete
    if settings['index_policy']['delete']['enabled'] then
      local delete_obj = {}
      delete_obj['min_age'] = settings['index_policy']['delete']['after']
      delete_obj['actions'] = {
        delete = { delete_searchable_snapshot = true },
      }
      index_policy['policy']['phases']['delete'] = delete_obj
    end
  -- opensearch state policy with hot state
  elseif detected_distro['name'] == 'opensearch' then
    local retry = {
      count = 3,
      backoff = 'exponential',
      delay = '1m',
    }
    index_policy = {
      policy = {
        description = 'Rspamd index state policy',
        ism_template = {
          {
            index_patterns = { settings['index_template']['name'] .. '-*' },
            priority = 100,
          },
        },
        default_state = 'hot',
        states = {
          {
            name = 'hot',
            actions = {
              {
                index_priority = {
                  priority = settings['index_policy']['hot']['index_priority'],
                },
                retry = retry,
              },
            },
            transitions = {},
          },
        },
      },
    }
    local state_id = 1 -- includes hot state
    -- opensearch state warm
    if settings['index_policy']['warm']['enabled'] then
      local prev_state_id = state_id
      state_id = state_id + 1
      index_policy['policy']['states'][prev_state_id]['transitions'] = {
        {
          state_name = 'warm',
          conditions = {
            min_index_age = settings['index_policy']['warm']['after']
          },
        },
      }
      local warm_obj = {
        name = 'warm',
        actions = {
          {
            index_priority = {
              priority = settings['index_policy']['warm']['index_priority'],
            },
            retry = retry,
          },
        },
        transitions = {},
      }
      table.insert(index_policy['policy']['states'], warm_obj)
      if settings['index_policy']['warm']['read_only'] then
        local read_only = {
          read_only = '{empty_object}',
          retry = retry,
        }
        table.insert(index_policy['policy']['states'][state_id]['actions'], read_only)
      end
      if settings['index_policy']['warm']['change_replicas'] then
        local change_replicas = {
          replica_count = {
            number_of_replicas = settings['index_policy']['warm']['replicas_count'],
          },
          retry = retry,
        }
        table.insert(index_policy['policy']['states'][state_id]['actions'], change_replicas)
      end
      if settings['index_policy']['warm']['shrink'] then
        local shrink = {
          shrink = {},
          retry = retry,
        }
        if settings['index_policy']['warm']['max_gb_per_shard'] then
          shrink['shrink']['max_shard_size'] = settings['index_policy']['warm']['max_gb_per_shard'] .. 'gb'
        else
          shrink['shrink']['num_new_shards'] = settings['index_policy']['warm']['shards_count']
        end
        shrink['shrink']['switch_aliases'] = false
        table.insert(index_policy['policy']['states'][state_id]['actions'], shrink)
      end
      if settings['index_policy']['warm']['force_merge'] then
        local force_merge = {
          force_merge = {
            max_num_segments = settings['index_policy']['warm']['segments_count'],
          },
          retry = retry,
        }
        table.insert(index_policy['policy']['states'][state_id]['actions'], force_merge)
      end
    end
    -- opensearch state cold
    if settings['index_policy']['cold']['enabled'] then
      local prev_state_id = state_id
      state_id = state_id + 1
      index_policy['policy']['states'][prev_state_id]['transitions'] = {
        {
          state_name = 'cold',
          conditions = {
            min_index_age = settings['index_policy']['cold']['after']
          },
        },
      }
      local cold_obj = {
        name = 'cold',
        actions = {
          {
            index_priority = {
              priority = settings['index_policy']['cold']['index_priority'],
            },
            retry = retry,
          },
        },
        transitions = {},
      }
      table.insert(index_policy['policy']['states'], cold_obj)
      if settings['index_policy']['cold']['read_only'] then
        local read_only = {
          read_only = '{empty_object}',
          retry = retry,
        }
        table.insert(index_policy['policy']['states'][state_id]['actions'], read_only)
      end
      if settings['index_policy']['cold']['change_replicas'] then
        local change_replicas = {
          replica_count = {
            number_of_replicas = settings['index_policy']['cold']['replicas_count'],
          },
          retry = retry,
        }
        table.insert(index_policy['policy']['states'][state_id]['actions'], change_replicas)
      end
    end
    -- opensearch state delete
    if settings['index_policy']['delete']['enabled'] then
      local prev_state_id = state_id
      state_id = state_id + 1
      index_policy['policy']['states'][prev_state_id]['transitions'] = {
        {
          state_name = 'delete',
          conditions = {
            min_index_age = settings['index_policy']['delete']['after']
          },
        },
      }
      local delete_obj = {
        name = 'delete',
        actions = {
          {
            delete = '{empty_object}',
            retry = retry,
          },
        },
        transitions = {},
      }
      table.insert(index_policy['policy']['states'], delete_obj)
    end
  end

  -- finish rendering index policy, will now get current version and update it if neeeded
  index_policy_json = ucl.to_format(index_policy, 'json-compact'):gsub('"{empty_object}"', '{}')
  get_index_policy(cfg, ev_base, upstream, host, policy_url, index_policy_json)
end

local function configure_index_template(cfg, ev_base)
  local upstream = settings.upstream:get_upstream_round_robin()
  local host = upstream:get_name():gsub(":[1-9][0-9]*$", "")
  local ip_addr = upstream:get_addr():to_string(true)
  local template_url = connect_prefix .. ip_addr .. '/_index_template/' .. settings['index_template']['name']

  -- common data types
  local t_boolean_nil_true = { type = 'boolean', null_value = true }
  local t_boolean_nil_false = { type = 'boolean', null_value = false }
  local t_date = { type = 'date' }
  local t_long = { type = 'long', null_value = 0 }
  local t_float = { type = 'float', null_value = 0 }
  local t_double = { type = 'double', null_value = 0 }
  local t_ip = { type = 'ip', null_value = '::' }
  local t_geo_point = { type = 'geo_point' }
  local t_keyword = { type = 'keyword', null_value = settings['index_template']['empty_value'] }
  local t_text = { type = 'text' }
  local t_text_with_keyword = {
    type = 'text',
    fields = {
      keyword = {
        type = 'keyword',
        ignore_above = settings['index_template']['dynamic_keyword_ignore_above'],
      },
    },
  }

  -- common objects types
  local geoip_obj = {
    dynamic = false,
    type = 'object',
    properties = {
      continent_name = t_text,
      region_iso_code = t_keyword,
      city_name = t_text,
      country_iso_code = t_keyword,
      country_name = t_text,
      location = t_geo_point,
      region_name = t_text,
    },
  }
  local asn_obj = {
    dynamic = false,
    type = 'object',
    properties = {
      country = t_keyword,
      asn = t_long,
      ipnet = t_keyword, -- do not use ip_range type, it's not usable for search
    },
  }
  local symbols_obj = {
    dynamic = false,
    type = 'object',
    properties = {
      name = t_keyword,
      group = t_keyword,
      options = t_text_with_keyword,
      score = t_double,
      weight = t_double,
    },
  }
  if settings['index_template']['symbols_nested'] then
    symbols_obj['type'] = 'nested'
  end

  -- dynamic templates
  local dynamic_templates_obj = {}
  local dynamic_strings = {
    strings = {
      match_mapping_type = 'string',
      mapping = {
        type = 'text',
        fields = {
          keyword = {
            type = 'keyword',
            ignore_above = settings['index_template']['dynamic_keyword_ignore_above'],
          },
        },
      },
    },
  }
  table.insert(dynamic_templates_obj, dynamic_strings)

  -- index template rendering
  local index_template = {
    index_patterns = { settings['index_template']['name'] .. '-*', },
    priority = settings['index_template']['priority'],
    template = {
      settings = {
        index = {
          number_of_shards = settings['index_template']['shards_count'],
          number_of_replicas = settings['index_template']['replicas_count'],
          refresh_interval = settings['index_template']['refresh_interval'] .. 's',
        },
      },
      mappings = {
        dynamic = false,
        dynamic_templates = dynamic_templates_obj,
        properties = {
          ['@timestamp'] = t_date,
          rspamd_meta = {
            dynamic = true,
            type = 'object',
            properties = {
              rspamd_server = t_keyword,
              action = t_keyword,
              score = t_double,
              symbols = symbols_obj,
              user = t_keyword,
              direction = t_keyword,
              qid = t_keyword,
              helo = t_text_with_keyword,
              hostname = t_text_with_keyword,
              ip = t_ip,
              is_local = t_boolean_nil_false,
              sender_ip = t_ip,
              message_id = t_text_with_keyword,
              rcpt = t_text_with_keyword,
              from_domain = t_keyword,
              from_user = t_keyword,
              mime_from_domain = t_keyword,
              mime_from_user = t_keyword,
              settings_id = t_keyword,
              asn = asn_obj,
              scan_time = t_float,
              language = t_text,
              non_en = t_boolean_nil_true,
              fuzzy_hashes = t_text,
              received_delay = t_long,
            },
          },
        },
      },
    },
  }

  -- render index lifecycle policy
  if detected_distro['name'] == 'elastic' and settings['index_policy']['enabled'] then
    index_template['template']['settings']['index']['lifecycle'] = {
      name = settings['index_policy']['name']
    }
  end

  -- render geoip mappings
  if settings['geoip']['enabled'] then
    index_template['template']['mappings']['properties']['rspamd_meta']['properties']['geoip'] = geoip_obj
    index_template['template']['mappings']['properties']['rspamd_meta']['properties']['sender_geoip'] = geoip_obj
  end

  -- render collect_headers and extra_collect_headers mappings
  for _, header in ipairs(settings['collect_headers']) do
    local header_name = get_header_name(header)
    if not index_template['template']['mappings']['properties']['rspamd_meta']['properties'][header_name] then
      index_template['template']['mappings']['properties']['rspamd_meta']['properties'][header_name] = t_text_with_keyword
    end
  end
  for _, header in ipairs(settings['extra_collect_headers']) do
    local header_name = get_header_name(header)
    if not index_template['template']['mappings']['properties']['rspamd_meta']['properties'][header_name] then
      index_template['template']['mappings']['properties']['rspamd_meta']['properties'][header_name] = t_text_with_keyword
    end
  end

  local function http_callback(err, code, body, _)
    if err then
      rspamd_logger.errx(rspamd_config, 'cannot connect to elastic (%s): %s', template_url, err)
      upstream:fail()
    elseif code == 200 then
      rspamd_logger.infox(rspamd_config, 'successfully updated elastic index template: %s', body)
      states['index_template']['configured'] = true
      upstream:ok()
    else
      rspamd_logger.errx(rspamd_config, 'cannot configure elastic index template (%s), status code: %s, response: %s',
        template_url, code, body)
      upstream:fail()
      handle_error('configure', 'index_template', settings['limits']['max_fail'])
    end
  end

  rspamd_http.request({
    url = template_url,
    ev_base = ev_base,
    config = cfg,
    body = ucl.to_format(index_template, 'json-compact'),
    headers = {
      ['Host'] = host,
      ['Content-Type'] = 'application/json',
    },
    method = 'put',
    callback = http_callback,
    gzip = settings.use_gzip,
    keepalive = settings.use_keepalive,
    no_ssl_verify = settings.no_ssl_verify,
    user = settings.user,
    password = settings.password,
    timeout = settings.timeout,
  })
end

local function verify_distro(manual)
  local detected_distro_name = detected_distro['name']
  local detected_distro_version = detected_distro['version']
  local valid = true
  local valid_unknown = false

  -- check that detected_distro_name is valid
  if not detected_distro_name then
    rspamd_logger.errx(rspamd_config, 'failed to detect elastic distribution')
    valid = false
  elseif not supported_distro[detected_distro_name] then
    rspamd_logger.errx(rspamd_config, 'unsupported elastic distribution: %s', detected_distro_name)
    valid = false
  else
    local supported_distro_info = supported_distro[detected_distro_name]
    -- check that detected_distro_version is valid
    if not detected_distro_version or type(detected_distro_version) ~= 'string' then
      rspamd_logger.errx(rspamd_config, 'elastic version should be a string, but we received: %s', type(detected_distro_version))
      valid = false
    elseif detected_distro_version == '' then
      rspamd_logger.errx(rspamd_config, 'unsupported elastic version: empty string')
      valid = false
    else
      -- compare versions using compare_versions
      local cmp_from = compare_versions(detected_distro_version, supported_distro_info['from'])
      if cmp_from == -1 then
        rspamd_logger.errx(rspamd_config, 'unsupported elastic version: %s, minimal supported version of %s is %s',
          detected_distro_version, detected_distro_name, supported_distro_info['from'])
        valid = false
      else
        local cmp_till = compare_versions(detected_distro_version, supported_distro_info['till'])
        if (cmp_till >= 0) and not supported_distro_info['till_unknown'] then
          rspamd_logger.errx(rspamd_config, 'unsupported elastic version: %s, maximum supported version of %s is less than %s',
            detected_distro_version, detected_distro_name, supported_distro_info['till'])
          valid = false
        elseif (cmp_till >= 0) and supported_distro_info['till_unknown'] then
          rspamd_logger.warnx(rspamd_config,
            'compatibility of elastic version: %s is unknown, maximum known supported version of %s is less than %s, use at your own risk',
            detected_distro_version, detected_distro_name, supported_distro_info['till'])
          valid_unknown = true
        end
      end
    end
  end

  if valid_unknown then
    detected_distro['supported'] = true
  else
    if valid and manual then
      rspamd_logger.infox(
        rspamd_config, 'assuming elastic distro: %s, version: %s', detected_distro_name, detected_distro_version)
      detected_distro['supported'] = true
    elseif valid and not manual then
      rspamd_logger.infox(rspamd_config, 'successfully connected to elastic distro: %s, version: %s',
        detected_distro_name, detected_distro_version)
      detected_distro['supported'] = true
    else
      handle_error('configure','distro',settings['version']['autodetect_max_fail'])
    end
  end
end

local function configure_distro(cfg, ev_base)
  if not settings['version']['autodetect_enabled'] then
    detected_distro['name'] = settings['version']['override']['name']
    detected_distro['version'] = settings['version']['override']['version']
    rspamd_logger.infox(rspamd_config, 'automatic detection of elastic distro and version is disabled, taking configuration from settings')
    verify_distro(true)
  end

  local upstream = settings.upstream:get_upstream_round_robin()
  local host = upstream:get_name():gsub(":[1-9][0-9]*$", "")
  local ip_addr = upstream:get_addr():to_string(true)
  local root_url = connect_prefix .. ip_addr .. '/'
  local function http_callback(err, code, body, _)
    if err then
      rspamd_logger.errx(rspamd_config, 'cannot connect to elastic (%s): %s', root_url, err)
      upstream:fail()
    elseif code ~= 200 then
      rspamd_logger.errx(rspamd_config, 'cannot connect to elastic (%s), status code: %s, response: %s', root_url, code, body)
      upstream:fail()
    else
      local parser = ucl.parser()
      local res, ucl_err = parser:parse_string(body)
      if not res then
        rspamd_logger.errx(rspamd_config, 'failed to parse reply from elastic (%s): %s', root_url, ucl_err)
        upstream:fail()
      else
        local obj = parser:get_object()
        if obj['tagline'] == "The OpenSearch Project: https://opensearch.org/" then
            detected_distro['name'] = 'opensearch'
        end
        if obj['tagline'] == "You Know, for Search" then
            detected_distro['name'] = 'elastic'
        end
        if obj['version'] then
          if obj['version']['number'] then
            detected_distro['version'] = obj['version']['number']
          end
          if not detected_distro['name'] and obj['version']['distribution'] then
            detected_distro['name'] = obj['version']['distribution']
          end
        end
        verify_distro()
        if detected_distro['supported'] then
          upstream:ok()
        end
      end
    end
  end

  if settings['version']['autodetect_enabled'] then
    rspamd_http.request({
      url = root_url,
      ev_base = ev_base,
      config = cfg,
      headers = {
        ['Host'] = host,
        ['Content-Type'] = 'application/json',
      },
      method = 'get',
      callback = http_callback,
      gzip = settings.use_gzip,
      keepalive = settings.use_keepalive,
      no_ssl_verify = settings.no_ssl_verify,
      user = settings.user,
      password = settings.password,
      timeout = settings.timeout,
    })
  end
end

local opts = rspamd_config:get_all_opt('elastic')

if opts then
  for k,v in pairs(opts) do
    settings[k] = v
  end

  if not settings['enabled'] then
    rspamd_logger.infox(rspamd_config, 'module disabled in config')
    lua_util.disable_module(N, "config")
  end

  if not settings['server'] and not settings['servers'] then
    rspamd_logger.infox(rspamd_config, 'no servers are specified, disabling module')
    lua_util.disable_module(N, "config")
  else
    if settings.use_https then
      connect_prefix = 'https://'
    end

    settings.upstream = upstream_list.create(rspamd_config, settings['server'] or settings['servers'], 9200)

    if not settings.upstream then
      rspamd_logger.errx(rspamd_config, 'cannot parse elastic address: %s', settings['server'] or settings['servers'])
      lua_util.disable_module(N, "config")
      return
    end

    rspamd_config:register_symbol({
      name = 'ELASTIC_COLLECT',
      type = 'idempotent',
      callback = elastic_collect,
      flags = 'empty,explicit_disable,ignore_passthrough',
      augmentations = { string.format("timeout=%f", settings.timeout) },
    })

    -- send tail of data if worker going to stop
    rspamd_config:register_finish_script(function(task)
      local nlogs_total = buffer['logs']:length()
      if nlogs_total > 0 then
        rspamd_logger.debugm(N, task, 'flushing buffer on shutdown, buffer size: %s', nlogs_total)
        elastic_send_data(true, task)
      end
    end)

    rspamd_config:add_on_load(function(cfg, ev_base, worker)
      if worker:is_scanner() then
        rspamd_config:add_periodic(ev_base, settings.periodic_interval, function(p_cfg, p_ev_base)
          if not detected_distro['supported'] then
            if states['distro']['configured'] then
              return false -- stop running periodic job
            else
              configure_distro(p_cfg, p_ev_base)
              return true -- continue running periodic job
            end
          end
        end)
        -- send data periodically if any of limits reached
        rspamd_config:add_periodic(ev_base, settings.periodic_interval, function(p_cfg, p_ev_base)
          if detected_distro['supported'] then
            periodic_send_data(p_cfg, p_ev_base)
          end
          return true
        end)
      end
      if worker:is_primary_controller() then
        rspamd_config:add_periodic(ev_base, settings.periodic_interval, function(p_cfg, p_ev_base)
          if not settings['index_template']['managed'] then
            return false
          elseif not detected_distro['supported'] then
            return true
          else
            if states['index_template']['configured'] then
              return false
            else
              configure_index_template(p_cfg, p_ev_base)
              return true
            end
          end
        end)
        rspamd_config:add_periodic(ev_base, settings.periodic_interval, function(p_cfg, p_ev_base)
          if not settings['index_policy']['enabled'] or not settings['index_policy']['managed'] then
            return false
          elseif not detected_distro['supported'] then
            return true
          else
            if states['index_policy']['configured'] then
              return false
            else
              configure_index_policy(p_cfg, p_ev_base)
              return true
            end
          end
        end)
        rspamd_config:add_periodic(ev_base, settings.periodic_interval, function(p_cfg, p_ev_base)
          if not settings['geoip']['enabled'] or not settings['geoip']['managed'] then
            return false
          elseif not detected_distro['supported'] then
            return true
          else
            if states['geoip_pipeline']['configured'] then
              return false
            else
              configure_geoip_pipeline(p_cfg, p_ev_base)
              return true
            end
          end
        end)
      end
    end)
  end
end
