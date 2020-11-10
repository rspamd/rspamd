--[[
Copyright (c) 2017, Veselin Iordanov
Copyright (c) 2018, Vsevolod Stakhov <vsevolod@highsecure.ru>

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
local util = require "rspamd_util"
local ucl = require "ucl"
local rspamd_redis = require "lua_redis"
local upstream_list = require "rspamd_upstream_list"
local lua_settings = require "lua_settings"

if confighelp then
  return
end

local rows = {}
local nrows = 0
local failed_sends = 0
local elastic_template
local redis_params
local N = "elastic"
local E = {}
local HOSTNAME = util.get_hostname()
local connect_prefix = 'http://'
local enabled = true
local ingest_geoip_type = 'plugins'
local settings = {
  limit = 500,
  index_pattern = 'rspamd-%Y.%m.%d',
  template_file = rspamd_paths['SHAREDIR'] .. '/elastic/rspamd_template.json',
  kibana_file = rspamd_paths['SHAREDIR'] ..'/elastic/kibana.json',
  key_prefix = 'elastic-',
  expire = 3600,
  timeout = 5.0,
  failover = false,
  import_kibana = false,
  use_https = false,
  use_gzip = true,
  allow_local = false,
  user = nil,
  password = nil,
  no_ssl_verify = false,
  max_fail = 3,
  ingest_module = false,
}

local function read_file(path)
    local file = io.open(path, "rb")
    if not file then return nil end
    local content = file:read "*a"
    file:close()
    return content
end

local function elastic_send_data(task)
  local es_index = os.date(settings['index_pattern'])
  local tbl = {}
  for _,value in pairs(rows) do
    table.insert(tbl, '{ "index" : { "_index" : "'..es_index..
        '", "_type" : "_doc" ,"pipeline": "rspamd-geoip"} }')
    table.insert(tbl, ucl.to_format(value, 'json-compact'))
  end

  table.insert(tbl, '') -- For last \n

  local upstream = settings.upstream:get_upstream_round_robin()
  local ip_addr = upstream:get_addr():to_string(true)

  local push_url = connect_prefix .. ip_addr .. '/'..es_index..'/_bulk'
  local bulk_json = table.concat(tbl, "\n")

  local function http_callback(err, code, _, _)
    if err then
      rspamd_logger.infox(task, "cannot push data to elastic backend (%s): %s; failed attempts: %s/%s",
          push_url, err, failed_sends, settings.max_fail)
    else
      if code ~= 200 then
        rspamd_logger.infox(task,
            "cannot push data to elastic backend (%s): wrong http code %s (%s); failed attempts: %s/%s",
            push_url, err, code, failed_sends, settings.max_fail)
      else
        lua_util.debugm(N, task, "successfully sent %s (%s bytes) rows to ES",
            nrows, #bulk_json)
      end
    end
  end

  return rspamd_http.request({
    url = push_url,
    headers = {
      ['Content-Type'] = 'application/x-ndjson',
    },
    body = bulk_json,
    callback = http_callback,
    task = task,
    method = 'post',
    gzip = settings.use_gzip,
    no_ssl_verify = settings.no_ssl_verify,
    user = settings.user,
    password = settings.password,
    timeout = settings.timeout,
  })
end

local function get_general_metadata(task)
  local r = {}
  local ip_addr = task:get_ip()

  r.webmail = false

  if ip_addr  and ip_addr:is_valid() then
    r.is_local = ip_addr:is_local()
    local origin = task:get_header('X-Originating-IP')
    if origin then
      origin = string.sub(origin, 2, -2)
      local rspamd_ip = require "rspamd_ip"
      local test = rspamd_ip.from_string(origin)

      if test and test:is_valid() then
        r.webmail = true
        r.ip = origin
      else
        r.ip = tostring(ip_addr)
      end
    else
      r.ip = tostring(ip_addr)
    end
  else
    r.ip = '127.0.0.1'
  end

  r.direction = "Inbound"
  r.user = task:get_user() or 'unknown'
  r.qid = task:get_queue_id() or 'unknown'
  r.action = task:get_metric_action('default')
  r.rspamd_server = HOSTNAME
  if r.user ~= 'unknown' then
      r.direction = "Outbound"
  end
  local s = task:get_metric_score('default')[1]
  r.score =  s

  local rcpt = task:get_recipients('smtp')
  if rcpt then
    local l = {}
    for _, a in ipairs(rcpt) do
      table.insert(l, a['addr'])
    end
    r.rcpt = l
  else
    r.rcpt = 'unknown'
  end

  local from = task:get_from{'smtp', 'orig'}
  if ((from or E)[1] or E).addr then
    r.from = from[1].addr
  else
    r.from = 'unknown'
  end

  local mime_from = task:get_from{'mime', 'orig'}
  if ((mime_from or E)[1] or E).addr then
    r.mime_from = mime_from[1].addr
  else
    r.mime_from = 'unknown'
  end

  local syminf = task:get_symbols_all()
  r.symbols = syminf
  r.asn = {}
  local pool = task:get_mempool()
  r.asn.country = pool:get_variable("country") or 'unknown'
  r.asn.asn   = pool:get_variable("asn") or 0
  r.asn.ipnet = pool:get_variable("ipnet") or 'unknown'

  local function process_header(name)
    local hdr = task:get_header_full(name)
    if hdr then
      local l = {}
      for _, h in ipairs(hdr) do
        table.insert(l, h.decoded)
      end
      return l
    else
      return 'unknown'
    end
  end

  r.header_from = process_header('from')
  r.header_to = process_header('to')
  r.header_subject = process_header('subject')
  r.header_date = process_header('date')
  r.message_id = task:get_message_id()
  local hname = task:get_hostname() or 'unknown'
  r.hostname = hname

  local settings_id = task:get_settings_id()

  if settings_id then
    -- Convert to string
    settings_id = lua_settings.settings_by_id(settings_id)

    if settings_id then
      settings_id = settings_id.name
    end
  end

  if not settings_id then
    settings_id = ''
  end

  r.settings_id = settings_id

  local scan_real = task:get_scan_time()
  scan_real = math.floor(scan_real * 1000)
  if scan_real < 0 then
    rspamd_logger.messagex(task,
        'clock skew detected for message: %s ms real scan time (reset to 0)',
        scan_real)
    scan_real = 0
  end

  r.scan_time = scan_real

  return r
end

local function elastic_collect(task)
  if not enabled then return end
  if task:has_flag('skip') then return end
  if not settings.allow_local and lua_util.is_rspamc_or_controller(task) then return end

  local row = {['rspamd_meta'] = get_general_metadata(task),
    ['@timestamp'] = tostring(util.get_time() * 1000)}
  table.insert(rows, row)
  nrows = nrows + 1
  if nrows > settings['limit'] then
    lua_util.debugm(N, task, 'send elastic search rows: %s', nrows)
    if elastic_send_data(task) then
      nrows = 0
      rows = {}
      failed_sends = 0;
    else
      failed_sends = failed_sends + 1

      if failed_sends > settings.max_fail then
        rspamd_logger.errx(task, 'cannot send %s rows to ES %s times, stop trying',
            nrows, failed_sends)
        nrows = 0
        rows = {}
        failed_sends = 0;
      end
    end
  end
end


local opts = rspamd_config:get_all_opt('elastic')

local function check_elastic_server(cfg, ev_base, _)
  local upstream = settings.upstream:get_upstream_round_robin()
  local ip_addr = upstream:get_addr():to_string(true)
  local plugins_url = connect_prefix .. ip_addr .. '/_nodes/' .. ingest_geoip_type
  local function http_callback(err, code, body, _)
    if code == 200 then
      local parser = ucl.parser()
      local res,ucl_err = parser:parse_string(body)
      if not res then
        rspamd_logger.infox(rspamd_config, 'failed to parse reply from %s: %s',
            plugins_url, ucl_err)
        enabled = false;
        return
      end
      local obj = parser:get_object()
      for node,value in pairs(obj['nodes']) do
        local plugin_found = false
        for _,plugin in pairs(value['plugins']) do
          if plugin['name'] == 'ingest-geoip' then
            plugin_found = true
            lua_util.debugm(N, "ingest-geoip plugin has been found")
          end
        end
        if not plugin_found then
          rspamd_logger.infox(rspamd_config,
              'Unable to find ingest-geoip on %1 node, disabling module', node)
          enabled = false
          return
        end
      end
    else
      rspamd_logger.errx('cannot get plugins from %s: %s(%s) (%s)', plugins_url,
          err, code, body)
      enabled = false
    end
  end
  rspamd_http.request({
    url = plugins_url,
    ev_base = ev_base,
    config = cfg,
    method = 'get',
    callback = http_callback,
    no_ssl_verify = settings.no_ssl_verify,
    user = settings.user,
    password = settings.password,
    timeout = settings.timeout,
  })
end

-- import ingest pipeline and kibana dashboard/visualization
local function initial_setup(cfg, ev_base, worker)
  if not worker:is_primary_controller() then return end

  local upstream = settings.upstream:get_upstream_round_robin()
  local ip_addr = upstream:get_addr():to_string(true)

  local function push_kibana_template()
    -- add kibana dashboard and visualizations
    if settings['import_kibana'] then
      local kibana_mappings = read_file(settings['kibana_file'])
      if kibana_mappings then
        local parser = ucl.parser()
        local res,parser_err = parser:parse_string(kibana_mappings)
        if not res then
          rspamd_logger.infox(rspamd_config, 'kibana template cannot be parsed: %s',
              parser_err)
          enabled = false

          return
        end
        local obj = parser:get_object()
        local tbl = {}
        for _,item in ipairs(obj) do
          table.insert(tbl, '{ "index" : { "_index" : ".kibana", "_type" : "doc" ,"_id": "'..
              item['_type'] .. ':' .. item["_id"]..'"} }')
          table.insert(tbl, ucl.to_format(item['_source'], 'json-compact'))
        end
        table.insert(tbl, '') -- For last \n

        local kibana_url = connect_prefix .. ip_addr ..'/.kibana/_bulk'
        local function kibana_template_callback(err, code, body, _)
          if code ~= 200 then
            rspamd_logger.errx('cannot put template to %s: %s(%s) (%s)', kibana_url,
                err, code, body)
            enabled = false
          else
            lua_util.debugm(N, 'pushed kibana template: %s', body)
          end
        end

        rspamd_http.request({
          url = kibana_url,
          ev_base = ev_base,
          config = cfg,
          headers = {
            ['Content-Type'] = 'application/x-ndjson',
          },
          body = table.concat(tbl, "\n"),
          method = 'post',
          gzip = settings.use_gzip,
          callback = kibana_template_callback,
          no_ssl_verify = settings.no_ssl_verify,
          user = settings.user,
          password = settings.password,
          timeout = settings.timeout,
        })
      else
        rspamd_logger.infox(rspamd_config, 'kibana template file %s not found', settings['kibana_file'])
      end
    end
  end

  if enabled then
    -- create ingest pipeline
    local geoip_url = connect_prefix .. ip_addr ..'/_ingest/pipeline/rspamd-geoip'
    local function geoip_cb(err, code, body, _)
      if code ~= 200 then
        rspamd_logger.errx('cannot get data from %s: %s(%s) (%s)',
            geoip_url, err, code, body)
        enabled = false
      end
    end
    local template = {
      description = "Add geoip info for rspamd",
      processors = {
        {
          geoip = {
            field = "rspamd_meta.ip",
            target_field = "rspamd_meta.geoip"
          }
        }
      }
    }
    rspamd_http.request({
      url = geoip_url,
      ev_base = ev_base,
      config = cfg,
      callback = geoip_cb,
      headers = {
        ['Content-Type'] = 'application/json',
      },
      gzip = settings.use_gzip,
      body = ucl.to_format(template, 'json-compact'),
      method = 'put',
      no_ssl_verify = settings.no_ssl_verify,
      user = settings.user,
      password = settings.password,
      timeout = settings.timeout,
    })
    -- create template mappings if not exist
    local template_url = connect_prefix .. ip_addr ..'/_template/rspamd'
    local function http_template_put_callback(err, code, body, _)
      if code ~= 200 then
        rspamd_logger.errx('cannot put template to %s: %s(%s) (%s)',
            template_url, err, code, body)
        enabled = false
      else
        lua_util.debugm(N, 'pushed rspamd template: %s', body)
        push_kibana_template()
      end
    end
    local function http_template_exist_callback(_, code, _, _)
      if code ~= 200 then
        rspamd_http.request({
          url = template_url,
          ev_base = ev_base,
          config = cfg,
          body = elastic_template,
          method = 'put',
          headers = {
            ['Content-Type'] = 'application/json',
          },
          gzip = settings.use_gzip,
          callback = http_template_put_callback,
          no_ssl_verify = settings.no_ssl_verify,
          user = settings.user,
          password = settings.password,
          timeout = settings.timeout,
        })
      else
        push_kibana_template()
      end
    end

    rspamd_http.request({
      url = template_url,
      ev_base = ev_base,
      config = cfg,
      method = 'head',
      callback = http_template_exist_callback,
      no_ssl_verify = settings.no_ssl_verify,
      user = settings.user,
      password = settings.password,
      timeout = settings.timeout,
    })

  end
end

redis_params = rspamd_redis.parse_redis_server('elastic')

if redis_params and opts then
  for k,v in pairs(opts) do
    settings[k] = v
  end

  if not settings['server'] and not settings['servers'] then
    rspamd_logger.infox(rspamd_config, 'no servers are specified, disabling module')
    lua_util.disable_module(N, "config")
  else
    if settings.use_https then
      connect_prefix = 'https://'
    end

    if settings.ingest_module then
      ingest_geoip_type = 'modules'
    end

    settings.upstream = upstream_list.create(rspamd_config,
      settings['server'] or settings['servers'], 9200)

    if not settings.upstream then
      rspamd_logger.errx('cannot parse elastic address: %s',
        settings['server'] or settings['servers'])
      lua_util.disable_module(N, "config")
      return
    end
    if not settings['template_file'] then
      rspamd_logger.infox(rspamd_config, 'elastic template_file is required, disabling module')
      lua_util.disable_module(N, "config")
      return
    end

    elastic_template = read_file(settings['template_file']);
    if not elastic_template then
      rspamd_logger.infox(rspamd_config, 'elastic unable to read %s, disabling module',
        settings['template_file'])
      lua_util.disable_module(N, "config")
      return
    end

    rspamd_config:register_symbol({
      name = 'ELASTIC_COLLECT',
      type = 'idempotent',
      callback = elastic_collect,
      priority = 10,
      flags = 'empty,explicit_disable,ignore_passthrough',
    })

    rspamd_config:add_on_load(function(cfg, ev_base,worker)
      if worker:is_scanner() then
        check_elastic_server(cfg, ev_base, worker) -- check for elasticsearch requirements
        initial_setup(cfg, ev_base, worker) -- import mappings pipeline and visualizations
      end
    end)
  end

end
