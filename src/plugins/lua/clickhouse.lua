--[[
Copyright (c) 2016, Vsevolod Stakhov <vsevolod@highsecure.ru>

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
local rspamd_lua_utils = require "lua_util"
local upstream_list = require "rspamd_upstream_list"
local lua_util = require "lua_util"
local lua_clickhouse = require "lua_clickhouse"
local fun = require "fun"

local N = "clickhouse"

if confighelp then
  return
end

local data_rows = {}
local custom_rows = {}
local nrows = 0
local schema_version = 2 -- Current schema version

local settings = {
  limit = 1000,
  timeout = 5.0,
  bayes_spam_symbols = {'BAYES_SPAM'},
  bayes_ham_symbols = {'BAYES_HAM'},
  fann_symbols = {'FANN_SCORE'},
  fuzzy_symbols = {'FUZZY_DENIED'},
  whitelist_symbols = {'WHITELIST_DKIM', 'WHITELIST_SPF_DKIM', 'WHITELIST_DMARC'},
  dkim_allow_symbols = {'R_DKIM_ALLOW'},
  dkim_reject_symbols = {'R_DKIM_REJECT'},
  dmarc_allow_symbols = {'DMARC_POLICY_ALLOW'},
  dmarc_reject_symbols = {'DMARC_POLICY_REJECT', 'DMARC_POLICY_QUARANTINE'},
  stop_symbols = {},
  ipmask = 19,
  ipmask6 = 48,
  full_urls = false,
  from_tables = nil,
  enable_symbols = false,
  database = 'default',
  use_https = false,
  use_gzip = true,
  allow_local = false,
  user = nil,
  password = nil,
  no_ssl_verify = false,
  custom_rules = {},
  retention = {
    enable = false,
    method = 'detach',
    period_months = 3,
    run_every = '7d',
  }
}

--- @language SQL
local clickhouse_schema = {[[
CREATE TABLE rspamd
(
    Date Date,
    TS DateTime,
    From String,
    MimeFrom String,
    IP String,
    Score Float64,
    NRcpt UInt8,
    Size UInt32,
    IsWhitelist Enum8('blacklist' = 0, 'whitelist' = 1, 'unknown' = 2) DEFAULT CAST('unknown' AS Enum8('blacklist' = 0, 'whitelist' = 1, 'unknown' = 2)),
    IsBayes Enum8('ham' = 0, 'spam' = 1, 'unknown' = 2) DEFAULT CAST('unknown' AS Enum8('ham' = 0, 'spam' = 1, 'unknown' = 2)),
    IsFuzzy Enum8('whitelist' = 0, 'deny' = 1, 'unknown' = 2) DEFAULT CAST('unknown' AS Enum8('whitelist' = 0, 'deny' = 1, 'unknown' = 2)),
    IsFann Enum8('ham' = 0, 'spam' = 1, 'unknown' = 2) DEFAULT CAST('unknown' AS Enum8('ham' = 0, 'spam' = 1, 'unknown' = 2)),
    IsDkim Enum8('reject' = 0, 'allow' = 1, 'unknown' = 2) DEFAULT CAST('unknown' AS Enum8('reject' = 0, 'allow' = 1, 'unknown' = 2)),
    IsDmarc Enum8('reject' = 0, 'allow' = 1, 'unknown' = 2) DEFAULT CAST('unknown' AS Enum8('reject' = 0, 'allow' = 1, 'unknown' = 2)),
    NUrls Int32,
    Action Enum8('reject' = 0, 'rewrite subject' = 1, 'add header' = 2, 'greylist' = 3, 'no action' = 4, 'soft reject' = 5) DEFAULT CAST('no action' AS Enum8('reject' = 0, 'rewrite subject' = 1, 'add header' = 2, 'greylist' = 3, 'no action' = 4, 'soft reject' = 5)),
    FromUser String,
    MimeUser String,
    RcptUser String,
    RcptDomain String,
    ListId String,
    `Attachments.FileName` Array(String),
    `Attachments.ContentType` Array(String),
    `Attachments.Length` Array(UInt32),
    `Attachments.Digest` Array(FixedString(16)),
    `Urls.Tld` Array(String),
    `Urls.Url` Array(String),
    Emails Array(String),
    ASN String,
    Country FixedString(2),
    IPNet String,
    `Symbols.Names` Array(String),
    `Symbols.Scores` Array(Float64),
    `Symbols.Options` Array(String),
    Digest FixedString(32)
) ENGINE = MergeTree(Date, (TS, From), 8192)
]],
[[CREATE TABLE rspamd_version ( Version UInt32) ENGINE = TinyLog]],
[[INSERT INTO rspamd_version (Version) Values (2)]],
}

-- This describes SQL queries to migrate between versions
local migrations = {
  [1] = {
    -- Move to a wide fat table
    [[ALTER TABLE rspamd
      ADD COLUMN `Attachments.FileName` Array(String) AFTER ListId,
      ADD COLUMN `Attachments.ContentType` Array(String) AFTER `Attachments.FileName`,
      ADD COLUMN `Attachments.Length` Array(UInt32) AFTER `Attachments.ContentType`,
      ADD COLUMN `Attachments.Digest` Array(FixedString(16)) AFTER `Attachments.Length`,
      ADD COLUMN `Urls.Tld` Array(String) AFTER `Attachments.Digest`,
      ADD COLUMN `Urls.Url` Array(String) AFTER `Urls.Tld`,
      ADD COLUMN Emails Array(String) AFTER `Urls.Url`,
      ADD COLUMN ASN String AFTER Emails,
      ADD COLUMN Country FixedString(2) AFTER ASN,
      ADD COLUMN IPNet String AFTER Country,
      ADD COLUMN `Symbols.Names` Array(String) AFTER IPNet,
      ADD COLUMN `Symbols.Scores` Array(Float64) AFTER `Symbols.Names`,
      ADD COLUMN `Symbols.Options` Array(String) AFTER `Symbols.Scores`]],
    -- Add explicit version
    [[CREATE TABLE rspamd_version ( Version UInt32) ENGINE = TinyLog]],
    [[INSERT INTO rspamd_version (Version) Values (2)]],
  }
}


local function clickhouse_main_row(res)
  local fields = {
    'Date',
    'TS',
    'From',
    'MimeFrom',
    'IP',
    'Score',
    'NRcpt',
    'Size',
    'IsWhitelist',
    'IsBayes',
    'IsFuzzy',
    'IsFann',
    'IsDkim',
    'IsDmarc',
    'NUrls',
    'Action',
    'FromUser',
    'MimeUser',
    'RcptUser',
    'RcptDomain',
    'ListId',
    'Digest'
  }

  for _,v in ipairs(fields) do table.insert(res, v) end
end

local function clickhouse_attachments_row(res)
  local fields = {
    'Attachments.FileName',
    'Attachments.ContentType',
    'Attachments.Length',
    'Attachments.Digest',
  }

  for _,v in ipairs(fields) do table.insert(res, v) end
end

local function clickhouse_urls_row(res)
  local fields = {
    'Urls.Tld',
    'Urls.Url',
  }
  for _,v in ipairs(fields) do table.insert(res, v) end
end

local function clickhouse_emails_row(res)
  local fields = {
    'Emails',
  }
  for _,v in ipairs(fields) do table.insert(res, v) end
end

local function clickhouse_symbols_row(res)
  local fields = {
    'Symbols.Names',
    'Symbols.Scores',
    'Symbols.Options',
  }
  for _,v in ipairs(fields) do table.insert(res, v) end
end

local function clickhouse_asn_row(res)
  local fields = {
    'ASN',
    'Country',
    'IPNet',
  }
  for _,v in ipairs(fields) do table.insert(res, v) end
end

local function today(ts)
  return os.date('%Y-%m-%d', ts)
end

local function clickhouse_check_symbol(task, symbols, need_score)
  for _,s in ipairs(symbols) do
    if task:has_symbol(s) then
      if need_score then
        local sym = task:get_symbol(s)[1]
        return sym['score']
      else
        return true
      end
    end
  end

  return false
end

local function clickhouse_send_data(task)
  local upstream = settings.upstream:get_upstream_round_robin()
  local ip_addr = upstream:get_addr():to_string(true)

  local function gen_success_cb(what, how_many)
    return function (_, _)
      rspamd_logger.infox(task, "sent %s rows of %s to clickhouse server %s",
          how_many, what, ip_addr)
      upstream:ok()
    end
  end

  local function gen_fail_cb(what, how_many)
    return function (_, err)
      rspamd_logger.errx(task, "cannot send %s rows of %s data to clickhouse server %s: %s",
          how_many, what, ip_addr, err)
      upstream:fail()
    end
  end

  local function send_data(what, tbl, query)
    local ch_params = {
      task = task,
    }

    local ret = lua_clickhouse.insert(upstream, settings, ch_params,
        query, tbl,
        gen_success_cb(what, #tbl),
        gen_fail_cb(what, #tbl))
    if not ret then
      rspamd_logger.errx(task, "cannot send %s rows of %s data to clickhouse server %s: %s",
          #tbl, what, ip_addr, 'cannot make HTTP request')
    end
  end

  local fields = {}
  clickhouse_main_row(fields)
  clickhouse_attachments_row(fields)
  clickhouse_urls_row(fields)
  clickhouse_emails_row(fields)
  clickhouse_asn_row(fields)

  if settings.enable_symbols then
    clickhouse_symbols_row(fields)
  end

  send_data('generic data', data_rows,
      string.format('INSERT INTO rspamd (%s)', table.concat(fields, ',')))

  for k,crows in pairs(custom_rows) do
    if #crows > 1 then
      send_data('custom data ('..k..')', settings.custom_rules[k].first_row(),
          crows)
    end
  end
end

local function clickhouse_collect(task)
  if task:has_flag('skip') then return end
  if not settings.allow_local and rspamd_lua_utils.is_rspamc_or_controller(task) then return end

  for _,sym in ipairs(settings.stop_symbols) do
    if task:has_symbol(sym) then
      lua_util.debugm(N, task, 'skip collection as symbol %s has fired', sym)
      return
    end
  end

  local from_domain = ''
  local from_user = ''
  if task:has_from('smtp') then
    local from = task:get_from('smtp')[1]

    if from then
      from_domain = from['domain']
      from_user = from['user']
    end

    if from_domain == '' then
      if task:get_helo() then
        from_domain = task:get_helo()
      end
    end
  else
    if task:get_helo() then
      from_domain = task:get_helo()
    end
  end

  local mime_domain = ''
  local mime_user = ''
  if task:has_from('mime') then
    local from = task:get_from('mime')[1]
    if from then
      mime_domain = from['domain']
      mime_user = from['user']
    end
  end

  local ip_str = 'undefined'
  local ip = task:get_from_ip()
  if ip and ip:is_valid() then
    local ipnet
    if ip:get_version() == 4 then
      ipnet = ip:apply_mask(settings['ipmask'])
    else
      ipnet = ip:apply_mask(settings['ipmask6'])
    end
    ip_str = ipnet:to_string()
  end

  local rcpt_user = ''
  local rcpt_domain = ''
  if task:has_recipients('smtp') then
    local rcpt = task:get_recipients('smtp')[1]
    rcpt_user = rcpt['user']
    rcpt_domain = rcpt['domain']
  end

  local list_id = ''
  local lh = task:get_header('List-Id')
  if lh then
    list_id = lh
  end

  local score = task:get_metric_score('default')[1];
  local bayes = 'unknown';
  local fuzzy = 'unknown';
  local fann = 'unknown';
  local whitelist = 'unknown';
  local dkim = 'unknown';
  local dmarc = 'unknown';

  local ret

  ret = clickhouse_check_symbol(task, settings['bayes_spam_symbols'], false)
  if ret then
    bayes = 'spam'
  end

  ret = clickhouse_check_symbol(task, settings['bayes_ham_symbols'], false)
  if ret then
    bayes = 'ham'
  end

  ret = clickhouse_check_symbol(task, settings['fann_symbols'], true)
  if ret then
    if ret > 0 then
      fann = 'spam'
    else
      fann = 'ham'
    end
  end


  ret = clickhouse_check_symbol(task, settings['whitelist_symbols'], true)
  if ret then
    if ret < 0 then
      whitelist = 'whitelist'
    else
      whitelist = 'blacklist'
    end
  end

  ret = clickhouse_check_symbol(task, settings['fuzzy_symbols'], false)
  if ret then
    fuzzy = 'deny'
  end

  ret = clickhouse_check_symbol(task, settings['dkim_allow_symbols'], false)
  if ret then
    dkim = 'allow'
  end

  ret = clickhouse_check_symbol(task, settings['dkim_reject_symbols'], false)
  if ret then
    dkim = 'reject'
  end

  ret = clickhouse_check_symbol(task, settings['dmarc_allow_symbols'], false)
  if ret then
    dmarc = 'allow'
  end

  ret = clickhouse_check_symbol(task, settings['dmarc_reject_symbols'], false)
  if ret then
    dmarc = 'reject'
  end

  local nrcpts = 0
  if task:has_recipients('smtp') then
    nrcpts = #task:get_recipients('smtp')
  end

  local nurls = 0
  if task:has_urls(true) then
    nurls = #task:get_urls(true)
  end

  local timestamp = task:get_date({
    format = 'connect',
    gmt = false
  })

  local action = task:get_metric_action('default')
  local digest = task:get_digest()

  local row = {
    today(timestamp),
    timestamp,
    from_domain,
    mime_domain,
    ip_str,
    score,
    nrcpts,
    task:get_size(),
    whitelist,
    bayes,
    fuzzy,
    fann,
    dkim,
    dmarc,
    nurls,
    action,
    from_user,
    mime_user,
    rcpt_user,
    rcpt_domain,
    list_id,
    digest
  }

  -- Attachments step
  local attachments_fnames = {}
  local attachments_ctypes = {}
  local attachments_lengths = {}
  local attachments_digests = {}
  for _,part in ipairs(task:get_parts()) do
    local fname = part:get_filename()

    if fname then
      table.insert(attachments_fnames, fname)
      local type, subtype = part:get_type()
      table.insert(attachments_ctypes, string.format("%s/%s",
          type, subtype))
      table.insert(attachments_lengths, part:get_length())
      table.insert(attachments_digests, string.sub(part:get_digest(), 1, 16))
    end
  end

  if #attachments_fnames > 0 then
    table.insert(row, attachments_fnames)
    table.insert(row,  attachments_ctypes)
    table.insert(row,  attachments_lengths)
    table.insert(row,   attachments_digests)
  else
    table.insert(row, {})
    table.insert(row, {})
    table.insert(row, {})
    table.insert(row, {})
  end

  local flatten_urls = function(f, ...)
    return fun.totable(fun.map(function(k,v) return f(k,v) end, ...))
  end

  -- Urls step
  local urls_urls = {}
  if task:has_urls(false) then

    for _,u in ipairs(task:get_urls(false)) do
      if settings['full_urls'] then
        urls_urls[u:get_text()] = u
      else
        urls_urls[u:get_host()] = u
      end
    end

    -- Get tlds
    table.insert(row, flatten_urls(function(_,u) return u:get_tld() end, urls_urls))
    -- Get hosts/full urls
    table.insert(row, flatten_urls(function(k, _) return k end, urls_urls))
  else
    table.insert(row, {})
    table.insert(row, {})
  end

  -- Emails step
  if task:has_urls(true) then
    table.insert(row, flatten_urls(function(k, _) return k end,
        fun.map(function(u)
          return string.format('%s@%s', u:get_user(), u:get_host()),true
        end, task:get_emails())))
  else
    table.insert(row, {})
  end

  -- ASN information
  local asn, country, ipnet = '--', '--', '--'
  local pool = task:get_mempool()
  ret = pool:get_variable("asn")
  if ret then
    asn = ret
  end
  ret = pool:get_variable("country")
  if ret then
    country = ret:sub(1, 2)
  end
  ret = pool:get_variable("ipnet")
  if ret then
    ipnet = ret
  end
  table.insert(row, asn)
  table.insert(row, country)
  table.insert(row, ipnet)

  -- Symbols info
  if settings.enable_symbols then
    local symbols = task:get_symbols_all()
    local syms_tab = {}
    local scores_tab = {}
    local options_tab = {}

    for _,s in ipairs(symbols) do
      table.insert(syms_tab, s.name or '')
      table.insert(scores_tab, s.score)

      if s.options then
        table.insert(options_tab, table.concat(s.options, ','))
      else
        table.insert(options_tab, '');
      end
    end
    table.insert(row, syms_tab)
    table.insert(row, scores_tab)
    table.insert(row, options_tab)
  end

  -- Custom data
  for k,rule in pairs(settings.custom_rules) do
    if not custom_rows[k] then custom_rows[k] = {} end
    table.insert(custom_rows[k], rule.get_row(task))
  end

  nrows = nrows + 1
  table.insert(data_rows, row)
  lua_util.debugm(N, task, "add clickhouse row %s / %s", nrows, settings.limit)

  if nrows > settings['limit'] then
    clickhouse_send_data(task)
    nrows = 0
    data_rows = {}
    custom_rows = {}
  end
end

local function do_remove_partition(ev_base, cfg, table_name, partition_id)
  lua_util.debugm(N, rspamd_config, "removing partition %s.%s", table_name, partition_id)
  local upstream = settings.upstream:get_upstream_round_robin()
  local remove_partition_sql = "ALTER TABLE ${table_name} ${remove_method} PARTITION ${partition_id}"
  local remove_method = (settings.retention.method == 'drop') and 'DROP' or 'DETACH'
  local sql_params = {
    ['table_name']     = table_name,
    ['remove_method']  = remove_method,
    ['partition_id']   = partition_id
  }

  local sql = rspamd_lua_utils.template(remove_partition_sql, sql_params)

  local ch_params = {
    body = sql,
    ev_base = ev_base,
    config = cfg,
  }

  local err, _ = lua_clickhouse.generic_sync(upstream, settings, ch_params, sql)
  if err then
    rspamd_logger.errx(rspamd_config,
      "cannot detach partition %s:%s from server %s: %s",
      table_name, partition_id,
      settings['server'], err)
    return
  end

  rspamd_logger.infox(rspamd_config,
      'detached partition %s:%s on server %s', table_name, partition_id,
      settings['server'])

end

--[[
  nil   - file is not writable, do not perform removal
  0     - it's time to perform removal
  <int> - how many seconds wait until next run
]]
local function get_last_removal_ago()
  local ts_file = string.format('%s/%s', rspamd_paths['DBDIR'], 'clickhouse_retention_run')
  local f, err = io.open(ts_file, 'r')
  local write_file
  local last_ts

  if err then
    lua_util.debugm(N, rspamd_config, 'Failed to open %s: %s', ts_file, err)
  else
    last_ts = tonumber(f:read('*number'))
    f:close()
  end

  local current_ts = os.time()

  if last_ts == nil or (last_ts + settings.retention.period) <= current_ts then
    write_file, err = io.open(ts_file, 'w')
    if err then
      rspamd_logger.errx(rspamd_config, 'Failed to open %s, will not perform retention: %s', ts_file, err)
      return nil
    end

    local res
    res, err = write_file:write(tostring(current_ts))
    if err or res == nil then
      rspamd_logger.errx(rspamd_config, 'Failed to write %s, will not perform retention: %s', ts_file, err)
      return nil
    end
    write_file:close()
    return 0
  end

  return (last_ts + settings.retention.period) - current_ts
end

local function clickhouse_remove_old_partitions(cfg, ev_base)
  local last_time_ago = get_last_removal_ago()
  if last_time_ago == nil then
    rspamd_logger.errx(rspamd_config, "Failed to get last run time. Disabling retention")
    return false
  elseif last_time_ago ~= 0 then
    return last_time_ago
  end

  local upstream = settings.upstream:get_upstream_round_robin()
  local partition_to_remove_sql = "SELECT distinct partition, table FROM system.parts WHERE " ..
      "table in ('${tables}') and max_date <= toDate(now() - interval ${month} month);"

  local table_names = {'rspamd'}
  local tables = table.concat(table_names, "', '")
  local sql_params = {
    tables = tables,
    month  = settings.retention.period_months,
  }
  local sql = rspamd_lua_utils.template(partition_to_remove_sql, sql_params)


  local ch_params = {
    ev_base = ev_base,
    config = cfg,
  }
  local err, rows = lua_clickhouse.select_sync(upstream, settings, ch_params, sql)
  if err then
    rspamd_logger.errx(rspamd_config,
      "cannot send data to clickhouse server %s: %s",
      settings['server'], err)
  else
    fun.each(function(row)
      do_remove_partition(ev_base, cfg, row.table, row.partition)
    end, rows)
  end

  -- settings.retention.period is added on initialisation, see below
  return settings.retention.period
end

local function upload_clickhouse_schema(upstream, ev_base, cfg)
  local ch_params = {
    ev_base = ev_base,
    config = cfg,
  }

  -- Apply schema sequentially
  for i,v in ipairs(clickhouse_schema) do
    local sql = v
    local err, _ = lua_clickhouse.generic_sync(upstream, settings, ch_params, sql)

    if err then
      rspamd_logger.errx(rspamd_config, "cannot upload schema '%s' on clickhouse server %s: %s",
        sql, upstream:get_addr():to_string(true), err)
      return
    end
    rspamd_logger.infox(rspamd_config, 'uploaded clickhouse schema element %s to %s',
      i, upstream:get_addr():to_string(true))
  end
end

local function maybe_apply_migrations(upstream, ev_base, cfg, version)
  local ch_params = {
    ev_base = ev_base,
    config = cfg,
  }
  -- Apply migrations sequentially
  local function migration_recursor(i)
    if i < schema_version  then
      if migrations[i] then
        -- We also need to apply statements sequentially
        local function sql_recursor(j)
          if migrations[i][j] then
            local sql = migrations[i][j]
            local ret = lua_clickhouse.generic(upstream, settings, ch_params, sql,
                function(_, _)
                  rspamd_logger.infox(rspamd_config,
                      'applied migration to version %s from version %s: %s',
                      i + 1, version, sql:gsub('[\n%s]+', ' '))
                  if j == #migrations[i] then
                    -- Go to the next migration
                    migration_recursor(i + 1)
                  else
                    -- Apply the next statement
                    sql_recursor(j + 1)
                  end
                end ,
                function(_, err)
                  rspamd_logger.errx(rspamd_config,
                      "cannot apply migration %s: '%s' on clickhouse server %s: %s",
                      i, sql, upstream:get_addr():to_string(true), err)
                end)
            if not ret then
              rspamd_logger.errx(rspamd_config,
                  "cannot apply migration %s: '%s' on clickhouse server %s: cannot make request",
                  i, sql, upstream:get_addr():to_string(true))
            end
          end
        end

        sql_recursor(1)
      else
        -- Try another migration
        migration_recursor(i + 1)
      end
    end
  end

  migration_recursor(version)
end

local function check_rspamd_table(upstream, ev_base, cfg)
  local ch_params = {
    ev_base = ev_base,
    config = cfg,
  }
  local sql = [[EXISTS TABLE rspamd]]
  local err, rows = lua_clickhouse.select_sync(upstream, settings, ch_params, sql)
  if err then
    rspamd_logger.errx(rspamd_config, "cannot check rspamd table in clickhouse server %s: %s",
      upstream:get_addr():to_string(true), err)
    return
  end

  if rows[1] and rows[1].result then
    if tonumber(rows[1].result) == 1 then
      -- Apply migration
      rspamd_logger.infox(rspamd_config, 'table rspamd exists, apply migration')
      maybe_apply_migrations(upstream, ev_base, cfg, 1)
    else
      -- Upload schema
      rspamd_logger.infox(rspamd_config, 'table rspamd does not exists, upload full schema')
      upload_clickhouse_schema(upstream, ev_base, cfg)
    end
  else
    rspamd_logger.errx(rspamd_config,
        "unexpected reply on EXISTS command from server %s: %s",
        upstream:get_addr():to_string(true), rows)
  end
end


local function check_clickhouse_upstream(upstream, ev_base, cfg)
  local ch_params = {
    ev_base = ev_base,
    config = cfg,
  }
  -- If we have some custom rules, we just send its schema to the upstream
  for k,rule in pairs(settings.custom_rules) do
    if rule.schema then
      local sql = rspamd_lua_utils.template(rule.schema, settings)
      local err, _ = lua_clickhouse.generic_sync(upstream, settings, ch_params, sql)
      if err then
        rspamd_logger.errx(rspamd_config, 'cannot send custom schema %s to clickhouse server %s: ' ..
        'cannot make request (%s)',
            k, upstream:get_addr():to_string(true), err)
      end
    end
  end

  -- Now check the main schema and apply migrations if needed
  local sql = [[SELECT MAX(Version) as v FROM rspamd_version]]
  local err, rows = lua_clickhouse.select_sync(upstream, settings, ch_params, sql)
  if err then
    if rows and rows.code == 404 then
      rspamd_logger.infox(rspamd_config, 'table rspamd_version does not exist, check rspamd table')
      check_rspamd_table(upstream, ev_base, cfg)
    else
      rspamd_logger.errx(rspamd_config, "cannot get version on clickhouse server %s: %s",
        upstream:get_addr():to_string(true), err)
    end
  else
    local version = tonumber(rows[1].v)
    maybe_apply_migrations(upstream, ev_base, cfg, version)
  end
end

local opts = rspamd_config:get_all_opt('clickhouse')
if opts then
    for k,v in pairs(opts) do
      if k == 'custom_rules' then
        if not v[1] then
          v = {v}
        end

        for i,rule in ipairs(v) do
          if rule.schema and rule.first_row and rule.get_row then
            local first_row, get_row
            local loadstring = loadstring or load
            local ret, res_or_err = pcall(loadstring(rule.first_row))

            if not ret or type(res_or_err) ~= 'function' then
              rspamd_logger.errx(rspamd_config, 'invalid first_row (%s) - must be a function',
                  res_or_err)
            else
              first_row = res_or_err
            end

            ret, res_or_err = pcall(loadstring(rule.get_row))

            if not ret or type(res_or_err) ~= 'function' then
              rspamd_logger.errx(rspamd_config, 'invalid get_row (%s) - must be a function',
                  res_or_err)
            else
              get_row = res_or_err
            end

            if first_row and get_row then
              local name = rule.name or tostring(i)
              settings.custom_rules[name] = {
                schema = rule.schema,
                first_row = first_row,
                get_row = get_row,
              }
            end
          else
            rspamd_logger.errx(rspamd_config, 'custom rule has no required attributes: schema, first_row and get_row')
          end
        end
      else
        settings[k] = v
      end
    end

    if not settings['server'] and not settings['servers'] then
      rspamd_logger.infox(rspamd_config, 'no servers are specified, disabling module')
      rspamd_lua_utils.disable_module(N, "config")
    else
      settings['from_map'] = rspamd_map_add('clickhouse', 'from_tables',
        'regexp', 'clickhouse specific domains')

      settings.upstream = upstream_list.create(rspamd_config,
        settings['server'] or settings['servers'], 8123)

      if not settings.upstream then
        rspamd_logger.errx(rspamd_config, 'cannot parse clickhouse address: %s',
            settings['server'] or settings['servers'])
        rspamd_lua_utils.disable_module(N, "config")
        return
      end

      rspamd_config:register_symbol({
        name = 'CLICKHOUSE_COLLECT',
        type = 'idempotent',
        callback = clickhouse_collect,
        priority = 10,
        flags = 'empty',
      })
      rspamd_config:register_finish_script(function(task)
        if nrows > 0 then
          clickhouse_send_data(task)
        end
      end)
      -- Create tables on load
      rspamd_config:add_on_load(function(cfg, ev_base, worker)
        if worker:is_primary_controller() then
          local upstreams = settings.upstream:all_upstreams()

          for _,up in ipairs(upstreams) do
            check_clickhouse_upstream(up, ev_base, cfg)
          end

          if settings.retention.enable and settings.retention.method ~= 'drop' and
              settings.retention.method ~= 'detach' then
            rspamd_logger.errx(rspamd_config,
                "retention.method should be either 'drop' or 'detach' (now: %s). Disabling retention",
                settings.retention.method)
            settings.retention.enable = false
          end
          if settings.retention.enable and settings.retention.period_months < 1 or
              settings.retention.period_months > 1000 then
            rspamd_logger.errx(rspamd_config,
                "please, set retention.period_months between 1 and 1000 (now: %s). Disabling retention",
                settings.retention.period_months)
            settings.retention.enable = false
          end
          local period = lua_util.parse_time_interval(settings.retention.run_every)
          if settings.retention.enable and period == nil then
            rspamd_logger.errx(rspamd_config, "invalid value for retention.run_every (%s). Disabling retention",
                    settings.retention.run_every)
            settings.retention.enable = false
          end

          if settings.retention.enable then
            settings.retention.period = period
            rspamd_logger.infox(rspamd_config,
                "retention will be performed each %s seconds for %s month with method %s",
                period, settings.retention.period_months, settings.retention.method)
            rspamd_config:add_periodic(ev_base, 0, clickhouse_remove_old_partitions, false)
          end
        end
      end)
    end
end
