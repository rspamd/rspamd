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
local upstream_list = require "rspamd_upstream_list"
local lua_util = require "lua_util"
local lua_clickhouse = require "lua_clickhouse"
local lua_settings = require "lua_settings"
local fun = require "fun"

local N = "clickhouse"

if confighelp then
  return
end

local data_rows = {}
local custom_rows = {}
local nrows = 0
local used_memory = 0
local last_collection = 0
local final_call = false -- If the final collection has been started
local schema_version = 9 -- Current schema version

local settings = {
  limits = { -- Collection limits
    max_rows = 1000, -- How many rows are allowed (0 for disable this)
    max_memory = 50 * 1024 * 1024, -- How many memory should be occupied before sending collection
    max_interval = 60, -- Maximum collection interval
  },
  collect_garbage = false, -- Peform GC collection after sending the data
  check_timeout = 10.0, -- Periodic timeout
  timeout = 5.0,
  bayes_spam_symbols = {'BAYES_SPAM'},
  bayes_ham_symbols = {'BAYES_HAM'},
  ann_symbols_spam = {'NEURAL_SPAM'},
  ann_symbols_ham = {'NEURAL_HAM'},
  fuzzy_symbols = {'FUZZY_DENIED'},
  whitelist_symbols = {'WHITELIST_DKIM', 'WHITELIST_SPF_DKIM', 'WHITELIST_DMARC'},
  dkim_allow_symbols = {'R_DKIM_ALLOW'},
  dkim_reject_symbols = {'R_DKIM_REJECT'},
  dkim_dnsfail_symbols = {'R_DKIM_TEMPFAIL', 'R_DKIM_PERMFAIL'},
  dkim_na_symbols = {'R_DKIM_NA'},
  dmarc_allow_symbols = {'DMARC_POLICY_ALLOW'},
  dmarc_reject_symbols = {'DMARC_POLICY_REJECT'},
  dmarc_quarantine_symbols = {'DMARC_POLICY_QUARANTINE'},
  dmarc_softfail_symbols = {'DMARC_POLICY_SOFTFAIL'},
  dmarc_na_symbols = {'DMARC_NA'},
  spf_allow_symbols = {'R_SPF_ALLOW'},
  spf_reject_symbols = {'R_SPF_FAIL'},
  spf_dnsfail_symbols = {'R_SPF_DNSFAIL', 'R_SPF_PERMFAIL'},
  spf_neutral_symbols = {'R_DKIM_TEMPFAIL', 'R_DKIM_PERMFAIL'},
  spf_na_symbols = {'R_SPF_NA'},
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
  insert_subject = false,
  subject_privacy = false, -- subject privacy is off
  subject_privacy_alg = 'blake2', -- default hash-algorithm to obfuscate subject
  subject_privacy_prefix = 'obf', -- prefix to show it's obfuscated
  subject_privacy_length = 16, -- cut the length of the hash
  schema_additions = {}, -- additional SQL statements to be executed when schema is uploaded
  user = nil,
  password = nil,
  no_ssl_verify = false,
  custom_rules = {},
  enable_digest = false,
  exceptions = nil,
  retention = {
    enable = false,
    method = 'detach',
    period_months = 3,
    run_every = '7d',
  },
  extra_columns = {},
}

--- @language SQL
local clickhouse_schema = {[[
CREATE TABLE IF NOT EXISTS rspamd
(
    Date Date COMMENT 'Date (used for partitioning)',
    TS DateTime COMMENT 'Date and time of the request start (UTC)',
    From String COMMENT 'Domain part of the return address (RFC5321.MailFrom)',
    MimeFrom String COMMENT 'Domain part of the address in From: header (RFC5322.From)',
    IP String COMMENT 'SMTP client IP as provided by MTA or from Received: header',
    Helo String COMMENT 'Full hostname as sent by the SMTP client (RFC5321.HELO/.EHLO)',
    Score Float32 COMMENT 'Message score',
    NRcpt UInt8 COMMENT 'Number of envelope recipients (RFC5321.RcptTo)',
    Size UInt32 COMMENT 'Message size in bytes',
    IsWhitelist Enum8('blacklist' = 0, 'whitelist' = 1, 'unknown' = 2) DEFAULT 'unknown' COMMENT 'Based on symbols configured in `whitelist_symbols` module option',
    IsBayes Enum8('ham' = 0, 'spam' = 1, 'unknown' = 2) DEFAULT 'unknown' COMMENT 'Based on symbols configured in `bayes_spam_symbols` and `bayes_ham_symbols` module options',
    IsFuzzy Enum8('whitelist' = 0, 'deny' = 1, 'unknown' = 2) DEFAULT 'unknown' COMMENT 'Based on symbols configured in `fuzzy_symbols` module option',
    IsFann Enum8('ham' = 0, 'spam' = 1, 'unknown' = 2) DEFAULT 'unknown' COMMENT 'Based on symbols configured in `ann_symbols_spam` and `ann_symbols_ham` module options',
    IsDkim Enum8('reject' = 0, 'allow' = 1, 'unknown' = 2, 'dnsfail' = 3, 'na' = 4) DEFAULT 'unknown' COMMENT 'Based on symbols configured in dkim_* module options',
    IsDmarc Enum8('reject' = 0, 'allow' = 1, 'unknown' = 2, 'softfail' = 3, 'na' = 4, 'quarantine' = 5) DEFAULT 'unknown' COMMENT 'Based on symbols configured in dmarc_* module options',
    IsSpf Enum8('reject' = 0, 'allow' = 1, 'neutral' = 2, 'dnsfail' = 3, 'na' = 4, 'unknown' = 5) DEFAULT 'unknown' COMMENT 'Based on symbols configured in spf_* module options',
    NUrls Int32 COMMENT 'Number of URLs and email extracted from the message',
    Action Enum8('reject' = 0, 'rewrite subject' = 1, 'add header' = 2, 'greylist' = 3, 'no action' = 4, 'soft reject' = 5, 'custom' = 6) DEFAULT 'no action' COMMENT 'Action returned for the message; if action is not predefined actual action will be in `CustomAction` field',
    CustomAction LowCardinality(String) COMMENT 'Action string for custom action',
    FromUser String COMMENT 'Local part of the return address (RFC5321.MailFrom)',
    MimeUser String COMMENT 'Local part of the address in From: header (RFC5322.From)',
    RcptUser String COMMENT '[Deprecated] Local part of the first envelope recipient (RFC5321.RcptTo)',
    RcptDomain String COMMENT '[Deprecated] Domain part of the first envelope recipient (RFC5321.RcptTo)',
    SMTPRecipients Array(String) COMMENT 'List of envelope recipients (RFC5321.RcptTo)',
    MimeRecipients Array(String) COMMENT 'List of recipients from headers (RFC5322.To/.CC/.BCC)',
    MessageId String COMMENT 'Message-ID header',
    ListId String COMMENT 'List-Id header',
    Subject String COMMENT 'Subject header (or hash if `subject_privacy` module option enabled)',
    `Attachments.FileName` Array(String) COMMENT 'Attachment name',
    `Attachments.ContentType` Array(String) COMMENT 'Attachment Content-Type',
    `Attachments.Length` Array(UInt32) COMMENT 'Attachment size in bytes',
    `Attachments.Digest` Array(FixedString(16)) COMMENT 'First 16 characters of hash returned by mime_part:get_digest()',
    `Urls.Tld` Array(String) COMMENT 'Effective second level domain part of the URL host',
    `Urls.Url` Array(String) COMMENT 'Full URL if `full_urls` module option enabled, host part of URL otherwise',
    `Urls.Flags` Array(UInt32) COMMENT 'Corresponding url flags, see `enum rspamd_url_flags` in libserver/url.h for details',
    Emails Array(String) COMMENT 'List of emails extracted from the message',
    ASN UInt32 COMMENT 'BGP AS number for SMTP client IP (returned by asn.rspamd.com or asn6.rspamd.com)',
    Country FixedString(2) COMMENT 'Country for SMTP client IP (returned by asn.rspamd.com or asn6.rspamd.com)',
    IPNet String,
    `Symbols.Names` Array(LowCardinality(String)) COMMENT 'Symbol name',
    `Symbols.Scores` Array(Float32) COMMENT 'Symbol score',
    `Symbols.Options` Array(String) COMMENT 'Symbol options (comma separated list)',
    `Groups.Names` Array(LowCardinality(String)) COMMENT 'Group name',
    `Groups.Scores` Array(Float32) COMMENT 'Group score',
    ScanTimeReal UInt32 COMMENT 'Request time in milliseconds',
    ScanTimeVirtual UInt32 COMMENT 'Deprecated do not use',
    AuthUser String COMMENT 'Username for authenticated SMTP client',
    SettingsId LowCardinality(String) COMMENT 'ID for the settings profile',
    Digest FixedString(32) COMMENT '[Deprecated]',
    SMTPFrom ALIAS if(From = '', '', concat(FromUser, '@', From)) COMMENT 'Return address (RFC5321.MailFrom)',
    SMTPRcpt ALIAS SMTPRecipients[1] COMMENT 'The first envelope recipient (RFC5321.RcptTo)',
    MIMEFrom ALIAS if(MimeFrom = '', '', concat(MimeUser, '@', MimeFrom)) COMMENT 'Address in From: header (RFC5322.From)',
    MIMERcpt ALIAS MimeRecipients[1] COMMENT 'The first recipient from headers (RFC5322.To/.CC/.BCC)'
) ENGINE = MergeTree()
PARTITION BY toMonday(Date)
ORDER BY TS
]],
[[CREATE TABLE IF NOT EXISTS rspamd_version ( Version UInt32) ENGINE = TinyLog]],
{[[INSERT INTO rspamd_version (Version) Values (${SCHEMA_VERSION})]], true},
}

-- This describes SQL queries to migrate between versions
local migrations = {
  [1] = {
    -- Move to a wide fat table
    [[ALTER TABLE rspamd
      ADD COLUMN IF NOT EXISTS `Attachments.FileName` Array(String) AFTER ListId,
      ADD COLUMN IF NOT EXISTS `Attachments.ContentType` Array(String) AFTER `Attachments.FileName`,
      ADD COLUMN IF NOT EXISTS `Attachments.Length` Array(UInt32) AFTER `Attachments.ContentType`,
      ADD COLUMN IF NOT EXISTS `Attachments.Digest` Array(FixedString(16)) AFTER `Attachments.Length`,
      ADD COLUMN IF NOT EXISTS `Urls.Tld` Array(String) AFTER `Attachments.Digest`,
      ADD COLUMN IF NOT EXISTS `Urls.Url` Array(String) AFTER `Urls.Tld`,
      ADD COLUMN IF NOT EXISTS Emails Array(String) AFTER `Urls.Url`,
      ADD COLUMN IF NOT EXISTS ASN UInt32 AFTER Emails,
      ADD COLUMN IF NOT EXISTS Country FixedString(2) AFTER ASN,
      ADD COLUMN IF NOT EXISTS IPNet String AFTER Country,
      ADD COLUMN IF NOT EXISTS `Symbols.Names` Array(String) AFTER IPNet,
      ADD COLUMN IF NOT EXISTS `Symbols.Scores` Array(Float64) AFTER `Symbols.Names`,
      ADD COLUMN IF NOT EXISTS `Symbols.Options` Array(String) AFTER `Symbols.Scores`]],
    -- Add explicit version
    [[CREATE TABLE rspamd_version ( Version UInt32) ENGINE = TinyLog]],
    [[INSERT INTO rspamd_version (Version) Values (2)]],
  },
  [2] = {
    -- Add `Subject` column
    [[ALTER TABLE rspamd
      ADD COLUMN IF NOT EXISTS Subject String AFTER ListId]],
    -- New version
    [[INSERT INTO rspamd_version (Version) Values (3)]],
  },
  [3] = {
    [[ALTER TABLE rspamd
      ADD COLUMN IF NOT EXISTS IsSpf Enum8('reject' = 0, 'allow' = 1, 'neutral' = 2, 'dnsfail' = 3, 'na' = 4, 'unknown' = 5) DEFAULT 'unknown' AFTER IsDmarc,
      MODIFY COLUMN IsDkim Enum8('reject' = 0, 'allow' = 1, 'unknown' = 2, 'dnsfail' = 3, 'na' = 4) DEFAULT 'unknown',
      MODIFY COLUMN IsDmarc Enum8('reject' = 0, 'allow' = 1, 'unknown' = 2, 'softfail' = 3, 'na' = 4, 'quarantine' = 5) DEFAULT 'unknown',
      ADD COLUMN IF NOT EXISTS MimeRecipients Array(String) AFTER RcptDomain,
      ADD COLUMN IF NOT EXISTS MessageId String AFTER MimeRecipients,
      ADD COLUMN IF NOT EXISTS ScanTimeReal UInt32 AFTER `Symbols.Options`,
      ADD COLUMN IF NOT EXISTS ScanTimeVirtual UInt32 AFTER ScanTimeReal]],
    -- Add aliases
    [[ALTER TABLE rspamd
      ADD COLUMN IF NOT EXISTS SMTPFrom ALIAS if(From = '', '', concat(FromUser, '@', From)),
      ADD COLUMN IF NOT EXISTS SMTPRcpt ALIAS if(RcptDomain = '', '', concat(RcptUser, '@', RcptDomain)),
      ADD COLUMN IF NOT EXISTS MIMEFrom ALIAS if(MimeFrom = '', '', concat(MimeUser, '@', MimeFrom)),
      ADD COLUMN IF NOT EXISTS MIMERcpt ALIAS MimeRecipients[1]
    ]],
    -- New version
    [[INSERT INTO rspamd_version (Version) Values (4)]],
  },
  [4] = {
    [[ALTER TABLE rspamd
      MODIFY COLUMN Action Enum8('reject' = 0, 'rewrite subject' = 1, 'add header' = 2, 'greylist' = 3, 'no action' = 4, 'soft reject' = 5, 'custom' = 6) DEFAULT 'no action',
      ADD COLUMN IF NOT EXISTS CustomAction String AFTER Action
    ]],
    -- New version
    [[INSERT INTO rspamd_version (Version) Values (5)]],
  },
  [5] = {
    [[ALTER TABLE rspamd
      ADD COLUMN IF NOT EXISTS AuthUser String AFTER ScanTimeVirtual,
      ADD COLUMN IF NOT EXISTS SettingsId LowCardinality(String) AFTER AuthUser
    ]],
    -- New version
    [[INSERT INTO rspamd_version (Version) Values (6)]],
  },
  [6] = {
    -- Add new columns
    [[ALTER TABLE rspamd
      ADD COLUMN IF NOT EXISTS Helo String AFTER IP,
      ADD COLUMN IF NOT EXISTS SMTPRecipients Array(String) AFTER RcptDomain
    ]],
    -- Modify SMTPRcpt alias
    [[
    ALTER TABLE rspamd
      MODIFY COLUMN SMTPRcpt ALIAS SMTPRecipients[1]
    ]],
    -- New version
    [[INSERT INTO rspamd_version (Version) Values (7)]],
  },
  [7] = {
    -- Add new columns
    [[ALTER TABLE rspamd
      ADD COLUMN IF NOT EXISTS `Groups.Names` Array(LowCardinality(String)) AFTER `Symbols.Options`,
      ADD COLUMN IF NOT EXISTS `Groups.Scores` Array(Float32) AFTER `Groups.Names`
    ]],
    -- New version
    [[INSERT INTO rspamd_version (Version) Values (8)]],
  },
  [8] = {
    -- Add new columns
    [[ALTER TABLE rspamd
      ADD COLUMN IF NOT EXISTS `Urls.Flags` Array(UInt32) AFTER `Urls.Url`
    ]],
    -- New version
    [[INSERT INTO rspamd_version (Version) Values (9)]],
  },
}

local predefined_actions = {
  ['reject'] = true,
  ['rewrite subject'] = true,
  ['add header'] = true,
  ['greylist'] = true,
  ['no action'] = true,
  ['soft reject'] = true
}

local function clickhouse_main_row(res)
  local fields = {
    'Date',
    'TS',
    'From',
    'MimeFrom',
    'IP',
    'Helo',
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
    'SMTPRecipients',
    'ListId',
    'Subject',
    'Digest',
    -- 1.9.2 +
    'IsSpf',
    'MimeRecipients',
    'MessageId',
    'ScanTimeReal',
    -- 1.9.3 +
    'CustomAction',
    -- 2.0 +
    'AuthUser',
    'SettingsId',
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
    'Urls.Flags',
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

local function clickhouse_groups_row(res)
  local fields = {
    'Groups.Names',
    'Groups.Scores',
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

local function clickhouse_extra_columns(res)
  for _,v in ipairs(settings.extra_columns) do table.insert(res, v.name) end
end

local function today(ts)
  return os.date('!%Y-%m-%d', ts)
end

local function clickhouse_check_symbol(task, settings_field_name, fields_table,
                                       field_name, value, value_negative)
  for _,s in ipairs(settings[settings_field_name] or {}) do
    if task:has_symbol(s) then
      if value_negative then
        local sym = task:get_symbol(s)[1]
        if sym['score'] > 0 then
          fields_table[field_name] = value
        else
          fields_table[field_name] = value_negative
        end
      else
        fields_table[field_name] = value
      end

      return true
    end
  end

  return false
end

local function clickhouse_send_data(task, ev_base, why, gen_rows, cust_rows)
  local log_object = task or rspamd_config
  local upstream = settings.upstream:get_upstream_round_robin()
  local ip_addr = upstream:get_addr():to_string(true)
  rspamd_logger.infox(log_object, "trying to send %s rows to clickhouse server %s; started as %s",
      #gen_rows + #cust_rows, ip_addr, why)

  local function gen_success_cb(what, how_many)
    return function (_, _)
      rspamd_logger.messagex(log_object, "sent %s rows of %s to clickhouse server %s; started as %s",
          how_many, what, ip_addr, why)
      upstream:ok()
    end
  end

  local function gen_fail_cb(what, how_many)
    return function (_, err)
      rspamd_logger.errx(log_object, "cannot send %s rows of %s data to clickhouse server %s: %s; started as %s",
          how_many, what, ip_addr, err, why)
      upstream:fail()
    end
  end

  local function send_data(what, tbl, query)
    local ch_params = {}
    if task then
      ch_params.task = task
    else
      ch_params.config = rspamd_config
      ch_params.ev_base = ev_base
    end

    local ret = lua_clickhouse.insert(upstream, settings, ch_params,
        query, tbl,
        gen_success_cb(what, #tbl),
        gen_fail_cb(what, #tbl))
    if not ret then
      rspamd_logger.errx(log_object, "cannot send %s rows of %s data to clickhouse server %s: %s",
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
    clickhouse_groups_row(fields)
  end

  if #settings.extra_columns > 0 then
    clickhouse_extra_columns(fields)
  end

  send_data('generic data', gen_rows,
      string.format('INSERT INTO rspamd (%s)',
          table.concat(fields, ',')))

  for k,crows in pairs(cust_rows) do
    if #crows > 1 then
      send_data('custom data ('..k..')', crows,
          settings.custom_rules[k].first_row())
    end
  end
end

local function clickhouse_collect(task)
  if task:has_flag('skip') then
    return
  end

  if not settings.allow_local and lua_util.is_rspamc_or_controller(task) then
    return
  end

  for _,sym in ipairs(settings.stop_symbols) do
    if task:has_symbol(sym) then
      rspamd_logger.infox(task, 'skip Clickhouse storage for message: symbol %s has fired', sym)
      return
    end
  end

  if settings.exceptions then
    local excepted,trace = settings.exceptions:process(task)
    if excepted then
      rspamd_logger.infox(task, 'skipped Clickhouse storage for message: excepted (%s)',
          trace)
      -- Excepted
      return
    end
  end

  local from_domain = ''
  local from_user = ''
  if task:has_from('smtp') then
    local from = task:get_from({'smtp','orig'})[1]

    if from then
      from_domain = from['domain']:lower()
      from_user = from['user']
    end
  end

  local mime_domain = ''
  local mime_user = ''
  if task:has_from('mime') then
    local from = task:get_from({'mime','orig'})[1]
    if from then
      mime_domain = from['domain']:lower()
      mime_user = from['user']
    end
  end

  local mime_recipients = {}
  if task:has_recipients('mime') then
    local recipients = task:get_recipients({'mime','orig'})
    for _, rcpt in ipairs(recipients) do
      table.insert(mime_recipients, rcpt['user'] .. '@' .. rcpt['domain']:lower())
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

  local helo = task:get_helo() or ''

  local rcpt_user = ''
  local rcpt_domain = ''
  local smtp_recipients = {}
  if task:has_recipients('smtp') then
    local recipients = task:get_recipients('smtp')
    -- for compatibility with an old table structure
    rcpt_user = recipients[1]['user']
    rcpt_domain = recipients[1]['domain']:lower()

    for _, rcpt in ipairs(recipients) do
      table.insert(smtp_recipients, rcpt['user'] .. '@' .. rcpt['domain']:lower())
    end
  end

  local list_id = task:get_header('List-Id') or ''
  local message_id = lua_util.maybe_obfuscate_string(task:get_message_id() or '',
      settings, 'mid')

  local score = task:get_metric_score('default')[1];
  local fields = {
    bayes = 'unknown',
    fuzzy = 'unknown',
    ann = 'unknown',
    whitelist = 'unknown',
    dkim = 'unknown',
    dmarc = 'unknown',
    spf = 'unknown',
  }

  local ret

  ret = clickhouse_check_symbol(task,'bayes_spam_symbols', fields,
      'bayes', 'spam')
  if not ret then
    clickhouse_check_symbol(task,'bayes_ham_symbols', fields,
        'bayes', 'ham')
  end

  clickhouse_check_symbol(task,'ann_symbols_spam', fields,
      'ann', 'spam')
  if not ret then
    clickhouse_check_symbol(task,'ann_symbols_ham', fields,
        'ann', 'ham')
  end

  clickhouse_check_symbol(task,'whitelist_symbols', fields,
      'whitelist', 'blacklist', 'whitelist')

  clickhouse_check_symbol(task,'fuzzy_symbols', fields,
      'fuzzy', 'deny')


  ret = clickhouse_check_symbol(task,'dkim_allow_symbols', fields,
      'dkim', 'allow')
  if not ret then
    ret = clickhouse_check_symbol(task,'dkim_reject_symbols', fields,
        'dkim', 'reject')
  end
  if not ret then
    ret = clickhouse_check_symbol(task,'dkim_dnsfail_symbols', fields,
        'dkim', 'dnsfail')
  end
  if not ret then
    clickhouse_check_symbol(task,'dkim_na_symbols', fields,
        'dkim', 'na')
  end


  ret = clickhouse_check_symbol(task,'dmarc_allow_symbols', fields,
      'dmarc', 'allow')
  if not ret then
    ret = clickhouse_check_symbol(task,'dmarc_reject_symbols', fields,
        'dmarc', 'reject')
  end
  if not ret then
    ret = clickhouse_check_symbol(task,'dmarc_quarantine_symbols', fields,
        'dmarc', 'quarantine')
  end
  if not ret then
    ret = clickhouse_check_symbol(task,'dmarc_softfail_symbols', fields,
        'dmarc', 'softfail')
  end
  if not ret then
    clickhouse_check_symbol(task,'dmarc_na_symbols', fields,
        'dmarc', 'na')
  end


  ret = clickhouse_check_symbol(task,'spf_allow_symbols', fields,
      'spf', 'allow')
  if not ret then
    ret = clickhouse_check_symbol(task,'spf_reject_symbols', fields,
        'spf', 'reject')
  end
  if not ret then
    ret = clickhouse_check_symbol(task,'spf_neutral_symbols', fields,
        'spf', 'neutral')
  end
  if not ret then
    ret = clickhouse_check_symbol(task,'spf_dnsfail_symbols', fields,
        'spf', 'dnsfail')
  end
  if not ret then
    clickhouse_check_symbol(task,'spf_na_symbols', fields,
        'spf', 'na')
  end

  local nrcpts = 0
  if task:has_recipients('smtp') then
    nrcpts = #task:get_recipients('smtp')
  end

  local nurls = 0
  local task_urls = task:get_urls({
   content = true,
   images = true,
   emails = false,
   sort = true,
  }) or {}

  nurls = #task_urls

  local timestamp = math.floor(task:get_date({
    format = 'connect',
    gmt = true, -- The only sane way to sync stuff with different timezones
  }))

  local action = task:get_metric_action('default')
  local custom_action = ''

  if not predefined_actions[action] then
    custom_action = action
    action = 'custom'
  end

  local digest = ''

  if settings.enable_digest then
    digest = task:get_digest()
  end

  local subject = ''
  if settings.insert_subject then
    subject = lua_util.maybe_obfuscate_string(task:get_subject() or '', settings, 'subject')
  end

  local scan_real = task:get_scan_time()
  scan_real = math.floor(scan_real * 1000)
  if scan_real < 0 then
    rspamd_logger.messagex(task,
        'clock skew detected for message: %s ms real scan time (reset to 0)',
        scan_real)
    scan_real = 0
  end

  local auth_user = task:get_user() or ''
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

  local row = {
    today(timestamp),
    timestamp,
    from_domain,
    mime_domain,
    ip_str,
    helo,
    score,
    nrcpts,
    task:get_size(),
    fields.whitelist,
    fields.bayes,
    fields.fuzzy,
    fields.ann,
    fields.dkim,
    fields.dmarc,
    nurls,
    action,
    from_user,
    mime_user,
    rcpt_user,
    rcpt_domain,
    smtp_recipients,
    list_id,
    subject,
    digest,
    fields.spf,
    mime_recipients,
    message_id,
    scan_real,
    custom_action,
    auth_user,
    settings_id
  }

  -- Attachments step
  local attachments_fnames = {}
  local attachments_ctypes = {}
  local attachments_lengths = {}
  local attachments_digests = {}
  for _, part in ipairs(task:get_parts()) do
    if part:is_attachment() then
      table.insert(attachments_fnames, part:get_filename() or '')
      local mime_type, mime_subtype = part:get_type()
      table.insert(attachments_ctypes, string.format("%s/%s", mime_type, mime_subtype))
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

  -- Urls step
  local urls_urls = {}
  local urls_tlds = {}
  local urls_flags = {}

  if settings.full_urls then
    for i,u in ipairs(task_urls) do
      urls_urls[i] = u:get_text()
      urls_tlds[i] = u:get_tld() or u:get_host()
      urls_flags[i] = u:get_flags_num()
    end
  else
    -- We need to store unique
    local mt = {
      ord_tbl = {}, -- ordered list of urls
      idx_tbl = {}, -- indexed by host + flags, reference to an index in ord_tbl
      __newindex = function(t, k, v)
        local idx = getmetatable(t).idx_tbl
        local ord =  getmetatable(t).ord_tbl
        local key = k:get_host() .. tostring(k:get_flags_num())
        if idx[key] then
          ord[idx[key]] = v -- replace
        else
          ord[#ord + 1] = v
          idx[key] = #ord
        end
      end,
      __index = function(t, k)
        local ord = getmetatable(t).ord_tbl
        if type(k) == 'number' then
          return ord[k]
        else
          local idx = getmetatable(t).idx_tbl
          local key = k:get_host() .. tostring(k:get_flags_num())
          if idx[key] then
            return ord[idx[key]]
          end
        end
      end,
    }
    -- Extra index needed for making this unique
    local urls_idx = {}
    setmetatable(urls_idx, mt)
    for _,u in ipairs(task_urls) do
      if not urls_idx[u] then
        urls_idx[u] = u
        urls_urls[#urls_urls + 1] = u:get_host()
        urls_tlds[#urls_tlds + 1] = u:get_tld() or u:get_host()
        urls_flags[#urls_flags + 1] = u:get_flags_num()
      end
    end
  end


  -- Get tlds
  table.insert(row, urls_tlds)
  -- Get hosts/full urls
  table.insert(row, urls_urls)
  -- Numeric flags
  table.insert(row, urls_flags)

  -- Emails step
  if task:has_urls(true) then
    local emails = task:get_emails() or {}
    local emails_formatted = {}
    for i,u in ipairs(emails) do
      emails_formatted[i] = string.format('%s@%s', u:get_user(), u:get_host())
    end
    table.insert(row, emails_formatted)
  else
    table.insert(row, {})
  end

  -- ASN information
  local asn, country, ipnet = 0, '--', '--'
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

    -- Groups data
    local groups = task:get_groups()
    local groups_tab = {}
    local gr_scores_tab = {}
    for gr,sc in pairs(groups) do
      table.insert(groups_tab, gr)
      table.insert(gr_scores_tab, sc)
    end
    table.insert(row, groups_tab)
    table.insert(row, gr_scores_tab)
  end

  -- Extra columns
  if #settings.extra_columns > 0 then
    for _,col in ipairs(settings.extra_columns) do
      local elts = col.real_selector(task)

      if elts then
        table.insert(row, elts)
      else
        table.insert(row, col.default_value)
      end
    end
  end

  -- Custom data
  for k,rule in pairs(settings.custom_rules) do
    if not custom_rows[k] then custom_rows[k] = {} end
    table.insert(custom_rows[k], lua_clickhouse.row_to_tsv(rule.get_row(task)))
  end

  local tsv_row = lua_clickhouse.row_to_tsv(row)
  used_memory = used_memory + #tsv_row
  data_rows[#data_rows + 1] = tsv_row
  nrows = nrows + 1
  lua_util.debugm(N, task,
      "add clickhouse row %s / %s; used memory: %s / %s",
      nrows, settings.limits.max_rows,
      used_memory, settings.limits.max_memory)
end

local function do_remove_partition(ev_base, cfg, table_name, partition)
  lua_util.debugm(N, rspamd_config, "removing partition %s.%s", table_name, partition)
  local upstream = settings.upstream:get_upstream_round_robin()
  local remove_partition_sql = "ALTER TABLE ${table_name} ${remove_method} PARTITION '${partition}'"
  local remove_method = (settings.retention.method == 'drop') and 'DROP' or 'DETACH'
  local sql_params = {
    ['table_name']     = table_name,
    ['remove_method']  = remove_method,
    ['partition']   = partition
  }

  local sql = lua_util.template(remove_partition_sql, sql_params)

  local ch_params = {
    body = sql,
    ev_base = ev_base,
    config = cfg,
  }

  local err, _ = lua_clickhouse.generic_sync(upstream, settings, ch_params, sql)
  if err then
    rspamd_logger.errx(rspamd_config,
      "cannot detach partition %s:%s from server %s: %s",
      table_name, partition,
      settings['server'], err)
    return
  end

  rspamd_logger.infox(rspamd_config,
      'detached partition %s:%s on server %s', table_name, partition,
      settings['server'])

end

--[[
  nil   - file is not writable, do not perform removal
  0     - it's time to perform removal
  <int> - how many seconds wait until next run
]]
local function get_last_removal_ago()
  local ts_file = string.format('%s/%s', rspamd_paths['DBDIR'], 'clickhouse_retention_run')
  local last_ts
  local current_ts = os.time()

  local function write_ts_to_file()
    local write_file, err = io.open(ts_file, 'w')
    if err then
      rspamd_logger.errx(rspamd_config, 'Failed to open %s, will not perform retention: %s', ts_file, err)
      return nil
    end

    local res
    res, err = write_file:write(tostring(current_ts))
    if err or res == nil then
      write_file:close()
      rspamd_logger.errx(rspamd_config, 'Failed to write %s, will not perform retention: %s', ts_file, err)
      return nil
    end
    write_file:close()

    return true
  end

  local f, err = io.open(ts_file, 'r')
  if err then
    lua_util.debugm(N, rspamd_config, 'Failed to open %s: %s', ts_file, err)
  else
    last_ts = tonumber(f:read('*number'))
    f:close()
  end

  if last_ts > current_ts then
    -- Clock skew detected, overwrite last_ts with current_ts and wait for the next
    -- retention period
    rspamd_logger.errx(rspamd_config, 'Last collection time is in future: %s; overwrite it with %s in %s',
        last_ts, current_ts, ts_file)
    return write_ts_to_file() and -1
  end

  if last_ts == nil or (last_ts + settings.retention.period) <= current_ts then
    return write_ts_to_file() and 0
  end

  return (last_ts + settings.retention.period) - current_ts
end

local function clickhouse_maybe_send_data_periodic(cfg, ev_base, now)
  local need_collect = false
  local reason

  if nrows == 0 then
    lua_util.debugm(N, cfg, "no need to send data, as there are no rows to collect")
    return settings.check_timeout
  end

  if final_call then
    lua_util.debugm(N, cfg, "no need to send data, final call has been issued")
    return 0
  end

  if settings.limits.max_rows > 0 then
    if nrows > settings.limits.max_rows then
      need_collect = true
      reason = string.format('limit of rows has been reached: %d', nrows)
    end
  end

  if last_collection > 0 and settings.limits.max_interval > 0 then
    if now - last_collection > settings.limits.max_interval then
      need_collect = true
      reason = string.format('limit of time since last collection has been reached: %d seconds passed ' ..
          '(%d seconds trigger)',
          (now - last_collection), settings.limits.max_interval)
    end
  end

  if settings.limits.max_memory > 0 then
    if used_memory >= settings.limits.max_memory then
      need_collect = true
      reason = string.format('limit of memory has been reached: %d bytes used',
          used_memory)
    end
  end

  if last_collection == 0 then
    last_collection = now
  end

  if need_collect then
    -- Do it atomic
    local saved_rows = data_rows
    local saved_custom = custom_rows
    nrows = 0
    last_collection = now
    used_memory = 0
    data_rows = {}
    custom_rows = {}

    clickhouse_send_data(nil, ev_base, reason, saved_rows, saved_custom)

    if settings.collect_garbadge then
      collectgarbage()
    end
  end

  return settings.check_timeout
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
  local partition_to_remove_sql = "SELECT partition, table " ..
      "FROM system.parts WHERE table IN ('${tables}') " ..
      "GROUP BY partition, table " ..
      "HAVING max(max_date) < toDate(now() - interval ${month} month)"

  local table_names = {'rspamd'}
  local tables = table.concat(table_names, "', '")
  local sql_params = {
    tables = tables,
    month  = settings.retention.period_months,
  }
  local sql = lua_util.template(partition_to_remove_sql, sql_params)


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

local function upload_clickhouse_schema(upstream, ev_base, cfg, initial)
  local ch_params = {
    ev_base = ev_base,
    config = cfg,
  }

  local errored = false

  -- Upload a single element of the schema
  local function upload_schema_elt(v)
    if errored then
      rspamd_logger.errx(rspamd_config, "cannot upload schema '%s' on clickhouse server %s: due to previous errors",
          v, upstream:get_addr():to_string(true))
      return
    end
    local sql = v
    local err, reply = lua_clickhouse.generic_sync(upstream, settings, ch_params, sql)

    if err then
      rspamd_logger.errx(rspamd_config, "cannot upload schema '%s' on clickhouse server %s: %s",
          sql, upstream:get_addr():to_string(true), err)
      errored = true
      return
    end
    rspamd_logger.debugm(N, rspamd_config, 'uploaded clickhouse schema element %s to %s: %s',
        v, upstream:get_addr():to_string(true), reply)
  end

  -- Process element and return nil if statement should be skipped
  local function preprocess_schema_elt(v)
    if type(v) == 'string' then
      return lua_util.template(v, {SCHEMA_VERSION = tostring(schema_version)})
    elseif type(v) == 'table' then
      -- Pair of statement + boolean
      if initial == v[2] then
        return lua_util.template(v[1], {SCHEMA_VERSION = tostring(schema_version)})
      else
        rspamd_logger.debugm(N, rspamd_config, 'skip clickhouse schema element %s: schema already exists',
            v)
      end
    end

    return nil
  end

  -- Apply schema elements sequentially, users additions are concatenated to the tail
  fun.each(upload_schema_elt,
    -- Also template schema version
    fun.filter(function(v) return v ~= nil end,
      fun.map(preprocess_schema_elt,
        fun.chain(clickhouse_schema, settings.schema_additions)
      )
    )
  )
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

local function add_extra_columns(upstream, ev_base, cfg)
  local ch_params = {
    ev_base = ev_base,
    config = cfg,
  }
  -- Apply migrations sequentially
  local function columns_recursor(i)
    if i <= #settings.extra_columns  then
      local col = settings.extra_columns[i]
      local prev_column
      if i == 1 then
        prev_column = 'MIMERcpt'
      else
        prev_column = settings.extra_columns[i - 1].name
      end
      local sql = string.format('ALTER TABLE rspamd ADD COLUMN IF NOT EXISTS `%s` %s AFTER `%s`',
          col.name, col.type, prev_column)
      if col.comment then
        sql = sql .. string.format(", COMMENT COLUMN IF EXISTS `%s` '%s'", col.name, col.comment)
      end

      local ret = lua_clickhouse.generic(upstream, settings, ch_params, sql,
          function(_, _)
            rspamd_logger.infox(rspamd_config,
                'added extra column %s (%s) after %s',
                col.name, col.type, prev_column)
            -- Apply the next statement
            columns_recursor(i + 1)
          end ,
          function(_, err)
            rspamd_logger.errx(rspamd_config,
                "cannot apply add column alter %s: '%s' on clickhouse server %s: %s",
                i, sql, upstream:get_addr():to_string(true), err)
          end)
      if not ret then
        rspamd_logger.errx(rspamd_config,
            "cannot apply add column alter %s: '%s' on clickhouse server %s: cannot make request",
            i, sql, upstream:get_addr():to_string(true))
      end
    end
  end

  columns_recursor(1)
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
      upload_clickhouse_schema(upstream, ev_base, cfg, false)
      rspamd_logger.infox(rspamd_config, 'table rspamd exists, check if we need to apply migrations')
      maybe_apply_migrations(upstream, ev_base, cfg, 1)
    else
      -- Upload schema
      rspamd_logger.infox(rspamd_config, 'table rspamd does not exists, upload full schema')
      upload_clickhouse_schema(upstream, ev_base, cfg, true)
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
      local sql = lua_util.template(rule.schema, settings)
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
      rspamd_logger.infox(rspamd_config,
          'table rspamd_version does not exist, check rspamd table')
      check_rspamd_table(upstream, ev_base, cfg)
    else
      rspamd_logger.errx(rspamd_config,
          "cannot get version on clickhouse server %s: %s",
        upstream:get_addr():to_string(true), err)
    end
  else
    upload_clickhouse_schema(upstream, ev_base, cfg, false)
    local version = tonumber(rows[1].v)
    maybe_apply_migrations(upstream, ev_base, cfg, version)
  end

  if #settings.extra_columns > 0 then
    add_extra_columns(upstream, ev_base, cfg)
  end
end

local opts = rspamd_config:get_all_opt('clickhouse')
if opts then
  -- Legacy `limit` options
  if opts.limit and not opts.limits then
    settings.limits.max_rows = opts.limit
  end
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
            rspamd_logger.errx(rspamd_config,
                'invalid get_row (%s) - must be a function',
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
      settings[k] = lua_util.deepcopy(v)
    end
  end

  if not settings['server'] and not settings['servers'] then
    rspamd_logger.infox(rspamd_config, 'no servers are specified, disabling module')
    lua_util.disable_module(N, "config")
  else
    settings['from_map'] = rspamd_map_add('clickhouse', 'from_tables',
        'regexp', 'clickhouse specific domains')

    settings.upstream = upstream_list.create(rspamd_config,
        settings['server'] or settings['servers'], 8123)

    if not settings.upstream then
      rspamd_logger.errx(rspamd_config, 'cannot parse clickhouse address: %s',
          settings['server'] or settings['servers'])
      lua_util.disable_module(N, "config")
      return
    end

    if settings.exceptions then
      local maps_expressions = require "lua_maps_expressions"

      settings.exceptions = maps_expressions.create(rspamd_config,
          settings.exceptions, N)
    end

    if settings.extra_columns then
      -- Check sanity and create selector closures
      local lua_selectors = require "lua_selectors"
      local columns_transformed = {}
      local need_sort = false
      -- Select traverse function depending on what we have
      local iter_func = settings.extra_columns[1] and ipairs or pairs

      for col_name,col_data in iter_func(settings.extra_columns) do
        -- Array based extra columns
        if col_data.name then col_name = col_data.name end
        if not col_data.selector or not col_data.type then
          rspamd_logger.errx(rspamd_config, 'cannot add clickhouse extra row %s: no type or no selector',
              col_name)
        else
          local is_array = false

          if col_data.type:lower():match('^array') then
            is_array = true
          end

          local selector = lua_selectors.create_selector_closure(rspamd_config,
              col_data.selector, col_data.delimiter or '', is_array)

          if not selector then
            rspamd_logger.errx(rspamd_config, 'cannot add clickhouse extra row %s: bad selector: %s',
                col_name, col_data.selector)
          else
            if not col_data.default_value then
              if is_array then
                col_data.default_value = {}
              else
                col_data.default_value = ''
              end
            end
            col_data.real_selector = selector
            if not col_data.name then
              col_data.name = col_name
              need_sort = true
            end
            table.insert(columns_transformed, col_data)
          end
        end
      end

      -- Convert extra columns from a map to an array sorted by column name to
      -- preserve strict order when doing altering
      if need_sort then
        rspamd_logger.infox(rspamd_config, 'sort extra columns as they are not configured as an array')
        table.sort(columns_transformed, function(c1, c2) return c1.name < c2.name end)
      end
      settings.extra_columns = columns_transformed
    end

    rspamd_config:register_symbol({
      name = 'CLICKHOUSE_COLLECT',
      type = 'idempotent',
      callback = clickhouse_collect,
      priority = 10,
      flags = 'empty,explicit_disable,ignore_passthrough',
    })
    rspamd_config:register_finish_script(function(task)
      if nrows > 0 then
        final_call = true
        local saved_rows = data_rows
        local saved_custom = custom_rows

        nrows = 0
        data_rows = {}
        used_memory = 0
        custom_rows = {}

        clickhouse_send_data(task, nil, 'final collection',
            saved_rows, saved_custom)

        if settings.collect_garbadge then
          collectgarbage()
        end
      end
    end)
    -- Create tables on load
    rspamd_config:add_on_load(function(cfg, ev_base, worker)
      if worker:is_scanner() then
        rspamd_config:add_periodic(ev_base, 0,
            clickhouse_maybe_send_data_periodic, true)
      end
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
