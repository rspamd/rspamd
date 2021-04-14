--[[
Copyright (c) 2017-2018, Vsevolod Stakhov <vsevolod@highsecure.ru>

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

if confighelp then
  return
end

-- A generic plugin for reputation handling

local E = {}
local N = 'reputation'

local rspamd_logger = require "rspamd_logger"
local rspamd_util = require "rspamd_util"
local lua_util = require "lua_util"
local lua_maps = require "lua_maps"
local lua_maps_exprs = require "lua_maps_expressions"
local hash = require 'rspamd_cryptobox_hash'
local lua_redis = require "lua_redis"
local fun = require "fun"
local lua_selectors = require "lua_selectors"
local ts = require("tableshape").types

local redis_params = nil
local default_expiry = 864000 -- 10 day by default
local default_prefix = 'RR:' -- Rspamd Reputation

local tanh = math.tanh or rspamd_util.tanh

local reject_threshold = rspamd_config:get_action('reject') or 10.0

-- Get reputation from ham/spam/probable hits
local function generic_reputation_calc(token, rule, mult, task)
  local cfg = rule.selector.config or E

  if cfg.score_calc_func then
    return cfg.score_calc_func(rule, token, mult)
  end

  if tonumber(token[1]) < cfg.lower_bound then
    lua_util.debugm(N, task, "not enough matches %s < %s for rule %s",
        token[1], cfg.lower_bound, rule.symbol)
    return 0
  end

  -- Get average score
  local avg_score = fun.foldl(function(acc, v)
    return acc + v
  end, 0.0, fun.map(tonumber, token[2])) / #token[2]

  -- Apply function tanh(x / reject_score * atanh(0.95) - atanh(0.5))
  --                                        1.83178       0.5493
  local score = tanh(avg_score / reject_threshold * 1.83178 - 0.5493) * mult
  lua_util.debugm(N, task, "got generic average score %s -> %s for rule %s",
      avg_score, score, rule.symbol)
  return score
end

local function add_symbol_score(task, rule, mult, params)
  if not params then params = {tostring(mult)};

  end
  if rule.selector.config.split_symbols then
    if mult >= 0 then
      task:insert_result(rule.symbol .. '_SPAM', mult, params)
    else
      task:insert_result(rule.symbol .. '_HAM', mult, params)
    end
  else
    task:insert_result(rule.symbol, mult, params)
  end
end

local function sub_symbol_score(task, rule, score)
  local function sym_score(sym)
    local s = task:get_symbol(sym)[1]
    return s.score
  end
  if rule.selector.config.split_symbols then
    local spam_sym = rule.symbol .. '_SPAM'
    local ham_sym = rule.symbol .. '_HAM'

    if task:has_symbol(spam_sym) then
      score = score - sym_score(spam_sym)
    elseif task:has_symbol(ham_sym) then
      score = score - sym_score(ham_sym)
    end
  else
    if task:has_symbol(rule.symbol) then
      score = score - sym_score(rule.symbol)
    end
  end

  return score
end

-- Extracts task score and subtracts score of the rule itself
local function extract_task_score(task, rule)
  local lua_verdict = require "lua_verdict"
  local verdict,score = lua_verdict.get_specific_verdict(N, task)

  if not score or verdict == 'passthrough' then return nil end

  return sub_symbol_score(task, rule, score)
end

-- DKIM Selector functions
local gr
local function gen_dkim_queries(task, rule)
  local dkim_trace = (task:get_symbol('DKIM_TRACE') or E)[1]
  local lpeg = require 'lpeg'
  local ret = {}

  if not gr then
    local semicolon = lpeg.P(':')
    local domain = lpeg.C((1 - semicolon)^1)
    local res = lpeg.S'+-?~'

    local function res_to_label(ch)
      if ch == '+' then return 'a'
      elseif ch == '-' then return 'r'
      end

      return 'u'
    end

    gr = domain * semicolon * (lpeg.C(res^1) / res_to_label)
  end

  if dkim_trace and dkim_trace.options then
    for _,opt in ipairs(dkim_trace.options) do
      local dom,res = lpeg.match(gr, opt)

      if dom and res then
        local tld = rspamd_util.get_tld(dom)
        ret[tld] = res
      end
    end
  end

  return ret
end

local function dkim_reputation_filter(task, rule)
  local requests = gen_dkim_queries(task, rule)
  local results = {}
  local nchecked = 0
  local rep_accepted = 0.0
  local rep_rejected = 0.0

  lua_util.debugm(N, task, 'dkim reputation tokens: %s', requests)

  local function tokens_cb(err, token, values)
    nchecked = nchecked + 1

    if values then
      results[token] = values
    end

    if nchecked == #requests then
      for k,v in pairs(results) do
        if requests[k] == 'a' then
          rep_accepted = rep_accepted + generic_reputation_calc(v, rule, 1.0, task)
        elseif requests[k] == 'r' then
          rep_rejected = rep_rejected + generic_reputation_calc(v, rule, 1.0, task)
        end
      end

      -- Set local reputation symbol
      if rep_accepted > 0 or rep_rejected > 0 then
        if rep_accepted > rep_rejected then
          add_symbol_score(task, rule, -(rep_accepted - rep_rejected))
        else
          add_symbol_score(task, rule, (rep_rejected - rep_accepted))
        end

        -- Store results for future DKIM results adjustments
        task:get_mempool():set_variable("dkim_reputation_accept", tostring(rep_accepted))
        task:get_mempool():set_variable("dkim_reputation_reject", tostring(rep_rejected))
      end
    end
  end

  for dom,res in pairs(requests) do
    -- tld + "." + check_result, e.g. example.com.+ - reputation for valid sigs
    local query = string.format('%s.%s', dom, res)
    rule.backend.get_token(task, rule, nil, query, tokens_cb, 'string')
  end
end

local function dkim_reputation_idempotent(task, rule)
  local requests = gen_dkim_queries(task, rule)
  local sc = extract_task_score(task, rule)

  if sc then
    for dom,res in pairs(requests) do
      -- tld + "." + check_result, e.g. example.com.+ - reputation for valid sigs
      local query = string.format('%s.%s', dom, res)
      rule.backend.set_token(task, rule, nil, query, sc)
    end
  end
end

local function dkim_reputation_postfilter(task, rule)
  local sym_accepted = task:get_symbol('R_DKIM_ALLOW')
  local accept_adjustment = task:get_mempool():get_variable("dkim_reputation_accept")

  if sym_accepted and accept_adjustment then
    local final_adjustment = rule.config.max_accept_adjustment *
        rspamd_util.tanh(tonumber(accept_adjustment))
    task:adjust_result('R_DKIM_ALLOW', sym_accepted.score * final_adjustment)
  end

  local sym_rejected = task:get_symbol('R_DKIM_REJECT')
  local reject_adjustment = task:get_mempool():get_variable("dkim_reputation_reject")

  if sym_rejected and reject_adjustment then
    local final_adjustment = rule.config.max_reject_adjustment *
        rspamd_util.tanh(tonumber(reject_adjustment))
    task:adjust_result('R_DKIM_REJECT', sym_rejected.score * final_adjustment)
  end
end

local dkim_selector = {
  config = {
    symbol = 'DKIM_SCORE', -- symbol to be inserted
    lower_bound = 10, -- minimum number of messages to be scored
    min_score = nil,
    max_score = nil,
    outbound = true,
    inbound = true,
    max_accept_adjustment = 2.0, -- How to adjust accepted DKIM score
    max_reject_adjustment = 3.0 -- How to adjust rejected DKIM score
  },
  dependencies = {"DKIM_TRACE"},
  filter = dkim_reputation_filter, -- used to get scores
  postfilter = dkim_reputation_postfilter, -- used to adjust DKIM scores
  idempotent = dkim_reputation_idempotent, -- used to set scores
}

-- URL Selector functions

local function gen_url_queries(task, rule)
  local domains = {}

  fun.each(function(u)
    if u:is_redirected() then
      local redir = u:get_redirected() -- get the original url
      local redir_tld = redir:get_tld()
      if domains[redir_tld] then
        domains[redir_tld] = domains[redir_tld] - 1
      end
    end
    local dom = u:get_tld()
    if not domains[dom] then
      domains[dom] = 1
    else
      domains[dom] = domains[dom] + 1
    end
  end, fun.filter(function(u) return not u:is_html_displayed() end,
    task:get_urls(true)))

  local results = {}
  for k,v in lua_util.spairs(domains,
    function(t, a, b) return t[a] > t[b] end, rule.selector.config.max_urls) do
    if v > 0 then
      table.insert(results, {k,v})
    end
  end

  return results
end

local function url_reputation_filter(task, rule)
  local requests = gen_url_queries(task, rule)
  local results = {}
  local nchecked = 0

  local function indexed_tokens_cb(err, index, values)
    nchecked = nchecked + 1

    if values then
      results[index] = values
    end

    if nchecked == #requests then
      -- Check the url with maximum hits
      local mhits = 0
      for k,_ in pairs(results) do
        if requests[k][2] > mhits then
          mhits = requests[k][2]
        end
      end

      if mhits > 0 then
        local score = 0
        for k,v in pairs(results) do
          score = score + generic_reputation_calc(v, rule,
              requests[k][2] / mhits, task)
        end

        if math.abs(score) > 1e-3 then
          -- TODO: add description
          add_symbol_score(task, rule, score)
        end
      end
    end
  end

  for i,req in ipairs(requests) do
    local function tokens_cb(err, token, values)
      indexed_tokens_cb(err, i, values)
    end

    rule.backend.get_token(task, rule, nil, req[1], tokens_cb, 'string')
  end
end

local function url_reputation_idempotent(task, rule)
  local requests = gen_url_queries(task, rule)
  local sc = extract_task_score(task, rule)

  if sc then
    for _,tld in ipairs(requests) do
      rule.backend.set_token(task, rule, nil, tld[1], sc)
    end
  end
end

local url_selector = {
  config = {
    symbol = 'URL_SCORE', -- symbol to be inserted
    lower_bound = 10, -- minimum number of messages to be scored
    min_score = nil,
    max_score = nil,
    max_urls = 10,
    check_from = true,
    outbound = true,
    inbound = true,
  },
  filter = url_reputation_filter, -- used to get scores
  idempotent = url_reputation_idempotent -- used to set scores
}
-- IP Selector functions

local function ip_reputation_init(rule)
  local cfg = rule.selector.config

  if cfg.asn_cc_whitelist then
    cfg.asn_cc_whitelist = rspamd_map_add('reputation',
      'asn_cc_whitelist',
      'map',
      'IP score whitelisted ASNs/countries')
  end

  return true
end

local function ip_reputation_filter(task, rule)

  local ip = task:get_from_ip()

  if not ip or not ip:is_valid() then return end
  if lua_util.is_rspamc_or_controller(task) then return end

  local cfg = rule.selector.config

  if ip:get_version() == 4 and cfg.ipv4_mask then
    ip = ip:apply_mask(cfg.ipv4_mask)
  elseif cfg.ipv6_mask then
    ip = ip:apply_mask(cfg.ipv6_mask)
  end

  local pool = task:get_mempool()
  local asn = pool:get_variable("asn")
  local country = pool:get_variable("country")

  if country and cfg.asn_cc_whitelist then
    if cfg.asn_cc_whitelist:get_key(country) then
      return
    end
    if asn and cfg.asn_cc_whitelist:get_key(asn) then
      return
    end
  end

  -- These variables are used to define if we have some specific token
  local has_asn = not asn
  local has_country = not country
  local has_ip = false

  local asn_stats, country_stats, ip_stats

  local function ipstats_check()
    local score = 0.0
    local description_t = {}

    if asn_stats then
      local asn_score = generic_reputation_calc(asn_stats, rule, cfg.scores.asn, task)
      score = score + asn_score
      table.insert(description_t, string.format('asn: %s(%.2f)',
              asn, asn_score))
    end
    if country_stats then
      local country_score = generic_reputation_calc(country_stats, rule,
          cfg.scores.country, task)
      score = score + country_score
      table.insert(description_t, string.format('country: %s(%.2f)',
              country, country_score))
    end
    if ip_stats then
      local ip_score = generic_reputation_calc(ip_stats, rule, cfg.scores.ip,
        task)
      score = score + ip_score
      table.insert(description_t, string.format('ip: %s(%.2f)',
              tostring(ip), ip_score))
    end

    if math.abs(score) > 0.001 then
      add_symbol_score(task, rule, score, table.concat(description_t, ', '))
    end
  end

  local function gen_token_callback(what)
    return function(err, _, values)
      if not err and values then
        if what == 'asn' then
          has_asn = true
          asn_stats = values
        elseif what == 'country' then
          has_country = true
          country_stats = values
        elseif what == 'ip' then
          has_ip = true
          ip_stats = values
        end
      else
        if what == 'asn' then
          has_asn = true
        elseif what == 'country' then
          has_country = true
        elseif what == 'ip' then
          has_ip = true
        end
      end

      if has_asn and has_country and has_ip then
        -- Check reputation
        ipstats_check()
      end
    end
  end

  if asn then
    rule.backend.get_token(task, rule, cfg.asn_prefix, asn,
            gen_token_callback('asn'), 'string')
  end
  if country then
    rule.backend.get_token(task, rule, cfg.country_prefix, country,
            gen_token_callback('country'), 'string')
  end

  rule.backend.get_token(task, rule, cfg.ip_prefix, ip,
          gen_token_callback('ip'), 'ip')
end

-- Used to set scores
local function ip_reputation_idempotent(task, rule)
  if not rule.backend.set_token then return end -- Read only backend
  local ip = task:get_from_ip()
  local cfg = rule.selector.config

  if not ip or not ip:is_valid() then return end

  if lua_util.is_rspamc_or_controller(task) then return end

  if ip:get_version() == 4 and cfg.ipv4_mask then
    ip = ip:apply_mask(cfg.ipv4_mask)
  elseif cfg.ipv6_mask then
    ip = ip:apply_mask(cfg.ipv6_mask)
  end

  local pool = task:get_mempool()
  local asn = pool:get_variable("asn")
  local country = pool:get_variable("country")

  if country and cfg.asn_cc_whitelist then
    if cfg.asn_cc_whitelist:get_key(country) then
      return
    end
    if asn and cfg.asn_cc_whitelist:get_key(asn) then
      return
    end
  end
  local sc = extract_task_score(task, rule)
  if sc then
    if asn then
      rule.backend.set_token(task, rule, cfg.asn_prefix, asn, sc, nil, 'string')
    end
    if country then
      rule.backend.set_token(task, rule, cfg.country_prefix, country, sc, nil, 'string')
    end

    rule.backend.set_token(task, rule, cfg.ip_prefix, ip, sc, nil, 'ip')
  end
end

-- Selectors are used to extract reputation tokens
local ip_selector = {
  config = {
    scores = { -- how each component is evaluated
      ['asn'] = 0.4,
      ['country'] = 0.01,
      ['ip'] = 1.0
    },
    symbol = 'SENDER_REP', -- symbol to be inserted
    split_symbols = true,
    asn_prefix = 'a:', -- prefix for ASN hashes
    country_prefix = 'c:', -- prefix for country hashes
    ip_prefix = 'i:',
    lower_bound = 10, -- minimum number of messages to be scored
    min_score = nil,
    max_score = nil,
    score_divisor = 1,
    outbound = false,
    inbound = true,
    ipv4_mask = 32, -- Mask bits for ipv4
    ipv6_mask = 64, -- Mask bits for ipv6
  },
  --dependencies = {"ASN"}, -- ASN is a prefilter now...
  init = ip_reputation_init,
  filter = ip_reputation_filter, -- used to get scores
  idempotent = ip_reputation_idempotent, -- used to set scores
}

-- SPF Selector functions

local function spf_reputation_filter(task, rule)
  local spf_record = task:get_mempool():get_variable('spf_record')
  local spf_allow = task:has_symbol('R_SPF_ALLOW')

  -- Don't care about bad/missing spf
  if not spf_record or not spf_allow then return end

  local cr = require "rspamd_cryptobox_hash"
  local hkey = cr.create(spf_record):base32():sub(1, 32)

  lua_util.debugm(N, task, 'check spf record %s -> %s', spf_record, hkey)

  local function tokens_cb(err, token, values)
    if values then
      local score = generic_reputation_calc(values, rule, 1.0, task)

      if math.abs(score) > 1e-3 then
        -- TODO: add description
        add_symbol_score(task, rule, score)
      end
    end
  end

  rule.backend.get_token(task, rule, nil, hkey, tokens_cb, 'string')
end

local function spf_reputation_idempotent(task, rule)
  local sc = extract_task_score(task, rule)
  local spf_record = task:get_mempool():get_variable('spf_record')
  local spf_allow = task:has_symbol('R_SPF_ALLOW')

  if not spf_record or not spf_allow or not sc then return end

  local cr = require "rspamd_cryptobox_hash"
  local hkey = cr.create(spf_record):base32():sub(1, 32)

  lua_util.debugm(N, task, 'set spf record %s -> %s = %s',
      spf_record, hkey, sc)
  rule.backend.set_token(task, rule, nil, hkey, sc)
end


local spf_selector = {
  config = {
    symbol = 'SPF_REP', -- symbol to be inserted
    split_symbols = true,
    lower_bound = 10, -- minimum number of messages to be scored
    min_score = nil,
    max_score = nil,
    outbound = true,
    inbound = true,
    max_accept_adjustment = 2.0, -- How to adjust accepted DKIM score
    max_reject_adjustment = 3.0 -- How to adjust rejected DKIM score
  },
  dependencies = {"R_SPF_ALLOW"},
  filter = spf_reputation_filter, -- used to get scores
  idempotent = spf_reputation_idempotent, -- used to set scores
}

-- Generic selector based on lua_selectors framework

local function generic_reputation_init(rule)
  local cfg = rule.selector.config

  if not cfg.selector then
    rspamd_logger.errx(rspamd_config, 'cannot configure generic rule: no selector specified')
    return false
  end

  local selector = lua_selectors.create_selector_closure(rspamd_config,
      cfg.selector, cfg.delimiter)

  if not selector then
    rspamd_logger.errx(rspamd_config, 'cannot configure generic rule: bad selector: %s',
        cfg.selector)
    return false
  end

  cfg.selector = selector -- Replace with closure

  if cfg.whitelist then
    cfg.whitelist = lua_maps.map_add('reputation',
        'generic_whitelist',
        'map',
        'Whitelisted selectors')
  end

  return true
end

local function generic_reputation_filter(task, rule)
  local cfg = rule.selector.config
  local selector_res = cfg.selector(task)

  local function tokens_cb(err, token, values)
    if values then
      local score = generic_reputation_calc(values, rule, 1.0, task)

      if math.abs(score) > 1e-3 then
        -- TODO: add description
        add_symbol_score(task, rule, score)
      end
    end
  end

  if selector_res then
    if type(selector_res) == 'table' then
      fun.each(function(e)
        lua_util.debugm(N, task, 'check generic reputation (%s) %s',
          rule['symbol'], e)
        rule.backend.get_token(task, rule, nil, e, tokens_cb, 'string')
      end, selector_res)
    else
      lua_util.debugm(N, task, 'check generic reputation (%s) %s',
        rule['symbol'], selector_res)
      rule.backend.get_token(task, rule, nil, selector_res, tokens_cb, 'string')
    end
  end
end

local function generic_reputation_idempotent(task, rule)
  local sc = extract_task_score(task, rule)
  local cfg = rule.selector.config

  local selector_res = cfg.selector(task)
  if not selector_res then return end

  if sc then
    if type(selector_res) == 'table' then
      fun.each(function(e)
        lua_util.debugm(N, task, 'set generic selector (%s) %s = %s',
            rule['symbol'], e, sc)
        rule.backend.set_token(task, rule, nil, e, sc)
      end, selector_res)
    else
      lua_util.debugm(N, task, 'set generic selector (%s) %s = %s',
          rule['symbol'], selector_res, sc)
      rule.backend.set_token(task, rule, nil, selector_res, sc)
    end
  end
end


local generic_selector = {
  schema = ts.shape{
    lower_bound = ts.number + ts.string / tonumber,
    max_score = ts.number:is_optional(),
    min_score = ts.number:is_optional(),
    outbound = ts.boolean,
    inbound = ts.boolean,
    selector = ts.string,
    delimiter = ts.string,
    whitelist = ts.one_of(lua_maps.map_schema, lua_maps_exprs.schema):is_optional(),
  },
  config = {
    lower_bound = 10, -- minimum number of messages to be scored
    min_score = nil,
    max_score = nil,
    outbound = true,
    inbound = true,
    selector = nil,
    delimiter = ':',
    whitelist = nil
  },
  init = generic_reputation_init,
  filter = generic_reputation_filter, -- used to get scores
  idempotent = generic_reputation_idempotent -- used to set scores
}



local selectors = {
  ip = ip_selector,
  sender = ip_selector, -- Better name
  url = url_selector,
  dkim = dkim_selector,
  spf = spf_selector,
  generic = generic_selector
}

local function reputation_dns_init(rule, _, _, _)
  if not rule.backend.config.list then
    rspamd_logger.errx(rspamd_config, "rule %s with DNS backend has no `list` parameter defined",
      rule.symbol)
    return false
  end

  return true
end


local function gen_token_key(prefix, token, rule)
  if prefix then
    token = prefix .. token
  end
  local res = token
  if rule.backend.config.hashed then
    local hash_alg = rule.backend.config.hash_alg or "blake2"
    local encoding = "base32"

    if rule.backend.config.hash_encoding then
      encoding = rule.backend.config.hash_encoding
    end

    local h = hash.create_specific(hash_alg, res)
    if encoding == 'hex' then
      res = h:hex()
    elseif encoding == 'base64' then
      res = h:base64()
    else
      res = h:base32()
    end
  end

  if rule.backend.config.hashlen then
    res = string.sub(res, 1, rule.backend.config.hashlen)
  end

  if rule.backend.config.prefix then
    res = rule.backend.config.prefix .. res
  end

  return res
end

--[[
-- Generic interface for get and set tokens functions:
-- get_token(task, rule, prefix, token, continuation, token_type), where `continuation` is the following function:
--
-- function(err, token, values) ... end
-- `err`: string value for error (similar to redis or DNS callbacks)
-- `token`: string value of a token
-- `values`: table of key=number, parsed from backend. It is selector's duty
--  to deal with missing, invalid or other values
--
-- set_token(task, rule, token, values, continuation_cb)
-- This function takes values, encodes them using whatever suitable format
-- and calls for continuation:
--
-- function(err, token) ... end
-- `err`: string value for error (similar to redis or DNS callbacks)
-- `token`: string value of a token
--
-- example of tokens: {'s': 0, 'h': 0, 'p': 1}
--]]

local function reputation_dns_get_token(task, rule, prefix, token, continuation_cb, token_type)
  -- local r = task:get_resolver()
  -- In DNS we never ever use prefix as prefix, we use if as a suffix!
  if token_type == 'ip' then
    token = table.concat(token:inversed_str_octets(), '.')
  end

  local key = gen_token_key(nil, token, rule)
  local dns_name = key .. '.' .. rule.backend.config.list

  if prefix then
    dns_name = string.format('%s.%s.%s', key, prefix,
            rule.backend.config.list)
  else
    dns_name = string.format('%s.%s', key, rule.backend.config.list)
  end

  local function dns_cb(_, _, results, err)
    if err and (err ~= 'requested record is not found' and
        err ~= 'no records with this name') then
      rspamd_logger.warnx(task, 'error looking up %s: %s', dns_name, err)
    end

    lua_util.debugm(N, task, 'DNS RESPONSE: label=%1 results=%2 err=%3 list=%4',
        dns_name, results, err, rule.backend.config.list)

    -- Now split tokens to list of values
    if results and results[1]  then
      -- Format: num_messages;sc1;sc2...scn
      local dns_tokens = lua_util.rspamd_str_split(results[1], ";")
      -- Convert all to numbers excluding any possible non-numbers
      dns_tokens = fun.totable(fun.filter(function(e)
        return type(e) == 'number'
      end,
      fun.map(function(e)
        local n = tonumber(e)
        if n then return n end
        return "BAD"
      end, dns_tokens)))

      if #dns_tokens < 2 then
        rspamd_logger.warnx(task, 'cannot parse response for reputation token %s: %s',
                dns_name, results[1])
        continuation_cb(results, dns_name, nil)
      else
        local cnt = table.remove(dns_tokens, 1)
        continuation_cb(nil, dns_name, { cnt, dns_tokens })
      end
    else
      rspamd_logger.messagex(task, 'invalid response for reputation token %s: %s',
              dns_name, results[1])
      continuation_cb(results, dns_name, nil)
    end
  end

 task:get_resolver():resolve_a({
    task = task,
    name = dns_name,
    callback = dns_cb,
    forced = true,
  })
end

local function reputation_redis_init(rule, cfg, ev_base, worker)
  local our_redis_params = {}

  our_redis_params = lua_redis.try_load_redis_servers(rule.backend.config, rspamd_config,
      true)
  if not our_redis_params then
    our_redis_params = redis_params
  end
  if not our_redis_params then
    rspamd_logger.errx(rspamd_config, 'cannot init redis for reputation rule: %s',
        rule)
    return false
  end
  -- Init scripts for buckets
  -- Redis script to extract data from Redis buckets
  -- KEYS[1] - key to extract
  -- Value returned - table of scores as a strings vector + number of scores
  local redis_get_script_tpl = [[
  local cnt = redis.call('HGET', KEYS[1], 'n')
  local results = {}
  if cnt then
  {% for w in windows %}
  local sc = tonumber(redis.call('HGET', KEYS[1], 'v' .. '{= w.name =}'))
  table.insert(results, tostring(sc * {= w.mult =}))
  {% endfor %}
  else
  {% for w in windows %}
  table.insert(results, '0')
  {% endfor %}
  end

  return {cnt or 0, results}
  ]]

  local get_script = lua_util.jinja_template(redis_get_script_tpl,
      {windows = rule.backend.config.buckets})
  rspamd_logger.debugm(N, rspamd_config, 'added extraction script %s', get_script)
  rule.backend.script_get = lua_redis.add_redis_script(get_script, our_redis_params)

  -- Redis script to update Redis buckets
  -- KEYS[1] - key to update
  -- KEYS[2] - current time in milliseconds
  -- KEYS[3] - message score
  -- KEYS[4] - expire for a bucket
  -- Value returned - table of scores as a strings vector
  local redis_adaptive_emea_script_tpl = [[
  local last = redis.call('HGET', KEYS[1], 'l')
  local score = tonumber(KEYS[3])
  local now = tonumber(KEYS[2])
  local scores = {}

  if last then
    {% for w in windows %}
    local last_value = tonumber(redis.call('HGET', KEYS[1], 'v' .. '{= w.name =}'))
    local window = {= w.time =}
    -- Adjust alpha
    local time_diff = now - last
    if time_diff < 0 then
      time_diff = 0
    end
    local alpha = 1.0 - math.exp((-time_diff) / (1000 * window))
    local nscore = alpha * score + (1.0 - alpha) * last_value
    table.insert(scores, tostring(nscore * {= w.mult =}))
    {% endfor %}
  else
    {% for w in windows %}
    table.insert(scores, tostring(score * {= w.mult =}))
    {% endfor %}
  end

  local i = 1
  {% for w in windows %}
    redis.call('HSET', KEYS[1], 'v' .. '{= w.name =}', scores[i])
    i = i + 1
  {% endfor %}
  redis.call('HSET', KEYS[1], 'l', now)
  redis.call('HINCRBY', KEYS[1], 'n', 1)
  redis.call('EXPIRE', KEYS[1], tonumber(KEYS[4]))

  return scores
]]

  local set_script = lua_util.jinja_template(redis_adaptive_emea_script_tpl,
      {windows = rule.backend.config.buckets})
  rspamd_logger.debugm(N, rspamd_config, 'added emea update script %s', set_script)
  rule.backend.script_set = lua_redis.add_redis_script(set_script, our_redis_params)

  return true
end

local function reputation_redis_get_token(task, rule, prefix, token, continuation_cb, token_type)
  if token_type and token_type == 'ip' then
    token = tostring(token)
  end
  local key = gen_token_key(prefix, token, rule)

  local function redis_get_cb(err, data)
    if data then
      if type(data) == 'table' then
        lua_util.debugm(N, task, 'rule %s - got values for key %s -> %s',
            rule['symbol'], key, data)
        continuation_cb(nil, key, data)
      else
        rspamd_logger.errx(task, 'rule %s - invalid type while getting reputation keys %s: %s',
          rule['symbol'], key, type(data))
        continuation_cb("invalid type", key, nil)
      end

    elseif err then
      rspamd_logger.errx(task, 'rule %s - got error while getting reputation keys %s: %s',
        rule['symbol'], key, err)
      continuation_cb(err, key, nil)
    else
      rspamd_logger.errx(task, 'rule %s - got error while getting reputation keys %s: %s',
        rule['symbol'], key, "unknown error")
      continuation_cb("unknown error", key, nil)
    end
  end

  local ret = lua_redis.exec_redis_script(rule.backend.script_get,
      {task = task, is_write = false},
      redis_get_cb,
      {key})
  if not ret then
    rspamd_logger.errx(task, 'cannot make redis request to check results')
  end
end

local function reputation_redis_set_token(task, rule, prefix, token, sc, continuation_cb, token_type)
  if token_type and token_type == 'ip' then
    token = tostring(token)
  end
  local key = gen_token_key(prefix, token, rule)

  local function redis_set_cb(err, data)
    if err then
      rspamd_logger.errx(task, 'rule %s - got error while setting reputation keys %s: %s',
        rule['symbol'], key, err)
      if continuation_cb then
        continuation_cb(err, key)
      end
    else
      if continuation_cb then
        continuation_cb(nil, key)
      end
    end
  end

  lua_util.debugm(N, task, 'rule %s - set values for key %s -> %s',
      rule['symbol'], key, sc)
  local ret = lua_redis.exec_redis_script(rule.backend.script_set,
      {task = task, is_write = true},
      redis_set_cb,
      {key, tostring(os.time() * 1000),
       tostring(sc),
       tostring(rule.backend.config.expiry)})
  if not ret then
    rspamd_logger.errx(task, 'got error while connecting to redis')
  end
end

--[[ Backends are responsible for getting reputation tokens
  -- Common config options:
  -- `hashed`: if `true` then apply hash function to the key
  -- `hash_alg`: use specific hash type (`blake2` by default)
  -- `hash_len`: strip hash to this amount of bytes (no strip by default)
  -- `hash_encoding`: use specific hash encoding (base32 by default)
--]]
local backends = {
  redis = {
    schema = ts.shape({
      prefix = ts.string,
      expiry = ts.number + ts.string / lua_util.parse_time_interval,
      buckets = ts.array_of(ts.shape{
        time = ts.number + ts.string / lua_util.parse_time_interval,
        name = ts.string,
        mult = ts.number + ts.string / tonumber
      }),
    }, {extra_fields = lua_redis.config_schema}),
    config = {
      expiry = default_expiry,
      prefix = default_prefix,
      buckets = {
        {
          time = 60 * 60 * 24 * 30,
          name = '1m',
          mult = 1.0,
        }
      }, -- What buckets should be used, default 1h and 1month
    },
    init = reputation_redis_init,
    get_token = reputation_redis_get_token,
    set_token = reputation_redis_set_token,
  },
  dns = {
    schema = ts.shape{
      list = ts.string,
    },
    config = {
      -- list = rep.example.com
    },
    get_token = reputation_dns_get_token,
    -- No set token for DNS
    init = reputation_dns_init,
  }
}

local function is_rule_applicable(task, rule)
  local ip = task:get_from_ip()
  if not (rule.selector.config.outbound and rule.selector.config.inbound) then
    if rule.selector.config.outbound then
      if not (task:get_user() or (ip and ip:is_local())) then
        return false
      end
    elseif rule.selector.config.inbound then
      if task:get_user() or (ip and ip:is_local()) then
        return false
      end
    end
  end

  if rule.config.whitelist_map then
    if rule.config.whitelist_map:process(task) then
      return false
    end
  end

  return true
end

local function reputation_filter_cb(task, rule)
  if (is_rule_applicable(task, rule)) then
    rule.selector.filter(task, rule, rule.backend)
  end
end

local function reputation_postfilter_cb(task, rule)
  if (is_rule_applicable(task, rule)) then
    rule.selector.postfilter(task, rule, rule.backend)
  end
end

local function reputation_idempotent_cb(task, rule)
  if (is_rule_applicable(task, rule)) then
    rule.selector.idempotent(task, rule, rule.backend)
  end
end

local function callback_gen(cb, rule)
  return function(task)
    if rule.enabled then
      cb(task, rule)
    end
  end
end

local function parse_rule(name, tbl)
  local sel_type,sel_conf = fun.head(tbl.selector)
  local selector = selectors[sel_type]

  if not selector then
    rspamd_logger.errx(rspamd_config, "unknown selector defined for rule %s: %s", name,
        sel_type)
    return
  end

  local bk_type,bk_conf = fun.head(tbl.backend)

  local backend = backends[bk_type]
  if not backend then
    rspamd_logger.errx(rspamd_config, "unknown backend defined for rule %s: %s", name,
      tbl.backend.type)
    return
  end
  -- Allow config override
  local rule = {
    selector = lua_util.shallowcopy(selector),
    backend = lua_util.shallowcopy(backend),
    config = {}
  }

  -- Override default config params
  rule.backend.config = lua_util.override_defaults(rule.backend.config, bk_conf)
  if backend.schema then
    local checked,schema_err = backend.schema:transform(rule.backend.config)
    if not checked then
      rspamd_logger.errx(rspamd_config, "cannot parse backend config for %s: %s",
          sel_type, schema_err)

      return
    end

    rule.backend.config = checked
  end

  rule.selector.config = lua_util.override_defaults(rule.selector.config, sel_conf)
  if selector.schema then
    local checked,schema_err = selector.schema:transform(rule.selector.config)

    if not checked then
      rspamd_logger.errx(rspamd_config, "cannot parse selector config for %s: %s (%s)",
          sel_type,
          schema_err, sel_conf)
      return
    end

    rule.selector.config = checked
  end
  -- Generic options
  tbl.selector = nil
  tbl.backend = nil
  rule.config = lua_util.override_defaults(rule.config, tbl)

  if rule.config.whitelist then
    if lua_maps_exprs.schema(rule.config.whitelist) then
      rule.config.whitelist_map = lua_maps_exprs.create(rspamd_config,
          rule.config.whitelist, N)
    elseif lua_maps.map_schema(rule.config.whitelist) then
      local map = lua_maps.map_add_from_ucl(rule.config.whitelist,
          'radix',
          sel_type .. ' reputation whitelist')

      if not map then
        rspamd_logger.errx(rspamd_config, "cannot parse whitelist map config for %s: (%s)",
            sel_type,
            rule.config.whitelist)
        return
      end

      rule.config.whitelist_map = {
        process = function(_, task)
          -- Hack: we assume that it is an ip whitelist :(
          local ip = task:get_from_ip()

          if ip and map:get_key(ip) then return true end
          return false
        end
      }
    else
      rspamd_logger.errx(rspamd_config, "cannot parse whitelist map config for %s: (%s)",
          sel_type,
          rule.config.whitelist)
      return
    end
  end

  local symbol = rule.selector.config.symbol or name
  if tbl.symbol then
    symbol = tbl.symbol
  end

  rule.symbol = symbol
  rule.enabled = true
  if rule.selector.init then
    rule.enabled = false
  end
  if rule.backend.init then
    rule.enabled = false
  end
  -- Perform additional initialization if needed
  rspamd_config:add_on_load(function(cfg, ev_base, worker)
    if rule.selector.init then
      if not rule.selector.init(rule, cfg, ev_base, worker) then
        rule.enabled = false
        rspamd_logger.errx(rspamd_config, 'Cannot init selector %s (backend %s) for symbol %s',
            sel_type, bk_type, rule.symbol)
      else
        rule.enabled = true
      end
    end
    if rule.backend.init then
      if not rule.backend.init(rule, cfg, ev_base, worker) then
        rule.enabled = false
        rspamd_logger.errx(rspamd_config, 'Cannot init backend (%s) for rule %s for symbol %s',
            bk_type, sel_type, rule.symbol)
      else
        rule.enabled = true
      end
    end

    if rule.enabled then
      rspamd_logger.infox(rspamd_config, 'Enable %s (%s backend) rule for symbol %s (split symbols: %s)',
          sel_type, bk_type, rule.symbol,
          rule.selector.config.split_symbols)
    end
  end)

  -- We now generate symbol for checking
  local rule_type = 'normal'
  if rule.selector.config.split_symbols then
    rule_type = 'callback'
  end

  local id = rspamd_config:register_symbol{
    name = rule.symbol,
    type = rule_type,
    callback = callback_gen(reputation_filter_cb, rule),
  }

  if rule.selector.config.split_symbols then
    rspamd_config:register_symbol{
      name = rule.symbol .. '_HAM',
      type = 'virtual',
      parent = id,
    }
    rspamd_config:register_symbol{
      name = rule.symbol .. '_SPAM',
      type = 'virtual',
      parent = id,
    }
  end

  if rule.selector.dependencies then
    fun.each(function(d)
      rspamd_config:register_dependency(symbol, d)
    end, rule.selector.dependencies)
  end

  if rule.selector.postfilter then
    -- Also register a postfilter
    rspamd_config:register_symbol{
      name = rule.symbol .. '_POST',
      type = 'postfilter',
      flags = 'nostat',
      callback = callback_gen(reputation_postfilter_cb, rule),
    }
  end

  if rule.selector.idempotent then
    -- Has also idempotent component (e.g. saving data to the backend)
    rspamd_config:register_symbol{
      name = rule.symbol .. '_IDEMPOTENT',
      type = 'idempotent',
      callback = callback_gen(reputation_idempotent_cb, rule),
    }
  end

end

redis_params = lua_redis.parse_redis_server('reputation')
local opts = rspamd_config:get_all_opt("reputation")

-- Initialization part
if not (opts and type(opts) == 'table') then
  rspamd_logger.infox(rspamd_config, 'Module is unconfigured')
  return
end

if opts['rules'] then
  for k,v in pairs(opts['rules']) do
    if not ((v or E).selector) then
      rspamd_logger.errx(rspamd_config, "no selector defined for rule %s", k)
    else
      parse_rule(k, v)
    end
  end
else
  lua_util.disable_module(N, "config")
end
