--[[
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
]] --

if confighelp then
  return
end

-- Multimap is rspamd module designed to define and operate with different maps

local rules = {}
local rspamd_logger = require "rspamd_logger"
local rspamd_util = require "rspamd_util"
local rspamd_regexp = require "rspamd_regexp"
local rspamd_expression = require "rspamd_expression"
local rspamd_ip = require "rspamd_ip"
local lua_util = require "lua_util"
local lua_selectors = require "lua_selectors"
local lua_maps = require "lua_maps"
local lua_mime = require "lua_mime"
local redis_params
local fun = require "fun"
local N = 'multimap'

-- SpamAssassin-like functionality
local sa_atoms = {}
local sa_scores = {}
local sa_meta_rules = {}
local sa_descriptions = {}

-- Symbol state tracking for graceful map reloads
-- States: 'available', 'loading', 'orphaned'
local regexp_rules_symbol_states = {}

local multimap_grammar
-- Parse result in form: <symbol>:<score>|<symbol>|<score>
local function parse_multimap_value(parse_rule, p_ret)
  if p_ret and type(p_ret) == 'string' then
    local lpeg = require "lpeg"

    if not multimap_grammar then
      local number = {}

      local digit = lpeg.R("09")
      number.integer = (lpeg.S("+-") ^ -1) *
          (digit ^ 1)

      -- Matches: .6, .899, .9999873
      number.fractional = (lpeg.P(".")) *
          (digit ^ 1)

      -- Matches: 55.97, -90.8, .9
      number.decimal = (number.integer * -- Integer
          (number.fractional ^ -1)) + -- Fractional
          (lpeg.S("+-") * number.fractional) -- Completely fractional number

      local sym_start = lpeg.R("az", "AZ") + lpeg.S("_")
      local sym_elt = sym_start + lpeg.R("09")
      local symbol = sym_start * sym_elt ^ 0
      local symbol_cap = lpeg.Cg(symbol, 'symbol')
      local score_cap = lpeg.Cg(number.decimal, 'score')
      local opts_cap = lpeg.Cg(lpeg.Ct(lpeg.C(symbol) * (lpeg.P(",") * lpeg.C(symbol)) ^ 0), 'opts')
      local symscore_cap = (symbol_cap * lpeg.P(":") * score_cap)
      local symscoreopt_cap = symscore_cap * lpeg.P(":") * opts_cap
      local grammar = symscoreopt_cap + symscore_cap + symbol_cap + score_cap
      multimap_grammar = lpeg.Ct(grammar)
    end
    local tbl = multimap_grammar:match(p_ret)

    if tbl then
      local sym
      local score = 1.0
      local opts = {}

      if tbl.symbol then
        sym = tbl.symbol
      end
      if tbl.score then
        score = tonumber(tbl.score)
      end
      if tbl.opts then
        opts = tbl.opts
      end

      return true, sym, score, opts
    else
      if p_ret ~= '' then
        rspamd_logger.infox(rspamd_config, '%s: cannot parse string "%s"',
            parse_rule.symbol, p_ret)
      end

      return true, nil, 1.0, {}
    end
  elseif type(p_ret) == 'boolean' then
    return p_ret, nil, 1.0, {}
  end

  return false, nil, 0.0, {}
end

-- SpamAssassin-like line processing functions
local function split_sa_line(str)
  local result = {}
  if not str then
    return result
  end

  for token in string.gmatch(str, '%S+') do
    table.insert(result, token)
  end

  return result
end

local function parse_sa_regexp(rule_symbol, re_expr)
  -- Extract regexp and flags from /regexp/flags format
  local re_str, flags = string.match(re_expr, '^/(.+)/([gimxsiu]*)$')
  if not re_str then
    re_str, flags = string.match(re_expr, '^m{(.+)}([gimxsiu]*)$')
  end
  if not re_str then
    -- Try without delimiters
    re_str = re_expr
    flags = ''
  end

  if flags and flags ~= '' then
    re_str = '(?' .. flags .. ')' .. re_str
  end

  local re = rspamd_regexp.create(re_str)
  if not re then
    rspamd_logger.errx(rspamd_config, 'cannot create regexp for %s: %s', rule_symbol, re_expr)
    return nil
  end

  return re
end

local function words_to_sa_re(words, start)
  return table.concat(fun.totable(fun.drop_n(start, words)), " ")
end

-- Helper function to create SA rule callbacks
local function create_sa_atom_function(name, re, match_type, opts)
  return function(task)
    if not re then
      rspamd_logger.errx(task, 're is missing for atom %s', name)
      return 0
    end

    local function process_re_match(re_obj, tsk, re_type, header, strong)
      local res = 0
      if type(jit) == 'table' then
        res = tsk:process_regexp(re_obj, re_type, header, strong)
      else
        res = tsk:process_regexp(re_obj, re_type, header, strong)
      end
      return res
    end

    local ret = 0

    if match_type == 'header' then
      ret = process_re_match(re, task, 'header', opts.header, opts.strong or false)
    elseif match_type == 'body' then
      ret = process_re_match(re, task, 'sabody')
    elseif match_type == 'rawbody' then
      ret = process_re_match(re, task, 'sarawbody')
    elseif match_type == 'full' then
      ret = process_re_match(re, task, 'body')
    elseif match_type == 'uri' then
      ret = process_re_match(re, task, 'url')
    else
      -- Default to body
      ret = process_re_match(re, task, 'sabody')
    end

    if opts and opts.negate then
      -- Negate the result for !~ operators
      ret = (ret > 0) and 0 or 1
      lua_util.debugm(N, task, 'SA atom %s negated result: %s', name, ret)
    end

    lua_util.debugm(N, task, 'SA atom %s result: %s', name, ret)
    return ret
  end
end

local function process_sa_line(rule, line)
  line = lua_util.str_trim(line)

  if string.len(line) == 0 or string.sub(line, 1, 1) == '#' then
    return
  end

  -- Add debug logging
  lua_util.debugm(N, rspamd_config, 'Processing SA line for rule %s: %s', rule.symbol, line)

  local words = split_sa_line(line)
  if not words or #words == 0 then
    lua_util.debugm(N, rspamd_config, 'Skipping empty or invalid line: %s', line)
    return
  end

  local rule_name = rule.symbol
  local scope_name = rule.scope_name or rule_name

  -- All regexps for this SA-style rule are registered in a dedicated scope
  -- This allows clean removal and replacement when the map is reloaded

  if words[1] == 'header' then
    -- header SYMBOL Header =~ /regexp/flags
    if #words >= 4 and (words[4] == '=~' or words[4] == '!~') then
      local atom_name = words[2]
      local header_name = words[3]
      local re_expr = words_to_sa_re(words, 4)

      -- Skip =~ or !~
      re_expr = string.gsub(re_expr, '^[!=]~%s*', '')

      local re = parse_sa_regexp(atom_name, re_expr)
      if re then
        -- Register regexp with cache in specific scope
        rspamd_config:register_regexp_scoped(scope_name, {
          re = re,
          type = 'header',
          header = header_name,
          pcre_only = false,
        })

        re:set_limit(0) -- No limit
        re:set_max_hits(1)

        local negate = (words[4] == '!~')
        sa_atoms[atom_name] = create_sa_atom_function(atom_name, re, 'header', {
          header = header_name,
          strong = false,
          negate = negate
        })

        -- Track atom state
        regexp_rules_symbol_states[atom_name] = {
          state = 'loading',
          rule_name = rule_name,
          type = 'atom'
        }

        lua_util.debugm(N, rspamd_config, 'added SA header atom: %s for header %s (scope: %s)',
            atom_name, header_name, scope_name)
      end
    end
  elseif words[1] == 'body' then
    -- body SYMBOL /regexp/flags
    if #words >= 3 then
      local atom_name = words[2]
      local re_expr = words_to_sa_re(words, 2)

      local re = parse_sa_regexp(atom_name, re_expr)
      if re then
        rspamd_config:register_regexp_scoped(scope_name, {
          re = re,
          type = 'sabody',
          pcre_only = false,
        })

        re:set_limit(0)
        re:set_max_hits(1)

        sa_atoms[atom_name] = create_sa_atom_function(atom_name, re, 'body', {})

        -- Track atom state
        regexp_rules_symbol_states[atom_name] = {
          state = 'loading',
          rule_name = rule_name,
          type = 'atom'
        }

        lua_util.debugm(N, rspamd_config, 'added SA body atom: %s (scope: %s)', atom_name, scope_name)
      end
    end
  elseif words[1] == 'rawbody' then
    -- rawbody SYMBOL /regexp/flags
    if #words >= 3 then
      local atom_name = words[2]
      local re_expr = words_to_sa_re(words, 2)

      local re = parse_sa_regexp(atom_name, re_expr)
      if re then
        rspamd_config:register_regexp_scoped(scope_name, {
          re = re,
          type = 'sarawbody',
          pcre_only = false,
        })

        re:set_limit(0)
        re:set_max_hits(1)

        sa_atoms[atom_name] = create_sa_atom_function(atom_name, re, 'rawbody', {})

        -- Track atom state
        regexp_rules_symbol_states[atom_name] = {
          state = 'loading',
          rule_name = rule_name,
          type = 'atom'
        }

        lua_util.debugm(N, rspamd_config, 'added SA rawbody atom: %s (scope: %s)', atom_name, scope_name)
      end
    end
  elseif words[1] == 'uri' then
    -- uri SYMBOL /regexp/flags
    if #words >= 3 then
      local atom_name = words[2]
      local re_expr = words_to_sa_re(words, 2)

      local re = parse_sa_regexp(atom_name, re_expr)
      if re then
        rspamd_config:register_regexp_scoped(scope_name, {
          re = re,
          type = 'url',
          pcre_only = false,
        })

        re:set_limit(0)
        re:set_max_hits(1)

        sa_atoms[atom_name] = create_sa_atom_function(atom_name, re, 'uri', {})

        -- Track atom state
        regexp_rules_symbol_states[atom_name] = {
          state = 'loading',
          rule_name = rule_name,
          type = 'atom'
        }

        lua_util.debugm(N, rspamd_config, 'added SA uri atom: %s (scope: %s)', atom_name, scope_name)
      end
    end
  elseif words[1] == 'full' then
    -- full SYMBOL /regexp/flags
    if #words >= 3 then
      local atom_name = words[2]
      local re_expr = words_to_sa_re(words, 2)

      local re = parse_sa_regexp(atom_name, re_expr)
      if re then
        rspamd_config:register_regexp_scoped(scope_name, {
          re = re,
          type = 'body',
          pcre_only = false,
        })

        re:set_limit(0)
        re:set_max_hits(1)

        sa_atoms[atom_name] = create_sa_atom_function(atom_name, re, 'full', {})

        -- Track atom state
        regexp_rules_symbol_states[atom_name] = {
          state = 'loading',
          rule_name = rule_name,
          type = 'atom'
        }

        lua_util.debugm(N, rspamd_config, 'added SA full atom: %s (scope: %s)', atom_name, scope_name)
      end
    end
  elseif words[1] == 'meta' then
    -- meta SYMBOL expression
    if #words >= 3 then
      local meta_name = words[2]
      local meta_expr = words_to_sa_re(words, 2)

      sa_meta_rules[meta_name] = {
        symbol = meta_name,
        expression = meta_expr,
        rule_name = rule_name
      }

      -- Track symbol state
      regexp_rules_symbol_states[meta_name] = {
        state = 'loading',
        rule_name = rule_name,
        type = 'meta'
      }

      lua_util.debugm(N, rspamd_config, 'added SA meta rule: %s = %s', meta_name, meta_expr)
    end
  elseif words[1] == 'score' then
    -- score SYMBOL value
    if #words >= 3 then
      local score_symbol = words[2]
      local score_value = tonumber(words[3])

      if score_value then
        sa_scores[score_symbol] = score_value
        lua_util.debugm(N, rspamd_config, 'added SA score: %s = %s', score_symbol, score_value)
      end
    end
  elseif words[1] == 'describe' then
    -- describe SYMBOL description text
    if #words >= 3 then
      local desc_symbol = words[2]
      local desc_text = words_to_sa_re(words, 2)

      sa_descriptions[desc_symbol] = desc_text
      lua_util.debugm(N, rspamd_config, 'added SA description: %s = %s', desc_symbol, desc_text)
    end
  end
end

local function parse_sa_atom(str)
  local atom = table.concat(fun.totable(fun.take_while(function(c)
    if string.find(', \t()><+!|&\n', c, 1, true) then
      return false
    end
    return true
  end, fun.iter(str))), '')

  return atom
end

-- Forward declaration for mutual recursion
local create_sa_meta_callback

local function gen_sa_process_atom_cb(task, rule_name)
  return function(atom)
    -- Check symbol state first
    local state_info = regexp_rules_symbol_states[atom]
    if state_info then
      if state_info.state == 'orphaned' or state_info.state == 'loading' then
        -- Double-check by looking at scope loaded state
        local scope_loaded = false
        for _, rule in ipairs(rules) do
          if rule.symbol == state_info.rule_name and rule.scope_name then
            scope_loaded = rspamd_config:is_regexp_scope_loaded(rule.scope_name)
            break
          end
        end

        if scope_loaded and (state_info.type == 'atom' and sa_atoms[atom]) then
          -- Update state to available if scope is loaded and atom exists
          state_info.state = 'available'
          lua_util.debugm(N, task, 'regexp_rules atom %s was %s, but scope is loaded - marking as available',
              atom, state_info.state)
        else
          lua_util.debugm(N, task, 'regexp_rules atom %s is %s, returning 0', atom, state_info.state)
          return 0
        end
      end
    end

    local atom_cb = sa_atoms[atom]

    if atom_cb then
      local res = atom_cb(task)

      -- Return result without logging each atom
      return res
    else
      -- Check if this is a SA meta rule
      local meta_rule = sa_meta_rules[atom]
      if meta_rule then
        local meta_cb = create_sa_meta_callback(meta_rule)
        local res = meta_cb(task)
        return res or 0
      end

      -- External atom - check if task has this symbol
      if task:has_symbol(atom) then
        return 1
      end
    end
    return 0
  end
end

create_sa_meta_callback = function(meta_rule)
  return function(task)
    -- Check symbol state before execution
    local state_info = regexp_rules_symbol_states[meta_rule.symbol]
    if state_info then
      if state_info.state == 'orphaned' or state_info.state == 'loading' then
        -- Double-check by looking at scope loaded state
        local scope_loaded = false
        for _, rule in ipairs(rules) do
          if rule.symbol == state_info.rule_name and rule.scope_name then
            scope_loaded = rspamd_config:is_regexp_scope_loaded(rule.scope_name)
            break
          end
        end

        if scope_loaded and sa_meta_rules[meta_rule.symbol] then
          -- Update state to available if scope is loaded and meta rule exists
          state_info.state = 'available'
          lua_util.debugm(N, task, 'regexp_rules meta %s was %s, but scope is loaded - marking as available',
              meta_rule.symbol, state_info.state)
        else
          lua_util.debugm(N, task, 'regexp_rules meta %s is %s, skipping execution',
              meta_rule.symbol, state_info.state)
          return 0
        end
      end
    end

    local cached = task:cache_get('sa_multimap_metas_processed')

    if not cached then
      cached = {}
      task:cache_set('sa_multimap_metas_processed', cached)
    end

    local function exclude_sym_filter(sopt)
      -- Exclude self and atoms starting with __
      return sopt ~= meta_rule.symbol
    end

    local already_processed = cached[meta_rule.symbol]

    if not (already_processed and already_processed['default']) then
      local expression = rspamd_expression.create(meta_rule.expression,
          parse_sa_atom,
          rspamd_config:get_mempool())
      if not expression then
        rspamd_logger.errx(rspamd_config, 'Cannot parse SA meta expression: %s', meta_rule.expression)
        return
      end

      local function exec_symbol(cur_res)
        local res, trace = expression:process_traced(gen_sa_process_atom_cb(task, meta_rule.rule_name))

        if res > 0 then
          local filtered_trace = fun.totable(fun.take_n(5,
              fun.map(function(elt)
                return elt:gsub('^__', '')
              end, fun.filter(exclude_sym_filter, trace))))
          lua_util.debugm(N, task, 'SA meta %s matched with result: %s; trace %s; filtered trace %s',
              meta_rule.symbol, res, trace, filtered_trace)
          task:insert_result_named(cur_res, meta_rule.symbol, 1.0, filtered_trace)
        end

        if not cached[meta_rule.symbol] then
          cached[meta_rule.symbol] = {}
        end
        cached[meta_rule.symbol][cur_res] = res

        return res
      end

      -- Invoke for all named results
      local named_results = task:get_all_named_results()
      for _, cur_res in ipairs(named_results) do
        exec_symbol(cur_res)
      end
    else
      -- We have cached the result
      local res = already_processed['default'] or 0
      lua_util.debugm(N, task, 'cached SA meta result for %s: %s', meta_rule.symbol, res)
    end
  end
end

-- Initialize SA meta rules after all atoms are processed
local function finalize_sa_rules()
  lua_util.debugm(N, rspamd_config, 'Finalizing SA rules - processing %s meta rules',
      fun.length(sa_meta_rules))

  for meta_name, meta_rule in pairs(sa_meta_rules) do
    local score = sa_scores[meta_name] or 1.0
    local description = sa_descriptions[meta_name] or ('multimap symbol ' .. meta_name)

    lua_util.debugm(N, rspamd_config, 'Registering SA meta rule %s (score: %s, expression: %s)',
        meta_name, score, meta_rule.expression)

    local id = rspamd_config:register_symbol({
      name = meta_name,
      weight = score,
      callback = create_sa_meta_callback(meta_rule),
      type = 'normal',
      flags = 'one_shot',
      augmentations = {},
    })

    lua_util.debugm(N, rspamd_config, 'Successfully registered SA meta symbol %s with id %s (callback attached)',
        meta_name, id)

    rspamd_config:set_metric_symbol({
      name = meta_name,
      score = score,
      description = description,
      group = N,
    })

    -- Also register meta rule as an atom so it can be used in other meta expressions
    sa_atoms[meta_name] = create_sa_meta_callback(meta_rule)

    -- Mark symbol as available
    if regexp_rules_symbol_states[meta_name] then
      regexp_rules_symbol_states[meta_name].state = 'available'
    else
      regexp_rules_symbol_states[meta_name] = {
        state = 'available',
        rule_name = meta_rule.rule_name,
        type = 'meta'
      }
    end

    lua_util.debugm(N, rspamd_config, 'registered SA meta symbol: %s (score: %s)',
        meta_name, score)
  end

  -- Mark orphaned symbols - only check meta symbols (not atoms) since atoms are just expression parts
  for symbol, state_info in pairs(regexp_rules_symbol_states) do
    if state_info.type == 'meta' and state_info.state == 'available' and not sa_meta_rules[symbol] then
      state_info.state = 'orphaned'
      state_info.orphaned_at = os.time()
      lua_util.debugm(N, rspamd_config, 'marked regexp_rules symbol %s as orphaned', symbol)
    end
  end

  lua_util.debugm(N, rspamd_config, 'SA rules finalization complete: registered %s meta rules with callbacks',
      fun.length(sa_meta_rules))
end

-- Helper function to get regexp_rules symbol state statistics (only meta symbols, not atoms)
local function get_regexp_rules_symbol_stats()
  local stats = {
    available = 0,
    loading = 0,
    orphaned = 0,
    total = 0
  }

  for _, state_info in pairs(regexp_rules_symbol_states) do
    if state_info.type == 'meta' then
      stats[state_info.state] = (stats[state_info.state] or 0) + 1
      stats.total = stats.total + 1
    end
  end

  return stats
end

-- Helper function to synchronize symbol states with loaded scopes
local function sync_regexp_rules_symbol_states()
  lua_util.debugm(N, rspamd_config, 'Synchronizing regexp_rules symbol states with loaded scopes')

  -- Check each rule to see if its scope is loaded
  for _, rule in ipairs(rules) do
    if rule.type == 'regexp_rules' and rule.scope_name then
      local scope_loaded = rspamd_config:is_regexp_scope_loaded(rule.scope_name)

      if scope_loaded then
        -- Mark all meta symbols for this rule as available (atoms are just expression parts)
        local updated_count = 0
        for _, state_info in pairs(regexp_rules_symbol_states) do
          if state_info.type == 'meta' and state_info.rule_name == rule.symbol and state_info.state ~= 'available' then
            state_info.state = 'available'
            updated_count = updated_count + 1
          end
        end

        lua_util.debugm(N, rspamd_config, 'Scope %s is loaded, marked %s symbols as available',
            rule.scope_name, updated_count)
      else
        lua_util.debugm(N, rspamd_config, 'Scope %s is not loaded', rule.scope_name)
      end
    end
  end

  local stats = get_regexp_rules_symbol_stats()
  lua_util.debugm(N, rspamd_config, 'Symbol state stats after sync: available=%s, loading=%s, orphaned=%s, total=%s',
      stats.available, stats.loading, stats.orphaned, stats.total)
end

-- Optional cleanup function to remove old orphaned symbols (can be called periodically)
local function cleanup_orphaned_regexp_rules_symbols(max_age_seconds)
  max_age_seconds = max_age_seconds or 3600 -- Default to 1 hour
  local current_time = os.time()
  local removed = 0

  for symbol, state_info in pairs(regexp_rules_symbol_states) do
    if state_info.type == 'meta' and state_info.state == 'orphaned' and state_info.orphaned_at then
      if (current_time - state_info.orphaned_at) > max_age_seconds then
        regexp_rules_symbol_states[symbol] = nil
        -- Only meta rules should be cleaned up from sa_meta_rules
        sa_meta_rules[symbol] = nil
        removed = removed + 1
        lua_util.debugm(N, rspamd_config, 'cleaned up orphaned regexp_rules symbol: %s', symbol)
      end
    end
  end

  if removed > 0 then
    lua_util.debugm(N, rspamd_config, 'cleaned up %s orphaned regexp_rules symbols', removed)
  end

  return removed
end

local value_types = {
  ip = {
    get_value = function(ip)
      return ip:to_string()
    end,
  },
  from = {
    get_value = function(val)
      return val
    end,
  },
  helo = {
    get_value = function(val)
      return val
    end,
  },
  header = {
    get_value = function(val)
      return val
    end,
  },
  rcpt = {
    get_value = function(val)
      return val
    end,
  },
  user = {
    get_value = function(val)
      return val
    end,
  },
  url = {
    get_value = function(val)
      return val
    end,
  },
  dnsbl = {
    get_value = function(ip)
      return ip:to_string()
    end,
  },
  filename = {
    get_value = function(val)
      return val
    end,
  },
  content = {
    get_value = function()
      return nil
    end,
  },
  hostname = {
    get_value = function(val)
      return val
    end,
  },
  asn = {
    get_value = function(val)
      return val
    end,
  },
  country = {
    get_value = function(val)
      return val
    end,
  },
  received = {
    get_value = function(val)
      return val
    end,
  },
  mempool = {
    get_value = function(val)
      return val
    end,
  },
  selector = {
    get_value = function(val)
      return val
    end,
  },
  symbol_options = {
    get_value = function(val)
      return val
    end,
  },
}

local function ip_to_rbl(ip, rbl)
  return table.concat(ip:inversed_str_octets(), ".") .. '.' .. rbl
end

local function apply_hostname_filter(task, filter, hostname, r)
  if filter == 'tld' then
    local tld = rspamd_util.get_tld(hostname)
    return tld
  elseif filter == 'top' then
    local tld = rspamd_util.get_tld(hostname)
    return tld:match('[^.]*$') or tld
  else
    if not r['re_filter'] then
      local pat = string.match(filter, 'tld:regexp:(.+)')
      if not pat then
        rspamd_logger.errx(task, 'bad search filter: %s', filter)
        return
      end
      r['re_filter'] = rspamd_regexp.create_cached(pat)
      if not r['re_filter'] then
        rspamd_logger.errx(task, 'couldnt create regex: %s', pat)
        return
      end
    end
    local tld = rspamd_util.get_tld(hostname)
    local res = r['re_filter']:search(tld)
    if res then
      return res[1]
    else
      return nil
    end
  end
end

local function apply_url_filter(task, filter, url, r)
  if not filter then
    return url:get_host()
  end

  if filter == 'tld' then
    return url:get_tld()
  elseif filter == 'top' then
    local tld = url:get_tld()
    return tld:match('[^.]*$') or tld
  elseif filter == 'full' then
    return url:get_text()
  elseif filter == 'is_phished' then
    if url:is_phished() then
      return url:get_host()
    else
      return nil
    end
  elseif filter == 'is_redirected' then
    if url:is_redirected() then
      return url:get_host()
    else
      return nil
    end
  elseif filter == 'is_obscured' then
    if url:is_obscured() then
      return url:get_host()
    else
      return nil
    end
  elseif filter == 'path' then
    return url:get_path()
  elseif filter == 'query' then
    return url:get_query()
  elseif string.find(filter, 'tag:') then
    local tags = url:get_tags()
    local want_tag = string.match(filter, 'tag:(.*)')
    for _, t in ipairs(tags) do
      if t == want_tag then
        return url:get_host()
      end
    end
    return nil
  elseif string.find(filter, 'tld:regexp:') then
    if not r['re_filter'] then
      local type, pat = string.match(filter, '(regexp:)(.+)')
      if type and pat then
        r['re_filter'] = rspamd_regexp.create_cached(pat)
      end
    end

    if not r['re_filter'] then
      rspamd_logger.errx(task, 'bad search filter: %s', filter)
    else
      local results = r['re_filter']:search(url:get_tld())
      if results then
        return results[1]
      else
        return nil
      end
    end
  elseif string.find(filter, 'full:regexp:') then
    if not r['re_filter'] then
      local type, pat = string.match(filter, '(regexp:)(.+)')
      if type and pat then
        r['re_filter'] = rspamd_regexp.create_cached(pat)
      end
    end

    if not r['re_filter'] then
      rspamd_logger.errx(task, 'bad search filter: %s', filter)
    else
      local results = r['re_filter']:search(url:get_text())
      if results then
        return results[1]
      else
        return nil
      end
    end
  elseif string.find(filter, 'regexp:') then
    if not r['re_filter'] then
      local type, pat = string.match(filter, '(regexp:)(.+)')
      if type and pat then
        r['re_filter'] = rspamd_regexp.create_cached(pat)
      end
    end

    if not r['re_filter'] then
      rspamd_logger.errx(task, 'bad search filter: %s', filter)
    else
      local results = r['re_filter']:search(url:get_host())
      if results then
        return results[1]
      else
        return nil
      end
    end
  elseif string.find(filter, '^template:') then
    if not r['template'] then
      r['template'] = string.match(filter, '^template:(.+)')
    end

    if r['template'] then
      return lua_util.template(r['template'], url:to_table())
    end
  end

  return url:get_host()
end

local function apply_addr_filter(task, filter, input, rule)
  if filter == 'email:addr' or filter == 'email' then
    local addr = rspamd_util.parse_mail_address(input, task:get_mempool(), 1024)
    if addr and addr[1] then
      return fun.totable(fun.map(function(a)
        return a.addr
      end, addr))
    end
  elseif filter == 'email:user' then
    local addr = rspamd_util.parse_mail_address(input, task:get_mempool(), 1024)
    if addr and addr[1] then
      return fun.totable(fun.map(function(a)
        return a.user
      end, addr))
    end
  elseif filter == 'email:domain' then
    local addr = rspamd_util.parse_mail_address(input, task:get_mempool(), 1024)
    if addr and addr[1] then
      return fun.totable(fun.map(function(a)
        return a.domain
      end, addr))
    end
  elseif filter == 'email:domain:tld' then
    local addr = rspamd_util.parse_mail_address(input, task:get_mempool(), 1024)
    if addr and addr[1] then
      return fun.totable(fun.map(function(a)
        return rspamd_util.get_tld(a.domain)
      end, addr))
    end
  elseif filter == 'email:name' then
    local addr = rspamd_util.parse_mail_address(input, task:get_mempool(), 1024)
    if addr and addr[1] then
      return fun.totable(fun.map(function(a)
        return a.name
      end, addr))
    end
  elseif filter == 'ip_addr' then
    local ip_addr = rspamd_ip.from_string(input)

    if ip_addr and ip_addr:is_valid() then
      return ip_addr
    end
  else
    -- regexp case
    if not rule['re_filter'] then
      local type, pat = string.match(filter, '(regexp:)(.+)')
      if type and pat then
        rule['re_filter'] = rspamd_regexp.create_cached(pat)
      end
    end

    if not rule['re_filter'] then
      rspamd_logger.errx(task, 'bad search filter: %s', filter)
    else
      local results = rule['re_filter']:search(input)
      if results then
        return results[1]
      end
    end
  end

  return input
end
local function apply_filename_filter(task, filter, fn, r)
  if filter == 'extension' or filter == 'ext' then
    return string.match(fn, '%.([^.]+)$')
  elseif string.find(filter, 'regexp:') then
    if not r['re_filter'] then
      local type, pat = string.match(filter, '(regexp:)(.+)')
      if type and pat then
        r['re_filter'] = rspamd_regexp.create_cached(pat)
      end
    end

    if not r['re_filter'] then
      rspamd_logger.errx(task, 'bad search filter: %s', filter)
    else
      local results = r['re_filter']:search(fn)
      if results then
        return results[1]
      else
        return nil
      end
    end
  end

  return fn
end

local function apply_regexp_filter(task, filter, fn, r)
  if string.find(filter, 'regexp:') then
    if not r['re_filter'] then
      local type, pat = string.match(filter, '(regexp:)(.+)')
      if type and pat then
        r['re_filter'] = rspamd_regexp.create_cached(pat)
      end
    end

    if not r['re_filter'] then
      rspamd_logger.errx(task, 'bad search filter: %s', filter)
    else
      local results = r['re_filter']:search(fn, false, true)
      if results then
        return results[1][2]
      else
        return nil
      end
    end
  end

  return fn
end

local function apply_content_filter(task, filter)
  if filter == 'body' then
    return { task:get_rawbody() }
  elseif filter == 'full' then
    return { task:get_content() }
  elseif filter == 'headers' then
    return { task:get_raw_headers() }
  elseif filter == 'text' then
    local ret = {}
    for _, p in ipairs(lua_mime.get_distinct_text_parts(task)) do
      table.insert(ret, p:get_content())
    end
    return ret
  elseif filter == 'rawtext' then
    local ret = {}
    for _, p in ipairs(lua_mime.get_distinct_text_parts(task)) do
      table.insert(ret, p:get_content('raw_parsed'))
    end
    return ret
  elseif filter == 'oneline' then
    local ret = {}
    for _, p in ipairs(lua_mime.get_distinct_text_parts(task)) do
      table.insert(ret, p:get_content_oneline())
    end
    return ret
  else
    rspamd_logger.errx(task, 'bad search filter: %s', filter)
  end

  return {}
end

local multimap_filters = {
  from = apply_addr_filter,
  rcpt = apply_addr_filter,
  helo = apply_hostname_filter,
  symbol_options = apply_regexp_filter,
  header = apply_addr_filter,
  url = apply_url_filter,
  filename = apply_filename_filter,
  mempool = apply_regexp_filter,
  selector = apply_regexp_filter,
  hostname = apply_hostname_filter,
  --content = apply_content_filter, -- Content filters are special :(
}

local function multimap_query_redis(key, task, value, callback)
  local cmd = 'HGET'
  if type(value) == 'userdata' and value.class == 'rspamd{ip}' then
    cmd = 'HMGET'
  end

  local srch = { key }

  -- Insert all ips for some mask :(
  if type(value) == 'userdata' and value.class == 'rspamd{ip}' then
    srch[#srch + 1] = tostring(value)
    -- IPv6 case
    local maxbits = 128
    local minbits = 64
    if value:get_version() == 4 then
      maxbits = 32
      minbits = 8
    end
    for i = maxbits, minbits, -1 do
      local nip = value:apply_mask(i):tostring() .. "/" .. i
      srch[#srch + 1] = nip
    end
  else
    srch[#srch + 1] = value
  end

  local function redis_map_cb(err, data)
    lua_util.debugm(N, task, 'got reply from Redis when trying to get key %s: err=%s, data=%s',
        key, err, data)
    if not err and type(data) ~= 'userdata' then
      callback(data)
    end
  end

  return rspamd_redis_make_request(task,
      redis_params, -- connect params
      key, -- hash key
      false, -- is write
      redis_map_cb, --callback
      cmd, -- command
      srch          -- arguments
  )
end

local function multimap_callback(task, rule)
  local function match_element(r, value, callback)
    if not value then
      return false
    end

    local function get_key_callback(ret, err_or_data, err_code)
      lua_util.debugm(N, task, 'got return "%s" (err code = %s) for multimap %s',
          err_or_data,
          err_code,
          rule.symbol)

      if ret then
        if type(err_or_data) == 'table' then
          for _, elt in ipairs(err_or_data) do
            callback(elt)
          end
        else
          callback(err_or_data)
        end
      elseif err_code ~= 404 then
        rspamd_logger.infox(task, "map %s: get key returned error %s: %s",
            rule.symbol, err_code, err_or_data)
      end
    end

    lua_util.debugm(N, task, 'check value %s for multimap %s', value,
        rule.symbol)

    local ret = false

    if r.redis_key then
      -- Deal with hash name here: it can be either plain string or a selector
      if type(r.redis_key) == 'string' then
        ret = multimap_query_redis(r.redis_key, task, value, callback)
      else
        -- Here we have a selector
        local results = r.redis_key(task)

        -- Here we need to spill this function into multiple queries
        if type(results) == 'table' then
          for _, res in ipairs(results) do
            ret = multimap_query_redis(res, task, value, callback)

            if not ret then
              break
            end
          end
        else
          ret = multimap_query_redis(results, task, value, callback)
        end
      end

      return ret
    elseif r.map_obj then
      r.map_obj:get_key(value, get_key_callback, task)
    end
  end

  local function insert_results(result, opt)
    local _, symbol, score, opts = parse_multimap_value(rule, result)
    local forced = false
    if symbol then
      if rule.symbols_set then
        if not rule.symbols_set[symbol] then
          rspamd_logger.infox(task, 'symbol %s is not registered for map %s, ' ..
              'replace it with just %s',
              symbol, rule.symbol, rule.symbol)
          symbol = rule.symbol
        end
      elseif rule.disable_multisymbol then
        symbol = rule.symbol
        if type(opt) == 'table' then
          table.insert(opt, result)
        elseif type(opt) ~= nil then
          opt = { opt, result }
        else
          opt = { result }
        end
      else
        forced = not rule.dynamic_symbols
      end
    else
      symbol = rule.symbol
    end

    if opts and #opts > 0 then
      -- Options come from the map itself
      task:insert_result(forced, symbol, score, opts)
    else
      if opt then
        if type(opt) == 'table' then
          task:insert_result(forced, symbol, score, fun.totable(fun.map(tostring, opt)))
        else
          task:insert_result(forced, symbol, score, tostring(opt))
        end
      else
        task:insert_result(forced, symbol, score)
      end
    end

    if rule.action then
      local message = rule.message
      if rule.message_func then
        message = rule.message_func(task, rule.symbol, opt)
      end
      if message then
        task:set_pre_result(rule.action, message, N)
      else
        task:set_pre_result(rule.action, 'Matched map: ' .. rule.symbol, N)
      end
    end
  end

  -- Match a single value for against a single rule
  local function match_rule(r, value)
    local function rule_callback(result)
      if result then
        if type(result) == 'table' then
          for _, rs in ipairs(result) do
            if type(rs) ~= 'userdata' then
              rule_callback(rs)
            end
          end
          return
        end
        local opt = value_types[r['type']].get_value(value)
        insert_results(result, opt)
      end
    end

    if r.filter or r.type == 'url' then
      local fn = multimap_filters[r.type]

      if fn then
        local filtered_value = fn(task, r.filter, value, r)
        lua_util.debugm(N, task, 'apply filter %s for rule %s: %s -> %s',
            r.filter, r.symbol, value, filtered_value)
        value = filtered_value
      end
    end

    if type(value) == 'table' then
      fun.each(function(elt)
        match_element(r, elt, rule_callback)
      end, value)
    else
      match_element(r, value, rule_callback)
    end
  end

  -- Match list of values according to the field
  local function match_list(r, ls, fields)
    if ls then
      if fields then
        fun.each(function(e)
          local match = e[fields[1]]
          if match then
            if fields[2] then
              match = fields[2](match)
            end
            match_rule(r, match)
          end
        end, ls)
      else
        fun.each(function(e)
          match_rule(r, e)
        end, ls)
      end
    end
  end

  local function match_addr(r, addr)
    match_list(r, addr, { 'addr' })

    if not r.filter then
      match_list(r, addr, { 'domain' })
      match_list(r, addr, { 'user' })
    end
  end

  local function match_url(r, url)
    match_rule(r, url)
  end

  local function match_hostname(r, hostname)
    match_rule(r, hostname)
  end

  local function match_filename(r, fn)
    match_rule(r, fn)
  end

  local function match_received_header(r, pos, total, h)
    local use_tld = false
    local filter = r['filter'] or 'real_ip'
    if filter:match('^tld:') then
      filter = filter:sub(5)
      use_tld = true
    end
    local v = h[filter]
    if v then
      local min_pos = tonumber(r['min_pos'])
      local max_pos = tonumber(r['max_pos'])
      if min_pos then
        if min_pos < 0 then
          if min_pos == -1 then
            if (pos ~= total) then
              return
            end
          else
            if pos <= (total - (min_pos * -1)) then
              return
            end
          end
        elseif pos < min_pos then
          return
        end
      end
      if max_pos then
        if max_pos < -1 then
          if (total - (max_pos * -1)) >= pos then
            return
          end
        elseif max_pos > 0 then
          if pos > max_pos then
            return
          end
        end
      end
      local match_flags = r['flags']
      local nmatch_flags = r['nflags']
      if match_flags or nmatch_flags then
        local got_flags = h['flags']
        if match_flags then
          for _, flag in ipairs(match_flags) do
            if not got_flags[flag] then
              return
            end
          end
        end
        if nmatch_flags then
          for _, flag in ipairs(nmatch_flags) do
            if got_flags[flag] then
              return
            end
          end
        end
      end
      if filter == 'real_ip' or filter == 'from_ip' then
        if type(v) == 'string' then
          v = rspamd_ip.from_string(v)
        end
        if v and v:is_valid() then
          match_rule(r, v)
        end
      else
        if use_tld and type(v) == 'string' then
          v = rspamd_util.get_tld(v)
        end
        match_rule(r, v)
      end
    end
  end

  local function match_content(r)
    local data

    if r['filter'] then
      data = apply_content_filter(task, r['filter'], r)
    else
      data = { task:get_content() }
    end

    for _, v in ipairs(data) do
      match_rule(r, v)
    end
  end

  if rule.expression and not rule.combined then
    local res, trace = rule['expression']:process_traced(task)

    if not res or res == 0 then
      lua_util.debugm(N, task, 'condition is false for %s',
          rule.symbol)
      return
    else
      lua_util.debugm(N, task, 'condition is true for %s: %s',
          rule.symbol,
          trace)
    end
  end

  local process_rule_funcs = {
    ip = function()
      local ip = task:get_from_ip()
      if ip and ip:is_valid() then
        match_rule(rule, ip)
      end
    end,
    dnsbl = function()
      local ip = task:get_from_ip()
      if ip and ip:is_valid() then
        local to_resolve = ip_to_rbl(ip, rule['map'])
        local function dns_cb(_, _, results, err)
          lua_util.debugm(N, rspamd_config,
              'resolve() finished: results=%1, err=%2, to_resolve=%3',
              results, err, to_resolve)

          if err and
              (err ~= 'requested record is not found' and
                  err ~= 'no records with this name') then
            rspamd_logger.errx(task, 'error looking up %s: %s', to_resolve, results)
          elseif results then
            task:insert_result(rule['symbol'], 1, rule['map'])
            if rule.action then
              task:set_pre_result(rule['action'],
                  'Matched map: ' .. rule['symbol'], N)
            end
          end
        end

        task:get_resolver():resolve_a({
          task = task,
          name = to_resolve,
          callback = dns_cb,
          forced = true
        })
      end
    end,
    header = function()
      if type(rule['header']) == 'table' then
        for _, rh in ipairs(rule['header']) do
          local hv = task:get_header_full(rh)
          match_list(rule, hv, { 'decoded' })
        end
      else
        local hv = task:get_header_full(rule['header'])
        match_list(rule, hv, { 'decoded' })
      end
    end,
    rcpt = function()
      local extract_from = rule.extract_from or 'default'

      if extract_from == 'mime' then
        local rcpts = task:get_recipients('mime')
        if rcpts then
          lua_util.debugm(N, task, 'checking mime rcpts against the map')
          match_addr(rule, rcpts)
        end
      elseif extract_from == 'smtp' then
        local rcpts = task:get_recipients('smtp')
        if rcpts then
          lua_util.debugm(N, task, 'checking smtp rcpts against the map')
          match_addr(rule, rcpts)
        end
      elseif extract_from == 'both' then
        local rcpts = task:get_recipients('smtp')
        if rcpts then
          lua_util.debugm(N, task, 'checking smtp rcpts against the map')
          match_addr(rule, rcpts)
        end
        rcpts = task:get_recipients('mime')
        if rcpts then
          lua_util.debugm(N, task, 'checking mime rcpts against the map')
          match_addr(rule, rcpts)
        end
      else
        -- Default algorithm
        if task:has_recipients('smtp') then
          local rcpts = task:get_recipients('smtp')
          lua_util.debugm(N, task, 'checking smtp rcpts against the map')
          match_addr(rule, rcpts)
        elseif task:has_recipients('mime') then
          local rcpts = task:get_recipients('mime')
          lua_util.debugm(N, task, 'checking mime rcpts against the map')
          match_addr(rule, rcpts)
        end
      end
    end,
    from = function()
      local extract_from = rule.extract_from or 'default'

      if extract_from == 'mime' then
        local from = task:get_from('mime')
        if from then
          lua_util.debugm(N, task, 'checking mime from against the map')
          match_addr(rule, from)
        end
      elseif extract_from == 'smtp' then
        local from = task:get_from('smtp')
        if from then
          lua_util.debugm(N, task, 'checking smtp from against the map')
          match_addr(rule, from)
        end
      elseif extract_from == 'both' then
        local from = task:get_from('smtp')
        if from then
          lua_util.debugm(N, task, 'checking smtp from against the map')
          match_addr(rule, from)
        end
        from = task:get_from('mime')
        if from then
          lua_util.debugm(N, task, 'checking mime from against the map')
          match_addr(rule, from)
        end
      else
        -- Default algorithm
        if task:has_from('smtp') then
          local from = task:get_from('smtp')
          lua_util.debugm(N, task, 'checking smtp from against the map')
          match_addr(rule, from)
        elseif task:has_from('mime') then
          local from = task:get_from('mime')
          lua_util.debugm(N, task, 'checking mime from against the map')
          match_addr(rule, from)
        end
      end
    end,
    helo = function()
      local helo = task:get_helo()
      if helo then
        match_hostname(rule, helo)
      end
    end,
    url = function()
      if task:has_urls() then
        local msg_urls = task:get_urls()

        for _, url in ipairs(msg_urls) do
          match_url(rule, url)
        end
      end
    end,
    user = function()
      local user = task:get_user()
      if user then
        match_rule(rule, user)
      end
    end,
    filename = function()
      local parts = task:get_parts()

      local function filter_parts(p)
        return p:is_attachment() or (not p:is_text()) and (not p:is_multipart())
      end

      local function filter_archive(p)
        local ext = p:get_detected_ext()
        local det_type = 'unknown'

        if ext then
          local lua_magic_types = require "lua_magic/types"
          local det_t = lua_magic_types[ext]

          if det_t then
            det_type = det_t.type
          end
        end

        return p:is_archive() and det_type == 'archive' and not rule.skip_archives
      end

      for _, p in fun.iter(fun.filter(filter_parts, parts)) do
        if filter_archive(p) then
          local fnames = p:get_archive():get_files(1000)

          for _, fn in ipairs(fnames) do
            match_filename(rule, fn)
          end
        end

        local fn = p:get_filename()
        if fn then
          match_filename(rule, fn)
        end
        -- Also deal with detected content type
        if not rule.skip_detected then
          local ext = p:get_detected_ext()

          if ext then
            local fake_fname = string.format('detected.%s', ext)
            lua_util.debugm(N, task, 'detected filename %s',
                fake_fname)
            match_filename(rule, fake_fname)
          end
        end
      end
    end,

    content = function()
      match_content(rule)
    end,
    hostname = function()
      local hostname = task:get_hostname()
      if hostname then
        match_hostname(rule, hostname)
      end
    end,
    asn = function()
      local asn = task:get_mempool():get_variable('asn')
      if asn then
        match_rule(rule, asn)
      end
    end,
    country = function()
      local country = task:get_mempool():get_variable('country')
      if country then
        match_rule(rule, country)
      end
    end,
    mempool = function()
      local var = task:get_mempool():get_variable(rule['variable'])
      if var then
        match_rule(rule, var)
      end
    end,
    symbol_options = function()
      local sym = task:get_symbol(rule['target_symbol'])
      if sym and sym[1].options then
        for _, o in ipairs(sym[1].options) do
          match_rule(rule, o)
        end
      end
    end,
    received = function()
      local hdrs = task:get_received_headers()
      if hdrs and hdrs[1] then
        if not rule['artificial'] then
          hdrs = fun.filter(function(h)
            return not h['flags']['artificial']
          end, hdrs):totable()
        end
        for pos, h in ipairs(hdrs) do
          match_received_header(rule, pos, #hdrs, h)
        end
      end
    end,
    selector = function()
      local elts = rule.selector(task)

      if elts then
        if type(elts) == 'table' then
          for _, elt in ipairs(elts) do
            match_rule(rule, elt)
          end
        else
          match_rule(rule, elts)
        end
      end
    end,
    combined = function()
      local ret, trace = rule.combined:process(task)
      if ret and ret ~= 0 then
        for n, t in pairs(trace) do
          insert_results(t.value, string.format("%s=%s",
              n, t.matched))
        end
      end
    end,
    regexp_rules = function()
      -- For regexp_rules, the meta rules are registered as separate symbols
      -- This is just a placeholder callback
      lua_util.debugm(N, task, 'Regexp rules callback for %s - meta rules are registered as separate symbols',
          rule.symbol)
    end,
  }

  local rt = rule.type
  local process_func = process_rule_funcs[rt]
  if process_func then
    process_func()
  else
    rspamd_logger.errx(task, 'Unrecognised rule type: %s', rt)
  end
end

local function gen_multimap_callback(rule)
  return function(task)
    multimap_callback(task, rule)
  end
end

local function multimap_on_load_gen(rule)
  return function()
    lua_util.debugm(N, rspamd_config, "loaded map object for rule %s", rule['symbol'])
    local known_symbols = {}
    rule.map_obj:foreach(function(key, value)
      local mult = rule.score or 1.0
      local r, symbol, score, _ = parse_multimap_value(rule, value)

      if r and symbol and not known_symbols[symbol] then
        lua_util.debugm(N, rspamd_config, "%s: adding new symbol %s (score = %s), triggered by %s",
            rule.symbol, symbol, score, key)
        rspamd_config:register_symbol {
          name = symbol,
          parent = rule.callback_id,
          type = 'virtual',
          score = score * mult,
        }
        rspamd_config:set_metric_symbol({
          group = N,
          score = mult, -- In future, we will parse score from `get_value` and use it as multiplier
          description = 'Automatic symbol generated by rule: ' .. rule.symbol,
          name = symbol,
        })
        known_symbols[value] = true
      end
    end)
  end
end

local function add_multimap_rule(key, newrule)
  local ret = false

  local function multimap_load_kv_map(rule)
    if rule['regexp'] then
      if rule['multi'] then
        rule.map_obj = lua_maps.map_add_from_ucl(rule.map, 'regexp_multi',
            rule.description)
      else
        rule.map_obj = lua_maps.map_add_from_ucl(rule.map, 'regexp',
            rule.description)
      end
    elseif rule['glob'] then
      if rule['multi'] then
        rule.map_obj = lua_maps.map_add_from_ucl(rule.map, 'glob_multi',
            rule.description)
      else
        rule.map_obj = lua_maps.map_add_from_ucl(rule.map, 'glob',
            rule.description)
      end
    else
      rule.map_obj = lua_maps.map_add_from_ucl(rule.map, 'hash',
          rule.description)
    end
  end

  local known_generic_types = {
    header = true,
    rcpt = true,
    from = true,
    helo = true,
    symbol_options = true,
    filename = true,
    url = true,
    user = true,
    content = true,
    hostname = true,
    asn = true,
    country = true,
    mempool = true,
    selector = true,
    combined = true,
    regexp_rules = true
  }

  if newrule['message_func'] then
    newrule['message_func'] = assert(load(newrule['message_func']))()
  end
  if newrule['url'] and not newrule['map'] then
    newrule['map'] = newrule['url']
  end
  if not (newrule.map or newrule.rules) then
    rspamd_logger.errx(rspamd_config, 'incomplete rule, missing map')
    return nil
  end
  if not newrule['symbol'] and key then
    newrule['symbol'] = key
  elseif not newrule['symbol'] then
    rspamd_logger.errx(rspamd_config, 'incomplete rule, missing symbol')
    return nil
  end
  if not newrule['description'] then
    newrule['description'] = string.format('multimap, type %s: %s', newrule['type'],
        newrule['symbol'])
  end
  if newrule['type'] == 'mempool' and not newrule['variable'] then
    rspamd_logger.errx(rspamd_config, 'mempool map requires variable')
    return nil
  end
  if newrule['type'] == 'selector' then
    if not newrule['selector'] then
      rspamd_logger.errx(rspamd_config, 'selector map requires selector definition')
      return nil
    else
      local selector = lua_selectors.create_selector_closure(
          rspamd_config, newrule['selector'], newrule['delimiter'] or "")

      if not selector then
        rspamd_logger.errx(rspamd_config, 'selector map has invalid selector: "%s", symbol: %s',
            newrule['selector'], newrule['symbol'])
        return nil
      end

      newrule.selector = selector
    end
  end
  if type(newrule['map']) == 'string' and
      string.find(newrule['map'], '^redis://.*$') then
    if not redis_params then
      rspamd_logger.infox(rspamd_config, 'no redis servers are specified, ' ..
          'cannot add redis map %s: %s', newrule['symbol'], newrule['map'])
      return nil
    end

    newrule['redis_key'] = string.match(newrule['map'], '^redis://(.*)$')

    if newrule['redis_key'] then
      ret = true
    end
  elseif type(newrule['map']) == 'string' and
      string.find(newrule['map'], '^redis%+selector://.*$') then
    if not redis_params then
      rspamd_logger.infox(rspamd_config, 'no redis servers are specified, ' ..
          'cannot add redis map %s: %s', newrule['symbol'], newrule['map'])
      return nil
    end

    local selector_str = string.match(newrule['map'], '^redis%+selector://(.*)$')
    local selector = lua_selectors.create_selector_closure(
        rspamd_config, selector_str, newrule['delimiter'] or "")

    if not selector then
      rspamd_logger.errx(rspamd_config, 'redis selector map has invalid selector: "%s", symbol: %s',
          selector_str, newrule['symbol'])
      return nil
    end

    newrule['redis_key'] = selector
    ret = true
  elseif newrule.type == 'combined' then
    local lua_maps_expressions = require "lua_maps_expressions"
    newrule.combined = lua_maps_expressions.create(rspamd_config,
        {
          rules = newrule.rules,
          expression = newrule.expression,
          description = newrule.description,
          on_load = newrule.dynamic_symbols and multimap_on_load_gen(newrule) or nil,
        }, N, 'Combined map for ' .. newrule.symbol)
    if not newrule.combined then
      rspamd_logger.errx(rspamd_config, 'cannot add combined map for %s', newrule.symbol)
    else
      ret = true
    end
  elseif newrule.type == 'regexp_rules' then
    -- SpamAssassin-like map processing using callback map with line-by-line processing
    local map_ucl = newrule.map
    if type(map_ucl) == 'string' then
      -- Convert string URL to UCL format
      map_ucl = {
        url = map_ucl,
        description = newrule.description
      }
    elseif type(map_ucl) == 'table' and not map_ucl.url and not map_ucl.urls then
      rspamd_logger.errx(rspamd_config, 'SA map %s has no URL defined', newrule.symbol)
      return nil
    end

    -- Set scope name for this regexp_rules map
    local scope_name = newrule.symbol
    newrule.scope_name = scope_name

    -- Remove existing scope if it exists to ensure clean state
    if rspamd_config:find_regexp_scope(scope_name) then
      lua_util.debugm(N, rspamd_config, 'removing existing regexp scope: %s', scope_name)
      rspamd_config:remove_regexp_scope(scope_name)
    end

    -- Mark the scope as unloaded during map processing
    -- The scope will be created automatically when first regexp is added
    local first_line_processed = false

    -- Create callback map with by_line processing
    newrule.map_obj = rspamd_config:add_map({
      type = "callback",
      url = map_ucl.url or map_ucl.urls or map_ucl,
      description = newrule.description or 'SA-style multimap: ' .. newrule.symbol,
      callback = function(pseudo_key, pseudo_value)
        -- We have values being parsed as kv pairs, but they are not, so we concat them and use as a line
        local line = pseudo_key .. ' ' .. pseudo_value
        -- Add debug logging to see if callback is called
        lua_util.debugm(N, rspamd_config, 'regexp_rules callback called for line: %s', line)

        -- Mark scope as unloaded on first line
        if not first_line_processed then
          first_line_processed = true
          lua_util.debugm(N, rspamd_config, 'processing first line of regexp_rules map %s', newrule.symbol)

          -- Mark all existing symbols for this scope as loading
          for symbol, state_info in pairs(regexp_rules_symbol_states) do
            if state_info.rule_name == newrule.symbol then
              state_info.state = 'loading'
              lua_util.debugm(N, rspamd_config, 'marked regexp_rules symbol %s as loading for scope %s reload',
                  symbol, scope_name)
            end
          end

          -- Clear atoms and meta rules for this scope
          local symbols_to_remove = {}
          for symbol, _ in pairs(sa_meta_rules) do
            if regexp_rules_symbol_states[symbol] and regexp_rules_symbol_states[symbol].rule_name == newrule.symbol then
              table.insert(symbols_to_remove, symbol)
            end
          end

          for _, symbol in ipairs(symbols_to_remove) do
            sa_atoms[symbol] = nil
            sa_meta_rules[symbol] = nil
            lua_util.debugm(N, rspamd_config, 'cleared regexp_rules symbol %s for scope %s reload',
                symbol, scope_name)
          end

          -- The scope will be created by process_sa_line when first regexp is added
          -- We mark it as unloaded immediately after creation
          rspamd_config:set_regexp_scope_loaded(scope_name, false)
          lua_util.debugm(N, rspamd_config, 'marked regexp scope %s as unloaded during processing', scope_name)
        end
        process_sa_line(newrule, line)
      end,
      by_line = true, -- Process line by line
      opaque_data = false, -- Use plain strings
    })

    -- Add on_load callback to mark scope as loaded when map processing is complete
    if newrule.map_obj then
      newrule.map_obj:on_load(function()
        lua_util.debugm(N, rspamd_config, 'regexp_rules map %s loaded successfully', newrule.symbol)

        -- Mark all meta symbols for this scope as available (atoms are just expression parts)
        for symbol, state_info in pairs(regexp_rules_symbol_states) do
          if state_info.type == 'meta' and state_info.rule_name == newrule.symbol then
            if state_info.state == 'loading' then
              -- Check if this meta symbol still exists in the rules
              if sa_meta_rules[symbol] then
                state_info.state = 'available'
                lua_util.debugm(N, rspamd_config, 'marked regexp_rules symbol %s as available after map load', symbol)
              else
                -- Symbol was removed in the new map
                state_info.state = 'orphaned'
                state_info.orphaned_at = os.time()
                lua_util.debugm(N, rspamd_config, 'marked regexp_rules symbol %s as orphaned after map load', symbol)
              end
            end
          end
        end

        -- Mark scope as loaded when map processing is complete
        -- Check if scope exists (it might not if map was empty)
        if rspamd_config:find_regexp_scope(scope_name) then
          rspamd_config:set_regexp_scope_loaded(scope_name, true)
          lua_util.debugm(N, rspamd_config, 'marked regexp scope %s as loaded after map processing', scope_name)

          -- Trigger hyperscan compilation for this updated scope
          newrule.map_obj:trigger_hyperscan_compilation()
          lua_util.debugm(N, rspamd_config, 'triggered hyperscan compilation for scope %s after map loading',
              scope_name)
        else
          lua_util.debugm(N, rspamd_config, 'regexp scope %s not created (empty map)', scope_name)
        end

        -- Synchronize symbol states after map load to ensure all processes see correct states
        sync_regexp_rules_symbol_states()

        -- Finalize SA rules immediately after map load
        finalize_sa_rules()

        -- Promote symcache resort after dynamic symbol registration
        rspamd_config:promote_symbols_cache_resort()
        lua_util.debugm(N, rspamd_config, 'promoted symcache resort after loading SA rules from map %s',
            newrule.symbol)
      end)
    end

    if newrule.map_obj then
      -- Mark this rule as using SA functionality
      newrule.uses_sa = true
      lua_util.debugm(N, rspamd_config, 'created regexp_rules map %s with scope: %s',
          newrule.symbol, scope_name)
      ret = true
    else
      rspamd_logger.warnx(rspamd_config, 'Cannot add SA-style rule: map doesn\'t exists: %s',
          newrule['map'])
    end
  else
    if newrule['type'] == 'ip' then
      newrule.map_obj = lua_maps.map_add_from_ucl(newrule.map, 'radix',
          newrule.description)
      if newrule.map_obj then
        ret = true
      else
        rspamd_logger.warnx(rspamd_config, 'Cannot add rule: map doesn\'t exists: %s',
            newrule['map'])
      end
    elseif newrule['type'] == 'received' then
      if type(newrule['flags']) == 'table' and newrule['flags'][1] then
        newrule['flags'] = newrule['flags']
      elseif type(newrule['flags']) == 'string' then
        newrule['flags'] = { newrule['flags'] }
      end
      if type(newrule['nflags']) == 'table' and newrule['nflags'][1] then
        newrule['nflags'] = newrule['nflags']
      elseif type(newrule['nflags']) == 'string' then
        newrule['nflags'] = { newrule['nflags'] }
      end
      local filter = newrule['filter'] or 'real_ip'
      if filter == 'real_ip' or filter == 'from_ip' then
        newrule.map_obj = lua_maps.map_add_from_ucl(newrule.map, 'radix',
            newrule.description)
        if newrule.map_obj then
          ret = true
        else
          rspamd_logger.warnx(rspamd_config, 'Cannot add rule: map doesn\'t exists: %s',
              newrule['map'])
        end
      else
        multimap_load_kv_map(newrule)

        if newrule.map_obj then
          ret = true
        else
          rspamd_logger.warnx(rspamd_config, 'Cannot add rule: map doesn\'t exists: %s',
              newrule['map'])
        end
      end
    elseif known_generic_types[newrule.type] then
      if newrule.filter == 'ip_addr' then
        newrule.map_obj = lua_maps.map_add_from_ucl(newrule.map, 'radix',
            newrule.description)
      elseif not newrule.combined then
        multimap_load_kv_map(newrule)
      end

      if newrule.map_obj then
        ret = true
      else
        rspamd_logger.warnx(rspamd_config, 'Cannot add rule: map doesn\'t exists: %s',
            newrule['map'])
      end
    elseif newrule['type'] == 'dnsbl' then
      ret = true
    else
      rspamd_logger.errx(rspamd_config, 'cannot add rule %s: invalid type %s',
          key, newrule['type'])
    end
  end

  if ret then
    if newrule.map_obj and newrule.dynamic_symbols then
      newrule.map_obj:on_load(multimap_on_load_gen(newrule))
    end
    if newrule['type'] == 'symbol_options' then
      rspamd_config:register_dependency(newrule['symbol'], newrule['target_symbol'])
    end
    if newrule['require_symbols'] then
      local atoms = {}

      local function parse_atom(str)
        local atom = table.concat(fun.totable(fun.take_while(function(c)
          if string.find(', \t()><+!|&\n', c, 1, true) then
            return false
          end
          return true
        end, fun.iter(str))), '')
        table.insert(atoms, atom)
        return atom
      end

      local function process_atom(atom, task)
        local f_ret = task:has_symbol(atom)
        lua_util.debugm(N, rspamd_config, 'check for symbol %s: %s', atom, f_ret)

        if f_ret then
          return 1
        end

        return 0
      end

      local expression = rspamd_expression.create(newrule['require_symbols'],
          { parse_atom, process_atom }, rspamd_config:get_mempool())
      if expression then
        newrule['expression'] = expression

        fun.each(function(v)
          lua_util.debugm(N, rspamd_config, 'add dependency %s -> %s',
              newrule['symbol'], v)
          rspamd_config:register_dependency(newrule['symbol'], v)
        end, atoms)
      end
    end
    return newrule
  end

  return nil
end

-- Registration
local opts = rspamd_config:get_all_opt(N)
if opts and type(opts) == 'table' then
  redis_params = rspamd_parse_redis_server(N)

  -- Initialize regexp_rules symbol states from existing sa_atoms and sa_meta_rules
  -- This helps with module reload scenarios
  for atom_name, _ in pairs(sa_atoms) do
    if not regexp_rules_symbol_states[atom_name] then
      regexp_rules_symbol_states[atom_name] = {
        state = 'available',
        rule_name = 'unknown',
        type = 'atom'
      }
    end
  end

  for meta_name, meta_rule in pairs(sa_meta_rules) do
    if not regexp_rules_symbol_states[meta_name] then
      regexp_rules_symbol_states[meta_name] = {
        state = 'available',
        rule_name = meta_rule.rule_name or 'unknown',
        type = 'meta'
      }
    end
  end

  for k, m in pairs(opts) do
    if type(m) == 'table' and m['type'] then
      local rule = add_multimap_rule(k, m)
      if not rule then
        rspamd_logger.errx(rspamd_config, 'cannot add rule: "' .. k .. '"')
      else
        rspamd_logger.infox(rspamd_config, 'added multimap rule: %s (%s)',
            k, rule.type)
        table.insert(rules, rule)
      end
    end
  end
  -- add fake symbol to check all maps inside a single callback
  fun.each(function(rule)
    local augmentations = {}

    if rule.action then
      table.insert(augmentations, 'passthrough')
    end

    local id = rspamd_config:register_symbol({
      type = 'normal',
      name = rule['symbol'],
      augmentations = augmentations,
      callback = gen_multimap_callback(rule),
    })

    rule.callback_id = id

    if rule['symbols'] then
      -- Find allowed symbols by this map
      rule['symbols_set'] = {}
      fun.each(function(s)
        rspamd_config:register_symbol({
          type = 'virtual',
          name = s,
          parent = id,
          score = tonumber(rule.score or "0") or 0, -- Default score
        })
        rule['symbols_set'][s] = 1
      end, rule['symbols'])
    end
    if not rule.score then
      rspamd_logger.infox(rspamd_config, 'set default score 0 for multimap rule %s', rule.symbol)
      rule.score = 0
    end
    if rule.score then
      -- Register metric symbol
      rule.name = rule.symbol
      rule.description = rule.description or 'multimap symbol'
      rule.group = rule.group or N

      local tmp_flags
      tmp_flags = rule.flags

      if rule.type == 'received' and rule.flags then
        -- XXX: hack to allow received flags/nflags
        -- See issue #3526 on GH
        rule.flags = nil
      end

      -- XXX: for combined maps we use trace, so flags must include one_shot to avoid scores multiplication
      if rule.combined and not rule.flags then
        rule.flags = 'one_shot'
      end
      rspamd_config:set_metric_symbol(rule)
      rule.flags = tmp_flags
    end
  end, rules)

  if #rules == 0 then
    lua_util.disable_module(N, "config")
  else
    -- Finalize SpamAssassin-like rules after all maps are processed
    local has_sa_rules = false
    for _, rule in ipairs(rules) do
      if rule.uses_sa then
        has_sa_rules = true
        break
      end
    end

    if has_sa_rules then
      -- Add a callback to synchronize symbol states in worker processes
      rspamd_config:add_on_load(function(cfg, ev_base, worker)
        -- Synchronize symbol states with loaded scopes in worker processes
        if worker then
          sync_regexp_rules_symbol_states()
        end
      end)

      -- Export utility functions for debugging/monitoring
      rspamd_plugins.multimap = rspamd_plugins.multimap or {}
      rspamd_plugins.multimap.get_regexp_rules_symbol_stats = get_regexp_rules_symbol_stats
      rspamd_plugins.multimap.cleanup_orphaned_regexp_rules_symbols = cleanup_orphaned_regexp_rules_symbols
    end
  end
end
