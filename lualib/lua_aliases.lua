--[[
Copyright (c) 2025, Vsevolod Stakhov <vsevolod@rspamd.com>

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

--[[[
-- @module lua_aliases
-- Email aliases resolution and local domains management
--
-- This module provides functionality for:
-- - Parsing Unix-style aliases (/etc/aliases format)
-- - Parsing virtual aliases (Postfix virtual format)
-- - Resolving email addresses through alias chains
-- - Detecting local vs external domains
-- - Classifying message direction (inbound/outbound/internal)
--]]

local rspamd_logger = require "rspamd_logger"
local lua_util = require "lua_util"
local lua_maps = require "lua_maps"

local N = "lua_aliases"

local exports = {}

--- Count elements in a table (including hash tables)
-- @param tbl table to count
-- @return number of elements
local function table_length(tbl)
  if not tbl then return 0 end
  local count = 0
  for _ in pairs(tbl) do
    count = count + 1
  end
  return count
end

-- Module state
local module_state = {
  initialized = false,
  config = nil,
  local_domains = {},   -- Set of local domains or backend
  unix_aliases = {},    -- Unix aliases map or backend
  virtual_aliases = {}, -- Virtual aliases map or backend
  rspamd_aliases = {},  -- Rspamd-specific aliases
  cache = {},           -- Resolution cache
  backends = {},        -- Storage backends instances
}

--[[ Backend abstraction ]] --

--- Backend interface:
-- backend:get(key) -> value or nil
-- backend:type() -> string

-- File backend (already implemented via parse_* functions)
local FileBackend = {}
FileBackend.__index = FileBackend

function FileBackend.new(file_path, parser_func)
  local self = setmetatable({}, FileBackend)
  self.file_path = file_path
  self.parser_func = parser_func
  self.data = nil
  self.loaded = false
  return self
end

function FileBackend:load()
  if not self.loaded then
    self.data = self.parser_func(self.file_path)
    self.loaded = true
  end
  return self.data ~= nil
end

function FileBackend:get(key)
  if not self.loaded then
    self:load()
  end
  return self.data and self.data[key:lower()]
end

function FileBackend:type()
  return "file"
end

-- Map backend (using lua_maps)
local MapBackend = {}
MapBackend.__index = MapBackend

function MapBackend.new(rspamd_config, map_config, map_type)
  local self = setmetatable({}, MapBackend)
  self.map_type = map_type or 'hash'

  -- Create map using lua_maps
  self.map = lua_maps.map_add_from_ucl(map_config, self.map_type,
    'aliases map (' .. self.map_type .. ')')

  if not self.map then
    rspamd_logger.errx(rspamd_config, 'cannot create map from config: %s',
      map_config)
    return nil
  end

  return self
end

function MapBackend:get(key)
  if not self.map then
    return nil
  end

  local result = self.map:get_key(key:lower())
  return result
end

function MapBackend:type()
  return "map:" .. self.map_type
end

-- CDB backend (using existing CDB support)
local CDBBackend = {}
CDBBackend.__index = CDBBackend

function CDBBackend.new(rspamd_config, cdb_path)
  local self = setmetatable({}, CDBBackend)

  -- Use lua_maps CDB support
  local map_config = {
    cdb = cdb_path,
    external = true,
  }

  self.map = lua_maps.map_add_from_ucl(map_config, 'cdb', 'aliases cdb')
  if not self.map then
    rspamd_logger.errx(rspamd_config, 'cannot load CDB from %s', cdb_path)
    return nil
  end

  return self
end

function CDBBackend:get(key)
  if not self.map then
    return nil
  end

  return self.map:get_key(key:lower())
end

function CDBBackend:type()
  return "cdb"
end

-- Forward declarations for parser functions
local parse_unix_aliases
local parse_virtual_aliases
local parse_local_domains

--- Create backend from configuration
-- @param rspamd_config rspamd config object
-- @param config backend configuration (table or string)
-- @param default_parser default parser for file backend
-- @return backend instance or nil
local function create_backend(rspamd_config, config, default_parser)
  -- String path -> file backend
  if type(config) == 'string' then
    return FileBackend.new(config, default_parser)
  end

  -- Table configuration
  if type(config) ~= 'table' then
    return nil
  end

  local backend_type = config.type or 'file'

  if backend_type == 'file' then
    if config.path then
      return FileBackend.new(config.path, default_parser)
    end
  elseif backend_type == 'map' then
    if config.url or config.urls then
      return MapBackend.new(rspamd_config, config, config.map_type or 'hash')
    end
  elseif backend_type == 'redis' then
    rspamd_logger.errx(rspamd_config,
      'Redis backend is not supported for aliases (requires async with task context). Use CDB or Map instead.')
    return nil
  elseif backend_type == 'cdb' then
    if config.path then
      return CDBBackend.new(rspamd_config, config.path)
    end
  end

  rspamd_logger.errx(rspamd_config, 'unknown backend type or invalid config: %s', backend_type)
  return nil
end

--- Initialize the module with configuration
-- @param rspamd_config rspamd config object
-- @param opts configuration options
-- @return true on success
local function init(rspamd_config, opts)
  if module_state.initialized then
    rspamd_logger.warnx(rspamd_config, 'lua_aliases already initialized')
    return true
  end

  module_state.config = rspamd_config
  opts = opts or {}

  -- Load local domains
  if opts.local_domains then
    if type(opts.local_domains) == 'table' and not opts.local_domains.type then
      -- Inline array of domains
      for _, domain in ipairs(opts.local_domains) do
        module_state.local_domains[domain:lower()] = true
      end
      rspamd_logger.infox(rspamd_config, 'loaded %s local domains from inline config',
        #opts.local_domains)
    else
      -- Backend configuration
      local backend = create_backend(rspamd_config, opts.local_domains, parse_local_domains)
      if backend then
        module_state.backends.local_domains = backend
        rspamd_logger.infox(rspamd_config, 'initialized local domains backend: %s',
          backend:type())

        -- For file backend, load immediately
        if backend.type and backend:type() == 'file' then
          if backend:load() then
            module_state.local_domains = backend.data
            rspamd_logger.infox(rspamd_config, 'loaded %s local domains',
              table_length(module_state.local_domains))
          end
        end
      end
    end
  end

  -- Load system aliases
  if opts.system_aliases then
    local backend = create_backend(rspamd_config, opts.system_aliases, parse_unix_aliases)
    if backend then
      module_state.backends.system_aliases = backend
      rspamd_logger.infox(rspamd_config, 'initialized system aliases backend: %s',
        backend:type())

      -- For file backend, load immediately
      if backend.type and backend:type() == 'file' then
        if backend:load() then
          module_state.unix_aliases = backend.data
          rspamd_logger.infox(rspamd_config, 'loaded %s system aliases',
            table_length(module_state.unix_aliases))
        end
      else
        -- For other backends, keep reference
        module_state.unix_aliases = backend
      end
    end
  end

  -- Load virtual aliases
  if opts.virtual_aliases then
    local backend = create_backend(rspamd_config, opts.virtual_aliases, parse_virtual_aliases)
    if backend then
      module_state.backends.virtual_aliases = backend
      rspamd_logger.infox(rspamd_config, 'initialized virtual aliases backend: %s',
        backend:type())

      -- For file backend, load immediately
      if backend.type and backend:type() == 'file' then
        if backend:load() then
          module_state.virtual_aliases = backend.data
          rspamd_logger.infox(rspamd_config, 'loaded %s virtual aliases',
            table_length(module_state.virtual_aliases))
        end
      else
        -- For other backends, keep reference
        module_state.virtual_aliases = backend
      end
    end
  end

  -- Load rspamd-specific aliases (always inline)
  if opts.rspamd_aliases then
    if type(opts.rspamd_aliases) == 'table' then
      module_state.rspamd_aliases = opts.rspamd_aliases
      rspamd_logger.infox(rspamd_config, 'loaded %s rspamd aliases from inline config',
        table_length(opts.rspamd_aliases))
    end
  end

  module_state.initialized = true
  return true
end
exports.init = init

--- Parse Unix-style aliases file (/etc/aliases format)
-- Format:
--   alias: target1, target2, ...
--   # Comments
--   continuation lines with backslash \
--
-- @param file_path path to aliases file
-- @return table of aliases {alias -> {targets...}} or nil on error
function parse_unix_aliases(file_path)
  local aliases = {}

  local f, err = io.open(file_path, 'r')
  if not f then
    if module_state.config then
      rspamd_logger.warnx(module_state.config,
        'cannot open aliases file %s: %s', file_path, err)
    end
    return nil
  end

  local current_line = ""
  local line_num = 0

  for line in f:lines() do
    line_num = line_num + 1

    -- Strip trailing whitespace
    line = line:gsub('%s+$', '')

    -- Handle line continuation
    if line:match('\\$') then
      current_line = current_line .. line:gsub('\\$', '')
      goto continue
    else
      current_line = current_line .. line
    end

    -- Skip empty lines and comments
    if current_line:match('^%s*$') or current_line:match('^%s*#') then
      current_line = ""
      goto continue
    end

    -- Parse alias line: "alias: target1, target2, ..."
    local alias, targets = current_line:match('^%s*([^:]+):%s*(.*)$')

    if alias and targets then
      alias = alias:gsub('%s+$', ''):lower() -- Normalize alias

      -- Split targets by comma
      local target_list = {}
      for target in targets:gmatch('[^,]+') do
        target = target:gsub('^%s+', ''):gsub('%s+$', '') -- Trim

        -- Skip special targets for now (:include:, |program, /file)
        if not target:match('^:include:') and
            not target:match('^|') and
            not target:match('^/') then
          -- Normalize target
          target = target:lower()
          -- Add domain if missing and it's not email format
          if not target:match('@') then
            -- It's a local user, we'll handle it later
            table.insert(target_list, target)
          else
            table.insert(target_list, target)
          end
        else
          if module_state.config then
            rspamd_logger.debugm(N, module_state.config,
              'skipping special target in %s:%d: %s', file_path, line_num, target)
          end
        end
      end

      if #target_list > 0 then
        aliases[alias] = target_list
      end
    else
      if module_state.config then
        rspamd_logger.debugm(N, module_state.config,
          'cannot parse line %d in %s: %s', line_num, file_path, current_line)
      end
    end

    current_line = ""
    :: continue ::
  end

  f:close()
  return aliases
end

exports.parse_unix_aliases = parse_unix_aliases

--- Parse virtual aliases file (Postfix virtual format)
-- Format:
--   user@domain.com target@domain.com
--   @catchall.com   catchall@domain.com
--
-- @param file_path path to virtual aliases file
-- @return table of aliases {source -> target} or nil on error
function parse_virtual_aliases(file_path)
  local aliases = {}

  local f, err = io.open(file_path, 'r')
  if not f then
    if module_state.config then
      rspamd_logger.warnx(module_state.config,
        'cannot open virtual aliases file %s: %s', file_path, err)
    end
    return nil
  end

  local line_num = 0
  for line in f:lines() do
    line_num = line_num + 1

    -- Skip empty lines and comments
    if line:match('^%s*$') or line:match('^%s*#') then
      goto continue
    end

    -- Parse: source target
    local source, target = line:match('^%s*(%S+)%s+(%S+)')

    if source and target then
      source = source:lower()
      target = target:lower()
      aliases[source] = target
    else
      if module_state.config then
        rspamd_logger.debugm(N, module_state.config,
          'cannot parse line %d in %s: %s', line_num, file_path, line)
      end
    end

    :: continue ::
  end

  f:close()
  return aliases
end

exports.parse_virtual_aliases = parse_virtual_aliases

--- Parse local domains file (one domain per line)
-- Format:
--   example.com
--   mail.example.com
--   # comments
--
-- @param file_path path to local domains file
-- @return set of domains {domain -> true} or nil on error
function parse_local_domains(file_path)
  local domains = {}

  local f, err = io.open(file_path, 'r')
  if not f then
    if module_state.config then
      rspamd_logger.warnx(module_state.config,
        'cannot open local domains file %s: %s', file_path, err)
    end
    return nil
  end

  for line in f:lines() do
    -- Skip empty lines and comments
    if not line:match('^%s*$') and not line:match('^%s*#') then
      local domain = line:match('^%s*(%S+)')
      if domain then
        domains[domain:lower()] = true
      end
    end
  end

  f:close()
  return domains
end

exports.parse_local_domains = parse_local_domains

--- Get value from backend or table
-- @param source backend object or table
-- @param key lookup key
-- @return value or nil
local function get_from_source(source, key)
  if not source then
    return nil
  end

  -- If it's a backend object with :get() method
  if type(source) == 'table' and source.get then
    return source:get(key)
  end

  -- Otherwise treat as plain table
  return source[key]
end

--- Check if a domain is local
-- @param domain domain name to check
-- @return true if domain is local, false otherwise
local function is_local_domain(domain)
  if not domain then
    return false
  end

  domain = domain:lower()
  local result = get_from_source(module_state.local_domains, domain)

  lua_util.debugm(N, module_state.config,
      'is_local_domain: domain=%s result=%s',
      domain, result)

  return result ~= nil and result ~= false
end
exports.is_local_domain = is_local_domain

--- Check if an email address is local
-- @param addr email address (string or table with 'domain' field)
-- @return true if address is in local domain, false otherwise
local function is_local_address(addr)
  local domain

  if type(addr) == 'string' then
    domain = addr:match('@([^@]+)$')
  elseif type(addr) == 'table' and addr.domain then
    domain = addr.domain
  end

  return is_local_domain(domain)
end
exports.is_local_address = is_local_address

--- Apply service-specific alias rules (Gmail, plus-aliases)
-- This replaces the old lua_util.remove_email_aliases() function
-- @param email_addr email address table with user, domain, addr fields
-- @return new_user, tags, new_domain or nil
local function apply_service_rules(email_addr)
  local function check_gmail_user(addr)
    -- Remove all points
    local no_dots_user = string.gsub(addr.user, '%.', '')
    local cap, pluses = string.match(no_dots_user, '^([^%+][^%+]*)(%+.*)$')
    if cap then
      return cap, lua_util.str_split(pluses, '+'), nil
    elseif no_dots_user ~= addr.user then
      return no_dots_user, {}, nil
    end

    return nil
  end

  local function check_address(addr)
    if addr.user then
      local cap, pluses = string.match(addr.user, '^([^%+][^%+]*)(%+.*)$')
      if cap then
        return cap, lua_util.str_split(pluses, '+'), nil
      end
    end

    return nil
  end

  local function check_gmail(addr)
    local nu, tags, nd = check_gmail_user(addr)
    if nu then
      return nu, tags, nd
    end
    return nil
  end

  local function check_googlemail(addr)
    local nd = 'gmail.com'
    local nu, tags = check_gmail_user(addr)
    if nu then
      return nu, tags, nd
    end
    return nil, nil, nd
  end

  local specific_domains = {
    ['gmail.com'] = check_gmail,
    ['googlemail.com'] = check_googlemail,
  }

  if email_addr then
    if email_addr.domain and specific_domains[email_addr.domain] then
      local nu, tags, nd = specific_domains[email_addr.domain](email_addr)
      if nu or nd then
        return nu, tags, nd
      end
    else
      local nu, tags, nd = check_address(email_addr)
      if nu or nd then
        return nu, tags, nd
      end
    end

    return nil
  end
end
exports.apply_service_rules = apply_service_rules

--- Resolve one step of aliasing
-- @param email_str normalized email string
-- @return result (string, array of strings, or nil), rule_type
local function resolve_one_step(email_str)
  -- Check virtual aliases first
  local virtual_result = get_from_source(module_state.virtual_aliases, email_str)
  if virtual_result then
    return virtual_result, 'virtual'
  end

  -- Check rspamd aliases
  if module_state.rspamd_aliases[email_str] then
    return module_state.rspamd_aliases[email_str], 'rspamd'
  end

  -- Check unix aliases (user part only)
  local user = email_str:match('^([^@]+)@')
  if user then
    local unix_result = get_from_source(module_state.unix_aliases, user)
    if unix_result then
      -- Normalize result to always be array
      if type(unix_result) == 'string' then
        unix_result = { unix_result }
      end

      if type(unix_result) == 'table' and #unix_result > 0 then
        -- Add domain to targets that don't have one
        local domain = email_str:match('@([^@]+)$')
        if domain then
          local normalized = {}
          for _, target in ipairs(unix_result) do
            if not target:match('@') then
              table.insert(normalized, target .. '@' .. domain)
            else
              table.insert(normalized, target)
            end
          end
          return normalized, 'unix'
        else
          return unix_result, 'unix'
        end
      end
    end
  end

  -- No alias found
  return nil, nil
end

--- Resolve email address recursively with loop detection
-- @param addr email address (string or table)
-- @param opts options: max_depth, track_chain, expand_multiple
-- @return canonical (string or array), chain, metadata
local function resolve_address_recursive(addr, opts)
  opts = opts or {}
  local max_depth = opts.max_depth or 10
  local track_chain = opts.track_chain
  local expand_multiple = opts.expand_multiple

  -- Convert to normalized form
  local email_str
  if type(addr) == 'string' then
    email_str = addr:lower()
  elseif type(addr) == 'table' and addr.addr then
    email_str = addr.addr:lower()
  else
    return addr, nil, { error = 'invalid address format' }
  end

  -- Track visited addresses for loop detection
  local visited = {}
  local chain = track_chain and { email_str } or nil
  local rules_applied = {}

  --- Recursive resolve helper
  -- @param current_addr current address to resolve
  -- @param depth current recursion depth
  -- @param path current resolution path (for loop detection)
  -- @return array of canonical addresses
  local function resolve_recursive(current_addr, depth, path)
    path = path or {}
    -- Check depth limit
    if depth > max_depth then
      lua_util.debugm(N, module_state.config,
        'max recursion depth %s reached for %s', max_depth, email_str)
      return { current_addr }
    end

    -- Check for loops (only in current path, not all visited)
    if path[current_addr] then
      lua_util.debugm(N, module_state.config,
        'alias loop detected for %s at %s', email_str, current_addr)
      return { current_addr }
    end

    -- Track in visited for metadata
    visited[current_addr] = true
    -- Create new path with current address
    local new_path = {}
    for k, v in pairs(path) do
      new_path[k] = v
    end
    new_path[current_addr] = true

    -- Try to resolve one step
    local result, rule_type = resolve_one_step(current_addr)

    if not result then
      -- No more aliases, this is canonical
      return { current_addr }
    end

    -- Track rule application
    if rule_type and not rules_applied[rule_type] then
      rules_applied[rule_type] = 0
    end
    if rule_type then
      rules_applied[rule_type] = rules_applied[rule_type] + 1
    end

    -- Normalize result to array
    local targets
    if type(result) == 'string' then
      targets = { result }
    elseif type(result) == 'table' then
      targets = result
    else
      return { current_addr }
    end

    -- If we have multiple targets and expand_multiple is false, take first
    if #targets > 1 and not expand_multiple then
      if track_chain and chain then
        table.insert(chain, targets[1])
      end
      return resolve_recursive(targets[1], depth + 1, new_path)
    end

    -- Expand multiple targets
    local canonical_addrs = {}
    for _, target in ipairs(targets) do
      if track_chain and chain then
        table.insert(chain, target)
      end

      -- Recursively resolve each target with current path
      -- Each branch gets the same path, allowing convergence while detecting loops
      local resolved = resolve_recursive(target, depth + 1, new_path)
      for _, resolved_addr in ipairs(resolved) do
        table.insert(canonical_addrs, resolved_addr)
      end
    end

    return canonical_addrs
  end

  -- Start resolution
  local canonical_addrs = resolve_recursive(email_str, 1)

  -- Build metadata
  local metadata = {
    depth = table_length(visited),
    rules_applied = rules_applied,
    expanded = #canonical_addrs > 1,
  }

  -- Return result
  if #canonical_addrs == 1 then
    return canonical_addrs[1], chain, metadata
  else
    return canonical_addrs, chain, metadata
  end
end

--- Resolve a single email address (backward compatible, non-recursive)
-- @param addr email address (string or table)
-- @param opts options table (can specify max_depth)
-- @return canonical address or original address if no alias found
local function resolve_address(addr, opts)
  opts = opts or {}

  -- Use recursive resolver with specified depth (default 10 for compatibility)
  local simple_opts = {
    max_depth = opts.max_depth or 10,
    track_chain = opts.track_chain or false,
    expand_multiple = opts.expand_multiple or false,
  }

  local canonical = resolve_address_recursive(addr, simple_opts)
  return canonical
end
exports.resolve_address = resolve_address
exports.resolve_address_recursive = resolve_address_recursive

--- Classify message direction (inbound/outbound/internal/forwarded)
-- @param task rspamd task
-- @param opts classification options
-- @return classification table with direction, from_local, to_local, canonical addresses, etc.
local function classify_message(task, opts)
  opts = opts or {}
  local resolve_opts = {
    max_depth = opts.max_depth or 10,
    track_chain = opts.track_chain or false,
    expand_multiple = opts.expand_multiple or true,
  }

  local classification = {
    direction = nil,
    from_local = false,
    to_local = false,
    canonical_from = nil,
    canonical_recipients = {},
    forwarding_detected = nil,
    aliases_resolved = {
      from = nil,
      recipients = {},
    }
  }

  -- Get authenticated user and IP
  local user = task:get_user()
  local ip = task:get_ip()
  local is_authenticated = user ~= nil
  local is_local_ip = ip and ip:is_local()

  -- Resolve From address
  local from_smtp = task:get_from('smtp')
  if from_smtp and from_smtp[1] then
    local from_addr = from_smtp[1]

    -- Check if from is local domain
    classification.from_local = is_local_address(from_addr)

    -- Apply service rules to extract tags (but don't modify addr in task)
    local from_copy = {
      addr = from_addr.addr,
      user = from_addr.user,
      domain = from_addr.domain,
      name = from_addr.name,
    }
    local _, tags = apply_service_rules(from_copy)
    if tags and #tags > 0 then
      classification.from_tagged = tags
    end

    -- Resolve from address
    local canonical_from, from_chain, from_meta = resolve_address_recursive(
      from_addr, resolve_opts)

    classification.canonical_from = canonical_from
    classification.aliases_resolved.from = {
      chain = from_chain,
      metadata = from_meta,
    }
  end

  -- Resolve recipients
  local rcpts_smtp = task:get_recipients('smtp')
  if rcpts_smtp then
    local any_local = false
    local rcpt_count = 0

    for _, rcpt in ipairs(rcpts_smtp) do
      rcpt_count = rcpt_count + 1
      -- Check if recipient is local
      local rcpt_is_local = is_local_address(rcpt)
      if rcpt_is_local then
        any_local = true
      end

      -- Resolve recipient
      local canonical_rcpt, rcpt_chain, rcpt_meta = resolve_address_recursive(
        rcpt, resolve_opts)

      -- Handle multiple expansions
      if type(canonical_rcpt) == 'table' then
        for _, addr in ipairs(canonical_rcpt) do
          table.insert(classification.canonical_recipients, addr)
        end
      else
        table.insert(classification.canonical_recipients, canonical_rcpt)
      end

      table.insert(classification.aliases_resolved.recipients, {
        original = rcpt.addr,
        canonical = canonical_rcpt,
        chain = rcpt_chain,
        metadata = rcpt_meta,
        is_local = rcpt_is_local,
      })
    end

    classification.to_local = (rcpt_count > 0) and any_local
  end

  -- Determine direction
  if classification.from_local and classification.to_local then
    classification.direction = 'internal'
  elseif classification.from_local and not classification.to_local then
    classification.direction = 'outbound'
  elseif not classification.from_local and classification.to_local then
    classification.direction = 'inbound'
  else
    -- Neither from nor to is local - might be forwarded or external
    classification.direction = 'external'
  end

  -- Check for forwarding (from opts if provided by plugin)
  if opts.forwarding_detected then
    classification.forwarding_detected = {
      type = opts.forwarding_type,
      info = opts.forwarding_info,
    }
    classification.direction = 'forwarded'
  end

  -- Override with authenticated/local IP logic
  if is_authenticated or is_local_ip then
    -- Authenticated users or local IPs sending mail = outbound
    if not classification.to_local then
      classification.direction = 'outbound'
    elseif classification.to_local and classification.from_local then
      classification.direction = 'internal'
    end
  end

  return classification
end
exports.classify_message = classify_message

--- Get module state (for debugging)
-- @return module state table
local function get_state()
  return module_state
end
exports.get_state = get_state

--- Reset module state (for testing)
local function reset()
  module_state = {
    initialized = false,
    config = nil,
    local_domains = {},
    unix_aliases = {},
    virtual_aliases = {},
    rspamd_aliases = {},
    cache = {},
    backends = {},
  }
end
exports.reset = reset

return exports
