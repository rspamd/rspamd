--[[
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

local ansicolors = require "ansicolors"
local local_conf = rspamd_paths['CONFDIR']
local rspamd_util = require "rspamd_util"
local rspamd_logger = require "rspamd_logger"
local lua_util = require "lua_util"
local lua_stat_tools = require "lua_stat"
local lua_redis = require "lua_redis"
local ucl = require "ucl"
local argparse = require "argparse"
local fun = require "fun"

local plugins_stat = require "plugins_stats"

local rspamd_logo = [[
  ____                                     _
 |  _ \  ___  _ __    __ _  _ __ ___    __| |
 | |_) |/ __|| '_ \  / _` || '_ ` _ \  / _` |
 |  _ < \__ \| |_) || (_| || | | | | || (_| |
 |_| \_\|___/| .__/  \__,_||_| |_| |_| \__,_|
             |_|
]]

local parser = argparse()
    :name "rspamadm configwizard"
    :description "Perform guided configuration for Rspamd daemon"
    :help_description_margin(32)
parser:option "-c --config"
      :description "Path to config file"
      :argname("<file>")
      :default(rspamd_paths["CONFDIR"] .. "/" .. "rspamd.conf")
parser:argument "checks"
      :description "Checks to do (or 'list')"
      :argname("<checks>")
      :args "*"

local redis_params

local function printf(fmt, ...)
  if fmt then
    io.write(string.format(fmt, ...))
  end
  io.write('\n')
end

local function highlight(str)
  return ansicolors.white .. str .. ansicolors.reset
end

local function ask_yes_no(greet, default)
  local def_str
  if default then
    greet = greet .. "[Y/n]: "
    def_str = "yes"
  else
    greet = greet .. "[y/N]: "
    def_str = "no"
  end

  local reply = rspamd_util.readline(greet)

  if not reply then os.exit(0) end
  if #reply == 0 then reply = def_str end
  reply = reply:lower()
  if reply == 'y' or reply == 'yes' then return true end

  return false
end

local function readline_default(greet, def_value)
  local reply = rspamd_util.readline(greet)
  if not reply then os.exit(0) end

  if #reply == 0 then return def_value end

  return reply
end

local function readline_expire()
  local expire = '100d'
  repeat
    expire = readline_default("Expire time for new tokens [" .. expire .. "]: ",
      expire)
    expire = lua_util.parse_time_interval(expire)

    if not expire then
      expire = '100d'
    elseif expire > 2147483647 then
      printf("The maximum possible value is 2147483647 (about 68y)")
      expire = '68y'
    elseif expire < -1 then
      printf("The value must be a non-negative integer or -1")
      expire = -1
    elseif expire ~= math.floor(expire) then
      printf("The value must be an integer")
      expire = math.floor(expire)
    else
      return expire
    end
  until false
end

local function print_changes(changes)
  local function print_change(k, c, where)
    printf('File: %s, changes list:', highlight(local_conf .. '/'
        .. where .. '/'.. k))

    for ek,ev in pairs(c) do
      printf("%s => %s", highlight(ek), rspamd_logger.slog("%s", ev))
    end
  end
  for k, v in pairs(changes.l) do
    print_change(k, v, 'local.d')
    if changes.o[k] then
      v = changes.o[k]
      print_change(k, v, 'override.d')
    end
    print()
  end
end

local function apply_changes(changes)
  local function dirname(fname)
    if fname:match(".-/.-") then
      return string.gsub(fname, "(.*/)(.*)", "%1")
    else
      return nil
    end
  end

  local function apply_change(k, c, where)
    local fname = local_conf .. '/' .. where .. '/'.. k

    if not rspamd_util.file_exists(fname) then
      printf("Create file %s", highlight(fname))

      local dname = dirname(fname)

      if dname then
        local ret, err = rspamd_util.mkdir(dname, true)

        if not ret then
          printf("Cannot make directory %s: %s", dname, highlight(err))
          os.exit(1)
        end
      end
    end

    local f = io.open(fname, "a+")

    if not f then
      printf("Cannot open file %s, aborting", highlight(fname))
      os.exit(1)
    end

    f:write(ucl.to_config(c))

    f:close()
  end
  for k, v in pairs(changes.l) do
    apply_change(k, v, 'local.d')
    if changes.o[k] then
      v = changes.o[k]
      apply_change(k, v, 'override.d')
    end
  end
end


local function setup_controller(controller, changes)
  printf("Setup %s and controller worker:", highlight("WebUI"))

  if not controller.password or controller.password == 'q1' then
    if ask_yes_no("Controller password is not set, do you want to set one?", true) then
      local pw_encrypted = rspamadm.pw_encrypt()
      if pw_encrypted then
        printf("Set encrypted password to: %s", highlight(pw_encrypted))
        changes.l['worker-controller.inc'] = {
          password = pw_encrypted
        }
      end
    end
  end
end

local function setup_redis(cfg, changes)
  local function parse_servers(servers)
    local ls = lua_util.rspamd_str_split(servers, ",")

    return ls
  end

  printf("%s servers are not set:", highlight("Redis"))
  printf("The following modules will be enabled if you add Redis servers:")

  for k,_ in pairs(rspamd_plugins_state.disabled_redis) do
    printf("\t* %s", highlight(k))
  end

  if ask_yes_no("Do you wish to set Redis servers?", true) then
    local read_servers = readline_default("Input read only servers separated by `,` [default: localhost]: ",
      "localhost")

    local rs = parse_servers(read_servers)
    if rs and #rs > 0 then
      changes.l['redis.conf'] = {
        read_servers = table.concat(rs, ",")
      }
    end
    local write_servers = readline_default("Input write only servers separated by `,` [default: "
        .. read_servers .. "]: ", read_servers)

    if not write_servers or #write_servers == 0 then
      printf("Use read servers %s as write servers", highlight(table.concat(rs, ",")))
      write_servers = read_servers
    end

    redis_params = {
      read_servers = rs,
    }

    local ws = parse_servers(write_servers)
    if ws and #ws > 0 then
      changes.l['redis.conf']['write_servers'] = table.concat(ws, ",")
      redis_params['write_servers'] = ws
    end

    if ask_yes_no('Do you have any password set for your Redis?') then
      local passwd = readline_default("Enter Redis password:", nil)

      if passwd then
        changes.l['redis.conf']['password'] = passwd
        redis_params['password'] = passwd
      end
    end

    if ask_yes_no('Do you have any specific database for your Redis?') then
      local db = readline_default("Enter Redis database:", nil)

      if db then
        changes.l['redis.conf']['db'] = db
        redis_params['db'] = db
      end
    end
  end
end

local function setup_dkim_signing(cfg, changes)
  -- Remove the trailing slash of a pathname, if present.
  local function remove_trailing_slash(path)
    if string.sub(path, -1) ~= "/" then return path end
    return string.sub(path, 1, string.len(path) - 1)
  end

  printf('How would you like to set up DKIM signing?')
  printf('1. Use domain from %s for sign', highlight('mime from header'))
  printf('2. Use domain from %s for sign', highlight('SMTP envelope from'))
  printf('3. Use domain from %s for sign', highlight('authenticated user'))
  printf('4. Sign all mail from %s', highlight('specific networks'))
  printf()

  local sign_type = readline_default('Enter your choice (1, 2, 3, 4) [default: 1]: ', '1')
  local sign_networks
  local allow_mismatch
  local sign_authenticated
  local use_esld
  local sign_domain = 'pet luacheck'

  local defined_auth_types = {'header', 'envelope', 'auth', 'recipient'}

  if sign_type == '4' then
    repeat
      sign_networks = readline_default('Enter list of networks to perform dkim signing: ',
          '')
    until #sign_networks ~= 0

    sign_networks = fun.totable(fun.map(lua_util.rspamd_str_trim,
        lua_util.str_split(sign_networks, ',; ')))
    printf('What domain would you like to use for signing?')
    printf('* %s to use mime from domain', highlight('header'))
    printf('* %s to use SMTP from domain', highlight('envelope'))
    printf('* %s to use domain from SMTP auth', highlight('auth'))
    printf('* %s to use domain from SMTP recipient', highlight('recipient'))
    printf('* anything else to use as a %s domain (e.g. `example.com`)', highlight('static'))
    printf()

    sign_domain = readline_default('Enter your choice [default: header]: ', 'header')
  else
    if sign_type == '1' then
      sign_domain = 'header'
    elseif sign_type == '2' then
      sign_domain = 'envelope'
    else
      sign_domain = 'auth'
    end
  end

  if sign_type ~= '3' then
    sign_authenticated = ask_yes_no(
        string.format('Do you want to sign mail from %s? ',
            highlight('authenticated users')), true)
  else
    sign_authenticated = true
  end

  if fun.any(function(s) return s == sign_domain end, defined_auth_types) then
    -- Allow mismatch
    allow_mismatch = ask_yes_no(
        string.format('Allow data %s, e.g. if mime from domain is not equal to authenticated user domain? ',
            highlight('mismatch')), true)
    -- ESLD check
    use_esld = ask_yes_no(
        string.format('Do you want to use %s domain (e.g. example.com instead of foo.example.com)? ',
            highlight('effective')), true)
  else
    allow_mismatch = true
  end

  local domains = {}
  local has_domains = false

  local dkim_keys_dir = rspamd_paths["DBDIR"] .. "/dkim/"

  local prompt = string.format("Enter output directory for the keys [default: %s]: ",
    highlight(dkim_keys_dir))
  dkim_keys_dir = remove_trailing_slash(readline_default(prompt, dkim_keys_dir))

  local ret, err = rspamd_util.mkdir(dkim_keys_dir, true)

  if not ret then
    printf("Cannot make directory %s: %s", dkim_keys_dir, highlight(err))
    os.exit(1)
  end

  local function print_domains()
    printf("Domains configured:")
    for k,v in pairs(domains) do
      printf("Domain: %s, selector: %s, privkey: %s", highlight(k),
          v.selector, v.privkey)
    end
    printf("--")
  end

  repeat
    if has_domains then
      print_domains()
    end

    local domain
    repeat
      domain = rspamd_util.readline("Enter domain to sign: ")
      if not domain then
        os.exit(1)
      end
    until #domain ~= 0

    local selector = readline_default("Enter selector [default: dkim]: ", 'dkim')
    if not selector then selector = 'dkim' end

    local privkey_file = string.format("%s/%s.%s.key", dkim_keys_dir, domain,
        selector)
    if not rspamd_util.file_exists(privkey_file) then
      if ask_yes_no("Do you want to create privkey " .. highlight(privkey_file),
        true) then
        local pubkey_file = privkey_file .. ".pub"
        rspamadm.dkim_keygen(domain, selector, privkey_file, pubkey_file, 2048)

        local f = io.open(pubkey_file)
        if not f then
          printf("Cannot open pubkey file %s, fatal error", highlight(pubkey_file))
          os.exit(1)
        end

        local content = f:read("*all")
        f:close()
        print("To make dkim signing working, you need to place the following record in your DNS zone:")
        print(content)
      end
    end

    domains[domain] = {
      selector = selector,
      path = privkey_file,
    }
  until not ask_yes_no("Do you wish to add another DKIM domain?")

  changes.l['dkim_signing.conf'] = {domain = domains}
  local res_tbl = changes.l['dkim_signing.conf']

  if sign_networks then
    res_tbl.sign_networks = sign_networks
    res_tbl.use_domain_sign_networks = sign_domain
  else
    res_tbl.use_domain = sign_domain
  end

  if allow_mismatch then
    res_tbl.allow_hdrfrom_mismatch = true
    res_tbl.allow_hdrfrom_mismatch_sign_networks = true
    res_tbl.allow_username_mismatch = true
  end

  res_tbl.use_esld = use_esld
  res_tbl.sign_authenticated = sign_authenticated
end

local function check_redis_classifier(cls, changes)
  local symbol_spam, symbol_ham
  -- Load symbols from statfiles
  local statfiles = cls.statfile
  for _,stf in ipairs(statfiles) do
    local symbol = stf.symbol or 'undefined'

    local spam
    if stf.spam then
      spam = stf.spam
    else
      if string.match(symbol:upper(), 'SPAM') then
        spam = true
      else
        spam = false
      end
    end

    if spam then
      symbol_spam = symbol
    else
      symbol_ham = symbol
    end
  end

  if not symbol_spam or not symbol_ham then
    printf("Calssifier has no symbols defined")
    return
  end

  local parsed_redis = lua_redis.try_load_redis_servers(cls, nil)

  if not parsed_redis and redis_params then
    parsed_redis = lua_redis.try_load_redis_servers(redis_params, nil)
    if not parsed_redis then
      printf("Cannot parse Redis params")
      return
    end
  end

  local function try_convert(update_config)
    if ask_yes_no("Do you wish to convert data to the new schema?", true) then
      local expire = readline_expire()
      if not lua_stat_tools.convert_bayes_schema(parsed_redis, symbol_spam,
          symbol_ham, expire) then
        printf("Conversion failed")
      else
        printf("Conversion succeed")
        if update_config then
          changes.l['classifier-bayes.conf'] = {
            new_schema = true,
          }

          if expire then
            changes.l['classifier-bayes.conf'].expire = expire
          end
        end
      end
    end
  end

  local function get_version(conn)
    conn:add_cmd("SMEMBERS", {"RS_keys"})

    local ret,members = conn:exec()

    -- Empty db
    if not ret or #members == 0 then return false,0 end

    -- We still need to check versions
    local lua_script = [[
local ver = 0

local tst = redis.call('GET', KEYS[1]..'_version')
if tst then
  ver = tonumber(tst) or 0
end

return ver
]]
    conn:add_cmd('EVAL', {lua_script, '1', 'RS'})
    local _,ver = conn:exec()

    return true,tonumber(ver)
  end

  local function check_expire(conn)
    -- We still need to check versions
    local lua_script = [[
local ttl = 0

local sc = redis.call('SCAN', 0, 'MATCH', 'RS*_*', 'COUNT', 1)
local _,key = sc[1], sc[2]

if key and key[1] then
  ttl = redis.call('TTL', key[1])
end

return ttl
]]
    conn:add_cmd('EVAL', {lua_script, '0'})
    local _,ttl = conn:exec()

    return tonumber(ttl)
  end

  local res,conn = lua_redis.redis_connect_sync(parsed_redis, true)
  if not res then
    printf("Cannot connect to Redis server")
    return false
  end

  if not cls.new_schema then
    local r,ver = get_version(conn)
    if not r then return false end
    if ver ~= 2 then
      if not ver then
        printf('Key "RS_version" has not been found in Redis for %s/%s',
            symbol_ham, symbol_spam)
      else
        printf("You are using an old schema version: %s for %s/%s",
            ver, symbol_ham, symbol_spam)
      end
      try_convert(true)
    else
      printf("You have configured an old schema for %s/%s but your data has new layout",
          symbol_ham, symbol_spam)

      if ask_yes_no("Switch config to the new schema?", true) then
        changes.l['classifier-bayes.conf'] = {
          new_schema = true,
        }

        local expire = check_expire(conn)
        if expire then
          changes.l['classifier-bayes.conf'].expire = expire
        end
      end
    end
  else
    local r,ver = get_version(conn)
    if not r then return false end
    if ver ~= 2 then
      printf("You have configured new schema for %s/%s but your DB has old version: %s",
        symbol_spam, symbol_ham, ver)
      try_convert(false)
    else
      printf(
          'You have configured new schema for %s/%s and your DB already has new layout (v. %s).' ..
              ' DB conversion is not needed.',
        symbol_spam, symbol_ham, ver)
    end
  end
end

local function setup_statistic(cfg, changes)
  local sqlite_configs = lua_stat_tools.load_sqlite_config(cfg)

  if #sqlite_configs > 0 then

    if not redis_params then
      printf('You have %d sqlite classifiers, but you have no Redis servers being set',
        #sqlite_configs)
      return false
    end

    local parsed_redis = lua_redis.try_load_redis_servers(redis_params, nil)
    if parsed_redis then
      printf('You have %d sqlite classifiers', #sqlite_configs)
      local expire = readline_expire()

      local reset_previous = ask_yes_no("Reset previous data?")
      if ask_yes_no('Do you wish to convert them to Redis?', true) then

        for _,cls in ipairs(sqlite_configs) do
          if rspamd_util.file_exists(cls.db_spam) and rspamd_util.file_exists(cls.db_ham) then
            if not lua_stat_tools.convert_sqlite_to_redis(parsed_redis, cls.db_spam,
                cls.db_ham, cls.symbol_spam, cls.symbol_ham, cls.learn_cache, expire,
                reset_previous) then
              rspamd_logger.errx('conversion failed')

              return false
            end
          else
            rspamd_logger.messagex('cannot find %s and %s, skip conversion',
                cls.db_spam, cls.db_ham)
          end

          rspamd_logger.messagex('Converted classifier to the from sqlite to redis')
          changes.l['classifier-bayes.conf'] = {
            backend = 'redis',
            new_schema = true,
          }

          if expire then
            changes.l['classifier-bayes.conf'].expire = expire
          end

          if cls.learn_cache then
            changes.l['classifier-bayes.conf'].cache = {
              backend = 'redis'
            }
          end
        end
      end
    end
  else
    -- Check sanity for the existing Redis classifiers
    local classifier = cfg.classifier

    if classifier then
      if classifier[1] then
        for _,cls in ipairs(classifier) do
          if cls.bayes then cls = cls.bayes end
          if cls.backend and cls.backend == 'redis' then
            check_redis_classifier(cls, changes)
          end
        end
      else
        if classifier.bayes then

          classifier = classifier.bayes
          if classifier[1] then
            for _,cls in ipairs(classifier) do
              if cls.backend and cls.backend == 'redis' then
                check_redis_classifier(cls, changes)
              end
            end
          else
            if classifier.backend and classifier.backend == 'redis' then
              check_redis_classifier(classifier, changes)
            end
          end
        end
      end
    end
  end
end

local function find_worker(cfg, wtype)
  if cfg.worker then
    for k,s in pairs(cfg.worker) do
      if type(k) == 'number' and type(s) == 'table' then
        if s[wtype] then return s[wtype] end
      end
      if type(s) == 'table' and s.type and s.type == wtype then
        return s
      end
      if type(k) == 'string' and k == wtype then return s end
    end
  end

  return nil
end



return {
  handler = function(cmd_args)
    local changes = {
      l = {}, -- local changes
      o = {}, -- override changes
    }

    local interactive_start = true
    local checks = {}
    local all_checks = {
      'controller',
      'redis',
      'dkim',
      'statistic',
    }

    local opts = parser:parse(cmd_args)
    local args = opts['checks'] or {}

    local _r,err = rspamd_config:load_ucl(opts['config'])

    if not _r then
      rspamd_logger.errx('cannot parse %s: %s', opts['config'], err)
      os.exit(1)
    end

    _r,err = rspamd_config:parse_rcl({'logging', 'worker'})
    if not _r then
      rspamd_logger.errx('cannot process %s: %s', opts['config'], err)
      os.exit(1)
    end

    local cfg = rspamd_config:get_ucl()

    if not rspamd_config:init_modules() then
      rspamd_logger.errx('cannot init modules when parsing %s', opts['config'])
      os.exit(1)
    end

    if #args > 0 then
      interactive_start = false

      for _,arg in ipairs(args) do
        if arg == 'all' then
          checks = all_checks
        elseif arg == 'list' then
          printf(highlight(rspamd_logo))
          printf('Available modules')
          for _,c in ipairs(all_checks) do
            printf('- %s', c)
          end
          return
        else
          table.insert(checks, arg)
        end
      end
    else
      checks = all_checks
    end

    local function has_check(check)
      for _,c in ipairs(checks) do
        if c == check then
          return true
        end
      end

      return false
    end

    rspamd_util.umask('022')
    if interactive_start then
      printf(highlight(rspamd_logo))
      printf("Welcome to the configuration tool")
      printf("We use %s configuration file, writing results to %s",
          highlight(opts['config']), highlight(local_conf))
      plugins_stat(nil, nil)
    end

    if not interactive_start or
        ask_yes_no("Do you wish to continue?", true) then

      if has_check('controller') then
        local controller = find_worker(cfg, 'controller')
        if controller then
          setup_controller(controller, changes)
        end
      end

      if has_check('redis') then
        if not cfg.redis or (not cfg.redis.servers and not cfg.redis.read_servers) then
          setup_redis(cfg, changes)
        else
          redis_params = cfg.redis
        end
      else
        redis_params = cfg.redis
      end

      if has_check('dkim') then
        if cfg.dkim_signing and not cfg.dkim_signing.domain then
          if ask_yes_no('Do you want to setup dkim signing feature?') then
            setup_dkim_signing(cfg, changes)
          end
        end
      end

      if has_check('statistic') or has_check('statistics') then
        setup_statistic(cfg, changes)
      end

      local nchanges = 0
      for _,_ in pairs(changes.l) do nchanges = nchanges + 1 end
      for _,_ in pairs(changes.o) do nchanges = nchanges + 1 end

      if nchanges > 0 then
        print_changes(changes)
        if ask_yes_no("Apply changes?", true) then
          apply_changes(changes)
          printf("%d changes applied, the wizard is finished now", nchanges)
          printf("*** Please reload the Rspamd configuration ***")
        else
          printf("No changes applied, the wizard is finished now")
        end
      else
        printf("No changes found, the wizard is finished now")
      end
    end
  end,
  name = 'configwizard',
  description = parser._description,
}

