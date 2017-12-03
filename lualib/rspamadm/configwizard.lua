--[[
Copyright (c) 2017, Vsevolod Stakhov <vsevolod@highsecure.ru>

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

local ansicolors = require "rspamadm/ansicolors"
local local_conf = rspamd_paths['CONFDIR']
local rspamd_util = require "rspamd_util"
local rspamd_logger = require "rspamd_logger"
local lua_util = require "lua_util"

local plugins_stat = require "rspamadm/plugins_stats"

local function printf(fmt, ...)
  print(string.format(fmt, ...))
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

    for ek,ev in pairs(c) do
      f:write(rspamd_logger.slog("%s = %s; # Set from configwizard\n", ek, ev))
    end

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
    local read_servers = rspamd_util.readline("Input read only servers separated by `,` [default: localhost]: ")

    if not read_servers or #read_servers == 0 then
      read_servers = "localhost"
    end

    local rs = parse_servers(read_servers)
    if rs and #rs > 0 then
      changes.l['redis.conf'] = {
        read_servers = table.concat(rs, ",")
      }
    end
    local write_servers = rspamd_util.readline("Input write only servers separated by `,` [default: "
        .. read_servers .. "]: ")

    if not write_servers or #write_servers == 0 then
      printf("Use read servers %s as write servers", highlight(table.concat(rs, ",")))
      write_servers = read_servers
    end

    local ws = parse_servers(write_servers)
    if ws and #ws > 0 then
      changes.l['redis.conf']['write_servers'] = table.concat(ws, ",")
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

return function(args, cfg)
  local changes = {
    l = {}, -- local changes
    o = {}, -- override changes
  }

  rspamd_util.umask('022')
  printf("Welcome to %s configuration tool", highlight("Rspamd"))
  printf("We use %s configuration file, writing results to %s",
    highlight(cfg.config_path), highlight(local_conf))
  plugins_stat(nil, nil)
  if ask_yes_no("Do you wish to continue?", true) then

    local controller = find_worker(cfg, 'controller')
    if controller then
      setup_controller(controller, changes)
    end

    if not cfg.redis or (not cfg.redis.servers and not cfg.redis.read_servers) then
      setup_redis(cfg, changes)
    end

    local nchanges = 0
    for _,_ in pairs(changes.l) do nchanges = nchanges + 1 end
    for _,_ in pairs(changes.o) do nchanges = nchanges + 1 end

    if nchanges > 0 then
      print_changes(changes)
      if ask_yes_no("Apply changes?", true) then
        apply_changes(changes)
        printf("%d changes applied, the wizard is finished now", nchanges)
      else
        printf("No changes applied, the wizard is finished now")
      end
    else
      printf("No changes found, the wizard is finished now")
    end
  end
end

