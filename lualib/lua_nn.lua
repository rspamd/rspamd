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

local rspamd_logger = require "rspamd_logger"
local torch
local exports = {}

local lua_nn_models = {}

local conf_section = rspamd_config:get_all_opt("nn_models")

if conf_section then
  if rspamd_config:has_torch() then
    torch = require "torch"
    torch.setnumthreads(1)
  end
end

if torch then
  exports.load_rspamd_nn = function()
    local function gen_process_callback(name)
      return function(str)
        if str then
          local f = torch.MemoryFile(torch.CharStorage():string(str))
          local ret, tnn_or_err = pcall(function() f:readObject() end)
          if not ret then
            rspamd_logger.errx(rspamd_config, "cannot load neural net model %s: %s",
              name, tnn_or_err)
          else
            rspamd_logger.infox(rspamd_config, "loaded NN model %s: %s bytes",
              name, #str)
            lua_nn_models[name] = tnn_or_err
          end
        end
      end
    end

    if conf_section and type(conf_section) == 'table' then
      for k,v in pairs(conf_section) do
        if not rspamd_config:add_map(v, "nn map " .. k, gen_process_callback(k)) then
          rspamd_logger.warnx(rspamd_config, 'cannot load NN map %1', k)
        end
      end
    end
  end
  exports.try_rspamd_nn = function(name, input)
    if not lua_nn_models.name then
      return false, 0.0
    else
      local ret, res_or_err = pcall(function() lua_nn_models.name:forward(input) end)
      if not ret then
        rspamd_logger.errx(rspamd_config, "cannot run neural net model %s: %s",
          name, res_or_err)
      else
        return true, tonumber(res_or_err)
      end
    end

    return false, 0.0
  end
else
  exports.load_rspamd_nn = function()
  end
  exports.try_rspamd_nn = function(name, input)
    return false,0.0
  end
end

return exports