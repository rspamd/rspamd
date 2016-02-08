--[[
Copyright (c) 2015, Vsevolod Stakhov <vsevolod@highsecure.ru>

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

-- This plugin is a concept of FANN scores adjustment
-- NOT FOR PRODUCTION USE so far

local rspamd_logger = require "rspamd_logger"
local rspamd_fann = require "rspamd_fann"
local rspamd_util = require "rspamd_util"
local fann_symbol = 'FANN_SCORE'
local ucl = require "ucl"

-- Module vars
local fann
local symbols
local nsymbols = 0
local opts = rspamd_config:get_all_opt("fann_scores")

local function fann_scores_filter(task)
  local fann_input = {}

  for sym,idx in pairs(symbols) do
    if task:has_symbol(sym) then
      fann_input[idx + 1] = 1
    else
      fann_input[idx + 1] = 0
    end
  end

  local out = fann:test(nsymbols, fann_input)
  local result = rspamd_util.tanh(2 * (out[1] - 0.5))
  local symscore = string.format('%.3f', out[1])
  rspamd_logger.infox(task, 'fann score: %s', symscore)

  task:insert_result(fann_symbol, result, symscore)
end

if not rspamd_fann.is_enabled() then
  rspamd_logger.errx(rspamd_config, 'fann is not compiled in rspamd, this ' ..
    'module is eventually disabled')
else
  if not opts['fann_file'] or not opts['symbols_file'] then
    rspamd_logger.errx(rspamd_config, 'fann_scores module requires ' ..
      '`fann_file` and `symbols_file` to be specified')
  else
    fann = rspamd_fann.load(opts['fann_file'])

    if not fann then
      rspamd_logger.errx(rspamd_config, 'cannot load fann from %s',
        opts['fann_file'])
      return
    end
    -- Parse symbols
    local parser = ucl.parser()
    local res, err = parser:parse_file(opts['symbols_file'])
    if not res then
      rspamd_logger.errx(rspamd_config, 'cannot load symbols from %s: %s',
        opts['symbols_file'], err)
      return
    end

    symbols = parser:get_object()

    -- Check sanity
    for _,s in pairs(symbols) do nsymbols = nsymbols + 1 end
    if fann:get_inputs() ~= nsymbols then
      rspamd_logger.errx(rspamd_config, 'fann number of inputs: %s is not equal' ..
          ' to symbols count: %s',
        fann:get_inputs(), nsymbols)
      return
    end

    if fann:get_outputs() ~= 1 then
      rspamd_logger.errx(rspamd_config, 'fann nuber of outputs is invalid: %s',
        fann:get_outputs())
      return
    end

    rspamd_config:set_metric_symbol(fann_symbol, 3.0, 'Experimental FANN adjustment')
    rspamd_config:register_post_filter(fann_scores_filter)
  end
end
