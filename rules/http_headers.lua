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

local logger = require "rspamd_logger"
local ucl = require "ucl"

-- Disable DKIM checks if passed via HTTP headers
rspamd_config:add_condition("R_DKIM_ALLOW", function(task)
  local hdr = task:get_request_header('DKIM')

  if hdr then
    local parser = ucl.parser()
    local res, err = parser:parse_string(tostring(hdr))
    if not res then
      logger.infox(task, "cannot parse DKIM header: %1", err)
      return true
    end

    local obj = parser:get_object()

    if obj['result'] then
      if obj['result'] == 'pass' or obj['result'] == 'allow' then
        task:insert_result('R_DKIM_ALLOW', 1.0, 'http header')
      elseif obj['result'] == 'fail' or obj['result'] == 'reject' then
        task:insert_result('R_DKIM_REJECT', 1.0, 'http header')
      elseif obj['result'] == 'tempfail' or obj['result'] == 'softfail' then
        task:insert_result('R_DKIM_TEMPFAIL', 1.0, 'http header')
      end

      return false
    end
  end

  return true
end)

-- Disable DKIM checks if passed via HTTP headers
rspamd_config:add_condition("R_SPF_ALLOW", function(task)
  local hdr = task:get_request_header('SPF')

  if hdr then
    local parser = ucl.parser()
    local res, err = parser:parse_string(tostring(hdr))
    if not res then
      logger.infox(task, "cannot parse SPF header: %1", err)
      return true
    end

    local obj = parser:get_object()

    if obj['result'] then
      if obj['result'] == 'pass' or obj['result'] == 'allow' then
        task:insert_result('R_SPF_ALLOW', 1.0, 'http header')
      elseif obj['result'] == 'fail' or obj['result'] == 'reject' then
        task:insert_result('R_SPF_FAIL', 1.0, 'http header')
      elseif obj['result'] == 'neutral' then
        task:insert_result('R_SPF_NEUTRAL', 1.0, 'http header')
      elseif obj['result'] == 'tempfail' or obj['result'] == 'softfail' then
        task:insert_result('R_SPF_SOFTFAIL', 1.0, 'http header')
      end

      return false
    end
  end

  return true
end)

rspamd_config:add_condition("DMARC_POLICY_ALLOW", function(task)
  local hdr = task:get_request_header('DMARC')

  if hdr then
    local parser = ucl.parser()
    local res, err = parser:parse_string(tostring(hdr))
    if not res then
      logger.infox(task, "cannot parse DMARC header: %1", err)
      return true
    end

    local obj = parser:get_object()

    if obj['result'] then
      if obj['result'] == 'pass' or obj['result'] == 'allow' then
        task:insert_result('DMARC_POLICY_ALLOW', 1.0, 'http header')
      elseif obj['result'] == 'fail' or obj['result'] == 'reject' then
        task:insert_result('DMARC_POLICY_REJECT', 1.0, 'http header')
      elseif obj['result'] == 'quarantine' then
        task:insert_result('DMARC_POLICY_QUARANTINE', 1.0, 'http header')
      elseif obj['result'] == 'tempfail' or obj['result'] == 'softfail' then
        task:insert_result('DMARC_POLICY_SOFTFAIL', 1.0, 'http header')
      end

      return false
    end
  end

  return true
end)

