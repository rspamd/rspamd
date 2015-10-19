--[[
Copyright (c) 2015, Vsevolod Stakhov <vsevolod@highsecure.ru>
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this
list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice,
this list of conditions and the following disclaimer in the documentation
and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
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
        task:insert_result('R_SPF_TEMPFAIL', 1.0, 'http header')
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

