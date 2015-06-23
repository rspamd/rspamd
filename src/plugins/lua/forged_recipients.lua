--[[
Copyright (c) 2011-2015, Vsevolod Stakhov <vsevolod@highsecure.ru>
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

-- Plugin for comparing smtp dialog recipients and sender with recipients and sender
-- in mime headers

local logger = require "rspamd_logger"
local symbol_rcpt = 'FORGED_RECIPIENTS'
local symbol_sender = 'FORGED_SENDER'

local function check_forged_headers(task)
	local smtp_rcpt = task:get_recipients(1)
	local res = false
	
	if smtp_rcpt then
		local mime_rcpt = task:get_recipients(2)
		local count = 0
		if mime_rcpt then 
			count = table.maxn(mime_rcpt)
		end
		if count < table.maxn(smtp_rcpt) then
			task:insert_result(symbol_rcpt, 1)
		else
			-- Find pair for each smtp recipient recipient in To or Cc headers
			for _,sr in ipairs(smtp_rcpt) do
				if mime_rcpt then
					for _,mr in ipairs(mime_rcpt) do
						if string.lower(mr['addr']) == string.lower(sr['addr']) then
							res = true
							break
						end
					end
				end
				if not res then
					task:insert_result(symbol_rcpt, 1)
					break
				end
			end
		end
	end
	-- Check sender
	local smtp_from = task:get_from(1)
	if smtp_from and smtp_from[1] and smtp_from[1]['addr'] ~= '' then
		local mime_from = task:get_from(2)
		if not mime_from or not mime_from[1] or 
		  not (string.lower(mime_from[1]['addr']) == string.lower(smtp_from[1]['addr'])) then
			task:insert_result(symbol_sender, 1)
		end
	end
end

-- Registration
if type(rspamd_config.get_api_version) ~= 'nil' then
	if rspamd_config:get_api_version() >= 1 then
		rspamd_config:register_module_option('forged_recipients', 'symbol_rcpt', 'string')
		rspamd_config:register_module_option('forged_recipients', 'symbol_sender', 'string')
	end
end

-- Configuration
local opts =  rspamd_config:get_all_opt('forged_recipients')
if opts then
	if opts['symbol_rcpt'] or opts['symbol_sender'] then
    local id = rspamd_config:register_callback_symbol(1.0, 
      check_forged_headers)
		if opts['symbol_rcpt'] then
			symbol_rcpt = opts['symbol_rcpt']
			rspamd_config:register_virtual_symbol(symbol_rcpt, 1.0, id)
		end
		if opts['symbol_sender'] then
			symbol_sender = opts['symbol_sender']
			rspamd_config:register_virtual_symbol(symbol_sender, 1.0, id)
		end
	end
end