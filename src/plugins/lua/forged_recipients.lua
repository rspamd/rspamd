-- Plugin for comparing smtp dialog recipients and sender with recipients and sender
-- in mime headers

local symbol_rcpt = 'FORGED_RECIPIENTS'
local symbol_sender = 'FORGED_SENDER'

function check_forged_headers(task)
	local msg = task:get_message()
	local smtp_rcpt = task:get_recipients()
	local res = false
	
	if smtp_rcpt then
		local mime_rcpt = task:get_recipients_headers()
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
	local smtp_from = task:get_from()
	if smtp_form then
		local mime_from = task:get_from_headers()
		if not mime_from or not (string.lower(mime_from[1]['addr']) == string.lower(smtp_from[1]['addr'])) then
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
		if opts['symbol_rcpt'] then
			symbol_rcpt = opts['symbol_rcpt']
			if type(rspamd_config.get_api_version) ~= 'nil' then
				rspamd_config:register_virtual_symbol(symbol_rcpt, 1.0, 'check_forged_headers')
			end
		end
		if opts['symbol_sender'] then
			symbol_sender = opts['symbol_sender']
			if type(rspamd_config.get_api_version) ~= 'nil' then
				rspamd_config:register_virtual_symbol(symbol_sender, 1.0)
			end
		end
		if type(rspamd_config.get_api_version) ~= 'nil' then
			rspamd_config:register_callback_symbol('FORGED_RECIPIENTS', 1.0, 'check_forged_headers')
		else
			rspamd_config:register_symbol('FORGED_RECIPIENTS', 1.0, 'check_forged_headers')
		end
		
	end
end
