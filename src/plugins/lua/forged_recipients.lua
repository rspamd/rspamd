-- Plugin for comparing smtp dialog recipients and sender with recipients and sender
-- in mime headers

local symbol_rcpt = 'FORGED_RECIPIENTS'
local symbol_sender = 'FORGED_SENDER'

function check_forged_headers(task)
	local msg = task:get_message()
	local smtp_rcpt = task:get_recipients()
	local res = false
	
	if smtp_rcpt then
		local mime_rcpt = msg:get_header('To')
		local mime_cc = msg:get_header('Cc')
		local count = 0
		if mime_rcpt then
			count = table.maxn(mime_rcpt)
		end
		if mime_cc then
			count = count + table.maxn(mime_cc)
		end
		-- Check recipients count
		if count < table.maxn(smtp_rcpt) then
			task:insert_result(symbol_rcpt, 1)
		else
			-- Find pair for each smtp recipient recipient in To or Cc headers
			for _,sr in ipairs(smtp_rcpt) do
				if sr:sub(1,1) == '<' then
					-- Trim brackets
					sr = string.sub(sr, 2, -2)
				end
				if mime_rcpt then
					for _,mr in ipairs(mime_rcpt) do
						if string.find(mr, sr) then
							res = true
							break
						end
					end
				end
				if mime_cc then
					for _,mr in ipairs(mime_cc) do
						if string.find(mr, sr) then
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
		local mime_from = msg:get_header('From')
		if not mime_from or not string.find(mime_from[0], smtp_from) then
			task:insert_result(symbol_sender, 1)
		end
	end
end

-- Configuration
local opts =  rspamd_config:get_all_opt('forged_recipients')
if opts then
	if opts['symbol_rcpt'] or opts['symbol_sender'] then
		if opts['symbol_rcpt'] then
			symbol_rcpt = opts['symbol_rcpt']
		end
		if opts['symbol_sender'] then
			symbol_sender = opts['symbol_sender']
		end
		rspamd_config:register_symbol(symbol_rcpt, 1.0, 'check_forged_headers')
	end
end


