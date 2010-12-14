-- Module that add symbols to those hosts or from domains that are contained in whitelist

local symbol_ip = nil
local symbol_from = nil

local r = nil
local h = nil  -- radix tree and hash table

function check_whitelist (task)
	if symbol_ip then
		-- check client's ip
		local ipn = task:get_from_ip_num()
		if ipn then
			local key = r:get_key(ipn)
			if key then
				task:insert_result( symbol_ip, 1)
			end
		end
	end

	if symbol_from then
		-- check client's from domain
		local from = task:get_from()
		if from then
			local _,_,domain = string.find(from, '@(.+)>?$')
			local key = h:get_key(domain)
			if key then
				task:insert_result(symbol_from, 1)
			end
		end
	end

end

-- Registration
rspamd_config:register_module_option('whitelist', 'symbol_ip', 'string')
rspamd_config:register_module_option('whitelist', 'symbol_from', 'string')
rspamd_config:register_module_option('whitelist', 'ip_whitelist', 'map')
rspamd_config:register_module_option('whitelist', 'from_whitelist', 'map')

-- Configuration
local opts =  rspamd_config:get_all_opt('whitelist')
if opts then
    if opts['symbol_ip'] or opts['symbol_from'] then
        symbol_ip = opts['symbol_ip']
        symbol_from = opts['symbol_from']
		
		if symbol_ip then
			if opts['ip_whitelist'] then
				r = rspamd_config:add_radix_map (opts['ip_whitelist'])
			else
				-- No whitelist defined
				symbol_ip = nil
			end
		end
		if symbol_from then
			if opts['from_whitelist'] then
				h = rspamd_config:add_hash_map (opts['from_whitelist'])
			else
				-- No whitelist defined
				symbol_from = nil
			end
		end


		-- Register symbol's callback
		if symbol_ip then
			rspamd_config:register_symbol(symbol_ip, 1.0, 'check_whitelist')
		elseif symbol_from then
			rspamd_config:register_symbol(symbol_from, 1.0, 'check_whitelist')
		end
	end
end
