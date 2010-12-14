-- Phishing detection interface for selecting phished urls and inserting corresponding symbol
--
--
local symbol = 'PHISHED_URL'
local domains = nil

function phishing_cb (task)
	local urls = task:get_urls();

	if urls then
		for _,url in ipairs(urls) do
			if url:is_phished() then
				if domains then
					local _,_,tld = string.find(url:get_phished():get_host(), '([a-zA-Z0-9%-]+\.[a-zA-Z0-9%-]+)$')
					if tld then
						if domains:get_key(tld) then
							if url:is_phished() then
								task:insert_result(symbol, 1, url:get_host())
							end
						end
					end
				else		
					task:insert_result(symbol, 1, url:get_phished():get_host())
				end
			end
		end
	end
end

-- Registration
rspamd_config:register_module_option('phishing', 'symbol', 'string')
rspamd_config:register_module_option('phishing', 'domains', 'map')

local opts = rspamd_config:get_all_opt('phishing')
if opts then
    if opts['symbol'] then
        symbol = opts['symbol']
        
        -- Register symbol's callback
        rspamd_config:register_symbol(symbol, 1.0, 'phishing_cb')
    end
	if opts['domains'] then
		domains = rspamd_config:add_hash_map (opts['domains'])
	end
    -- If no symbol defined, do not register this module
end
