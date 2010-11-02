-- Phishing detection interface for selecting phished urls and inserting corresponding symbol
--
--
local symbol = 'PHISHED_URL'

function phishing_cb (task)
	local urls = task:get_urls();

	if urls then
		for _,url in ipairs(urls) do
			if url:is_phished() then
				task:insert_result(symbol, 1, url:get_host())
			end
		end
	end
end


local opts =  rspamd_config:get_all_opt('phishing')
if opts then
    if opts['symbol'] then
        symbol = opts['symbol']
        
        -- Register symbol's callback
        rspamd_config:register_symbol(symbol, 1.0, 'phishing_cb')
    end
    -- If no symbol defined, do not register this module
end
