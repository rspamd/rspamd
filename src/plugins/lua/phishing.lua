-- Phishing detection interface for selecting phished urls and inserting corresponding symbol
--
--
local symbol = 'PHISHED_URL'
local domains = nil
local strict_domains = {}

function phishing_cb (task)
	local urls = task:get_urls();

	if urls then
		for _,url in ipairs(urls) do
			if url:is_phished() then
				local found = false
				local purl = url:get_phished()
				if table.maxn(strict_domains) > 0 then
					local _,_,tld = string.find(purl:get_host(), '([a-zA-Z0-9%-]+\.[a-zA-Z0-9%-]+)$')
					if tld then
						for _,rule in ipairs(strict_domains) do
							if rule['map']:get_key(tld) then
								task:insert_result(rule['symbol'], 1, purl:get_host())
								found = true
							end
						end
					end
				end
				if not found then
					if domains then
						local _,_,tld = string.find(purl:get_host(), '([a-zA-Z0-9%-]+\.[a-zA-Z0-9%-]+)$')
						if tld then
							if domains:get_key(tld) then
								task:insert_result(symbol, 1, purl:get_host())
							end
						end
					else		
						task:insert_result(symbol, 1, purl:get_host())
					end
				end
			end
		end
	end
end

-- Registration
if type(rspamd_config.get_api_version) ~= 'nil' then
	if rspamd_config:get_api_version() >= 1 then
		rspamd_config:register_module_option('phishing', 'symbol', 'string')
		rspamd_config:register_module_option('phishing', 'domains', 'map')
		rspamd_config:register_module_option('phishing', 'strict_domains', 'string')
	end
end

local opts = rspamd_config:get_all_opt('phishing')
if opts then
    if opts['symbol'] then
        symbol = opts['symbol']
        
        -- Register symbol's callback
        rspamd_config:register_symbol(symbol, 1.0, 'phishing_cb')
    end
	if opts['domains'] and type(opt['domains']) == 'string' then
		domains = rspamd_config:add_hash_map (opts['domains'])
	end
	if opts['strict_domains'] then
		local sd = {}
		if type(opts['strict_domains']) == 'table' then
			sd = opts['strict_domains']
		else
			sd[1] = opts['strict_domains']
		end
		for _,d in ipairs(sd) do
			local s, _ = string.find(d, ':[^:]+$')
			if s then
				local sym = string.sub(d, s + 1, -1)
				local map = string.sub(d, 1, s - 1)
				if type(rspamd_config.get_api_version) ~= 'nil' then
					rspamd_config:register_virtual_symbol(sym, 1)
				end
				local rmap = rspamd_config:add_hash_map (map, 'Phishing strict domains map')
				if rmap then
					local rule = {symbol = sym, map = rmap}
					table.insert(strict_domains, rule)
				else
					rspamd_logger.info('cannot add map: ' .. map .. ' for symbol: ' .. sym)
				end
			else
				rspamd_logger.info('strict_domains option must be in format <map>:<symbol>')
			end
		end
	end
    -- If no symbol defined, do not register this module
end
