-- Emails is module for different checks for emails inside messages

-- Rules format:
-- symbol = sym, map = file:///path/to/file, domain_only = yes
-- symbol = sym2, dnsbl = bl.somehost.com, domain_only = no
local rules = {}

function split(str, delim, maxNb)
	-- Eliminate bad cases...
	if string.find(str, delim) == nil then
		return { str }
	end
	if maxNb == nil or maxNb < 1 then
		maxNb = 0    -- No limit
	end
	local result = {}
	local pat = "(.-)" .. delim .. "()"
	local nb = 0
	local lastPos
	for part, pos in string.gfind(str, pat) do
		nb = nb + 1
		result[nb] = part
		lastPos = pos
		if nb == maxNb then break end
	end
	-- Handle the last field
	if nb ~= maxNb then
		result[nb + 1] = string.sub(str, lastPos)
	end
	return result
end

function emails_dns_cb(task, to_resolve, results, err, symbol)
	if results then
		rspamd_logger.info('found host for: ' .. to_resolve .. ', insert symbol: ' .. symbol) 
		task:insert_result(symbol, 1)
	end
end

-- Check rule for a single email
function check_email_rule(task, rule, addr)
	if rule['dnsbl'] then
		local to_resolve = ''
		if rule['domain_only'] then
			to_resolve = string.format('%s.%s', addr:get_host(), rule['dnsbl'])
		else
			to_resolve = string.format('%s.%s.%s', addr:get_user(), addr:get_host(), rule['dnsbl'])
		end
		task:resolve_dns_a(to_resolve, 'emails_dns_cb', rule['symbol'])
	elseif rule['map'] then
		if rule['domain_only'] then
			local key = addr:get_host()
			if rule['map']:get_key(key) then
				task:insert_result(rule['symbol'], 1)
				rspamd_logger.info('email: ' .. key .. ' is found in list: ' .. rule['symbol'])
			end
		else
			local key = string.format('%s@%s', addr:get_user(), addr:get_host())
			if rule['map']:get_key(key) then
				task:insert_result(rule['symbol'], 1)
				rspamd_logger.info('email: ' .. key .. ' is found in list: ' .. rule['symbol'])
			end
		end
	end
end

-- Check email
function check_emails(task)
	local emails = task:get_emails()
	local checked = {}
	if emails then
		for _,addr in ipairs(emails) do
			local to_check = string.format('%s@%s', addr:get_user(), addr:get_host())
			if not checked['to_check'] then
				for _,rule in ipairs(rules) do
					check_email_rule(task, rule, addr)
				end
				checked[to_check] = true
			end 
		end
	end
end

-- Add rule to ruleset
local function add_emails_rule(params)
	local newrule = {
		name = nil,
		dnsbl = nil,
		map = nil,
		domain_only = false,
		symbol = nil
	}
	for _,param in ipairs(params) do
		local _,_,name,value = string.find(param, '([a-zA-Z_0-9]+)%s*=%s*(.+)')
		if not name or not value then
			rspamd_logger.err('invalid rule: '..param)
			return nil
		end
		if name == 'dnsbl' then
			newrule['dnsbl'] = value
			newrule['name'] = value
		elseif name == 'map' then
			newrule['name'] = value
			newrule['map'] = rspamd_config:add_hash_map (newrule['name'])
		elseif name == 'symbol' then
			newrule['symbol'] = value
		elseif name == 'domain_only' then
			if value == 'yes' or value == 'true' or value == '1' then
				newrule['domain_only'] = true
			end
		else	
			rspamd_logger.err('invalid rule option: '.. name)
			return nil
		end

	end
	if not newrule['symbol'] or (not newrule['map'] and not newrule['dnsbl']) then
		rspamd_logger.err('incomplete rule')
		return nil
	end
	table.insert(rules, newrule)
	return newrule
end


-- Registration
if type(rspamd_config.get_api_version) ~= 'nil' then
	if rspamd_config:get_api_version() >= 2 then
		rspamd_config:register_module_option('emails', 'rule', 'string')
	else
		rspamd_logger.err('Invalid rspamd version for this plugin')
	end
end

local opts =  rspamd_config:get_all_opt('emails')
if opts then
	local strrules = opts['rule']
	if strrules then
		if type(strrules) == 'table' then 
			for _,value in ipairs(strrules) do
				local params = split(value, ',')
				local rule = add_emails_rule (params)
				if not rule then
					rspamd_logger.err('cannot add rule: "'..value..'"')
				else
					if type(rspamd_config.get_api_version) ~= 'nil' then
						rspamd_config:register_virtual_symbol(rule['symbol'], 1.0)
					end
				end
			end
		elseif type(strrules) == 'string' then
			local params = split(strrules, ',')
			local rule = add_emails_rule (params)
			if not rule then
				rspamd_logger.err('cannot add rule: "'..strrules..'"')
			else
				if type(rspamd_config.get_api_version) ~= 'nil' then
					rspamd_config:register_virtual_symbol(rule['symbol'], 1.0)
				end
			end
		end
	end
end

if table.maxn(rules) > 0 then
	-- add fake symbol to check all maps inside a single callback
	if type(rspamd_config.get_api_version) ~= 'nil' then
		rspamd_config:register_callback_symbol('EMAILS', 1.0, 'check_emails')
	else
		rspamd_config:register_symbol('EMAILS', 1.0, 'check_emails')
	end
end
