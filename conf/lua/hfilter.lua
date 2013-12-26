--[[
Rating for checks_hellohost and checks_hello:
5 - very hard
4 - hard
3 - meduim
2 - low
1 - very low
--]]

--Checks for HELO and Hostname
local checks_hellohost = {
['[.-]dynamic[.-]'] = 4, ['dynamic[.-][0-9]'] = 4, ['[0-9][.-]?dynamic'] = 4, 
['[.-]dyn[.-]'] = 4, ['dyn[.-][0-9]'] = 4, ['[0-9][.-]?dyn'] = 4, 
['[.-]clients?[.-]'] = 4, ['clients?[.-][0-9]'] = 4, ['[0-9][.-]?clients?'] = 4, 
['[.-]dynip[.-]'] = 4, ['dynip[.-][0-9]'] = 4, ['[0-9][.-]?dynip'] = 4, 
['[.-]broadband[.-]'] = 4, ['broadband[.-][0-9]'] = 4, ['[0-9][.-]?broadband'] = 4, 
['[.-]broad[.-]'] = 4, ['broad[.-][0-9]'] = 4, ['[0-9][.-]?broad'] = 4, 
['[.-]bredband[.-]'] = 4, ['bredband[.-][0-9]'] = 4, ['[0-9][.-]?bredband'] = 4, 
['[.-]nat[.-]'] = 4, ['nat[.-][0-9]'] = 4, ['[0-9][.-]?nat'] = 4, 
['[.-]pptp[.-]'] = 4, ['pptp[.-][0-9]'] = 4, ['[0-9][.-]?pptp'] = 4, 
['[.-]pppoe[.-]'] = 4, ['pppoe[.-][0-9]'] = 4, ['[0-9][.-]?pppoe'] = 4, 
['[.-]ppp[.-]'] = 4, ['ppp[.-][0-9]'] = 4, ['[0-9][.-]?ppp'] = 4, 
['[.-][a|x]?dsl[.-]'] = 3, ['[a|x]?dsl[.-]?[0-9]'] = 3, ['[0-9][.-]?[a|x]?dsl'] = 3, 
['[.-][a|x]?dsl-dynamic[.-]'] = 4, ['[a|x]?dsl-dynamic[.-]?[0-9]'] = 4, ['[0-9][.-]?[a|x]?dsl-dynamic'] = 4, 
['[.-][a|x]?dsl-line[.-]'] = 3, ['[a|x]?dsl-line[.-]?[0-9]'] = 3, ['[0-9][.-]?[a|x]?dsl-line'] = 3, 
['[.-]dhcp[.-]'] = 4, ['dhcp[.-][0-9]'] = 4, ['[0-9][.-]?dhcp'] = 4, 
['[.-]catv[.-]'] = 4, ['catv[.-][0-9]'] = 4, ['[0-9][.-]?catv'] = 4, 
['[.-]wifi[.-]'] = 4, ['wifi[.-][0-9]'] = 4, ['[0-9][.-]?wifi'] = 4, 
['[.-]unused-addr[.-]'] = 5, ['unused-addr[.-][0-9]'] = 5, ['[0-9][.-]?unused-addr'] = 5, 
['[.-]dial-?up[.-]'] = 4, ['dial-?up[.-][0-9]'] = 4, ['[0-9][.-]?dial-?up'] = 4, 
['[.-]gprs[.-]'] = 4, ['gprs[.-][0-9]'] = 4, ['[0-9][.-]?gprs'] = 4, 
['[.-]cdma[.-]'] = 4, ['cdma[.-][0-9]'] = 4, ['[0-9][.-]?cdma'] = 4, 
['[.-]homeuser[.-]'] = 4, ['homeuser[.-][0-9]'] = 4, ['[0-9][.-]?homeuser'] = 4, 
['[.-]in-?addr[.-]'] = 3, ['in-?addr[.-][0-9]'] = 3, ['[0-9][.-]?in-?addr'] = 3, 
['[.-]pool[.-]'] = 3, ['pool[.-][0-9]'] = 3, ['[0-9][.-]?pool'] = 3, 
['[.-]cable[.-]'] = 5, ['cable[.-][0-9]'] = 5, ['[0-9][.-]?cable'] = 5,
['[.-]host[.-]'] = 3, ['host[.-][0-9]'] = 3, ['[0-9][.-]?host'] = 3,
['[.-]customers[.-]'] = 2, ['customers[.-][0-9]'] = 2, ['[0-9][.-]?customers'] = 2
}

--Checks for HELO only
local checks_hello = {
['localhost$'] = 5, 
['^(dsl)?(device|speedtouch)\\.lan$'] = 5,
['\\.(lan|local|home|localdomain|intra|in-addr.arpa|priv|online|user|veloxzon)$'] = 5,
['^\\[*127\\.'] = 5, ['^\\[*10\\.'] = 5, ['^\\[*172\\.16\\.'] = 5, ['^\\[*192\\.168\\.'] = 5,
--bareip
['^\\[*\\d+[x.-]\\d+[x.-]\\d+[x.-]\\d+\\]*$'] = 5
}

--
local function trim1(s)
  return (s:gsub("^%s*(.-)%s*$", "%1"))
end

--
local function check_regexp(str, regexp_text)
    local re = regexp.get_cached(regexp_text)
    if not re then re = regexp.create(regexp_text, 'i') end
    if re:match(str) then return true end
return false
end

--
local function hfilter(task)
    local recvh = task:get_received_headers()
    
    if table.maxn(recvh) == 0 then 
        return false
    end
    
    --IP--
    local ip = false
    local rip = task:get_from_ip()
        if rip then
            ip = rip:to_string()
            if ip and ip == '0.0.0.0' then
                ip = false
            end
        end
    
    --HOSTNAME--
    local r = recvh[1]
    local hostname = false
    local hostname_lower = false
        if r['real_hostname'] and ( r['real_hostname'] ~= 'unknown' or not check_regexp(r['real_hostname'], '^\\d+\\.\\d+\\.\\d+\\.\\d+$') ) then
            hostname = r['real_hostname']
            hostname_lower = string.lower(hostname)
        end
    
    --HELO--
    local helo = task:get_helo()
    local helo_lower = false
        if helo then
            helo_lower = string.lower(helo)
        else
            helo = false
            helo_lower = false
        end
    
    -- Check's HELO
    local checks_hello_found = false
    if helo then
        -- Regexp check HELO
        for regexp,weight in pairs(checks_hello) do
            if check_regexp(helo_lower, regexp) then
                task:insert_result('HFILTER_HELO' .. weight, 1.0)
                checks_hello_found = true
                break
            end
        end
        if not checks_hello_found then
            local checks_hello_found = false
            for regexp,weight in pairs(checks_hellohost) do
                if check_regexp(helo_lower, regexp) then
                    task:insert_result('HFILTER_HELO' .. weight, 1.0)
                    break
                end
            end
        end
        
        --------
        local function hfilter_heloip_cb_mx_a(resolver, to_resolve, results, err)
            task:inc_dns_req()
            if not results then
                task:insert_result('HFILTER_HELO_NORESOLVE_MX', 1.0)
            elseif ip then
                for _,result in pairs(results) do 
                    local helo_ip = result:to_string()
                    if helo_ip == ip then
                        --task:insert_result('HFILTER_CHECK_HELO_IP_TRUE_MX', 0.0)
                        return true
                    end
                end
                task:insert_result('HFILTER_CHECK_HELO_IP_MX', 1.0)
            end
        end
        --
        local function hfilter_heloip_cb_mx(resolver, to_resolve, results, err)
            task:inc_dns_req()
            if not results then
                task:insert_result('HFILTER_HELO_NORESOLVE_A_OR_MX', 1.0)
            else
                for _,mx in pairs(results) do
                    if mx['name'] then
                        task:get_resolver():resolve_a(task:get_session(), task:get_mempool(), mx['name'], hfilter_heloip_cb_mx_a)
                    end
                end
            end
        end
        --
        local function hfilter_heloip_cb_a(resolver, to_resolve, results, err)
            task:inc_dns_req()
            if not results then
                task:get_resolver():resolve_mx(task:get_session(), task:get_mempool(), helo_lower, hfilter_heloip_cb_mx)
            elseif ip then
                for _,result in pairs(results) do 
                    local helo_ip = result:to_string()
                    if helo_ip == ip then
                        --task:insert_result('HFILTER_CHECK_HELO_IP_TRUE_A', 0.0)
                        return true
                    end
                end
                task:insert_result('HFILTER_CHECK_HELO_IP_A', 1.0)
            end
        end
        --------

        --FQDN check HELO
        if check_regexp(helo, '(?=^.{4,255}$)(^((?!-)[a-zA-Z0-9-]{1,63}(?<!-)\\.)+[a-zA-Z]{2,63}$)') then
            --Resolve and check's HELO ip--
            if not hostname or hostname_lower ~= helo_lower then
                task:get_resolver():resolve_a(task:get_session(), task:get_mempool(), helo_lower, hfilter_heloip_cb_a)
            end
        else
            task:insert_result('HFILTER_HELO_NOT_FQDN', 1.0)
        end
    end
    
    --
    local function check_hostname(hostname_res)
        -- Check regexp HOSTNAME
        for regexp,weight in pairs(checks_hellohost) do
            if check_regexp(hostname_res, regexp) then
                task:insert_result('HFILTER_HOSTNAME' .. weight, 1.0)
                break
            end
        end
    end
    --
    local function hfilter_hostname_ptr(resolver, to_resolve, results, err)
        task:inc_dns_req()
        if results then
            check_hostname(results[1])
        end
    end
    -- Check's HOSTNAME
    if not checks_hello_found then
        if hostname then
            check_hostname(hostname)
        else
            task:insert_result('HFILTER_HOSTNAME_NOPTR', 1.00)
            task:get_resolver():resolve_ptr(task:get_session(), task:get_mempool(), ip, hfilter_hostname_ptr)
        end
    end
    
    -- Links checks
    local parts = task:get_text_parts()
    if parts then
        --One text part--
        if table.maxn(parts) > 0 and parts[1]:get_content() then
            local part_text = trim1(parts[1]:get_content())
            local total_part_len = string.len(part_text)
            if total_part_len > 0 then
                local urls = task:get_urls()
                if urls then
                    local total_url_len = 0
                    for _,url in ipairs(urls) do
                        total_url_len = total_url_len + string.len(url:get_text())
                    end

                    if total_url_len > 0 then
                        if total_url_len + 7 > total_part_len then
                            task:insert_result('HFILTER_URL_ONLY', 1.00)
                        else
                            if not string.find(part_text, "\n") then
                                task:insert_result('HFILTER_URL_ONELINE', 1.00)
                            end
                        end
                    end
                end
            end
        end
    end
    
    return false
end

rspamd_config:register_symbols(hfilter, 1.0, 
'HFILTER_HELO_1', 'HFILTER_HELO_2', 'HFILTER_HELO_3', 'HFILTER_HELO_4', 'HFILTER_HELO_5',
'HFILTER_HELO_NORESOLVE_MX', 'HFILTER_CHECK_HELO_IP_MX', 'HFILTER_HELO_NORESOLVE_A_OR_MX',
'HFILTER_CHECK_HELO_IP_A', 'HFILTER_HELO_NOT_FQDN',
'HFILTER_HOSTNAME_1', 'HFILTER_HOSTNAME_2', 'HFILTER_HOSTNAME_3', 'HFILTER_HOSTNAME_4', 'HFILTER_HOSTNAME_5',
'HFILTER_HOSTNAME_NOPTR',
'HFILTER_URL_ONLY',
'HFILTER_URL_ONELINE');
