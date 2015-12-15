--Res here is the table of the following args:
--workers: {
-- pid: {
--  data: {
--    key_id: {
--      matched:
--      scanned:
--      added:
--      removed:
--      errors:
--      last_ips: {
--        ip: {
--          matched:
--          scanned
--          added:
--          removed:
--        }
--      }
--    }
--  }
-- }
--}

local function add_data(target, src)
  for k,v in pairs(src) do
    if k ~= 'ips' then
      if target[k] then
        target[k] = target[k] + v
      else
        target[k] = v
      end
    else
      if target['ips'] then
        add_data(target['ips'], v)
      else
        target['ips'] = {}
        add_data(target['ips'], v)
      end
    end
  end
end

return function(args, res)
  local res_keys = {}
  local res_ips = {}

  local wrk = res['workers']

  if wrk then
    for i,pr in pairs(wrk) do
      -- processes cycle
      if pr['data'] then
        for k,elts in pairs(pr['data']) do
          -- keys cycle
          if not res_keys[k] then
            res_keys[k] = {}
          end
          add_data(res_keys[k], elts)

          if elts['ips'] then
            for ip,v in pairs(elts['ips']) do
              if not res_ips[ip] then
                res_ips[ip] = {}
              end
              add_data(res_ips[ip], v)
            end
          end
        end
      end
    end
  end


end

