local logger = require "rspamd_logger"

-- This function parses redis server definition using either
-- specific server string for this module or global
-- redis section
function rspamd_parse_redis_server(module_name)

  local result = {}
  local default_port = 6379
  local default_timeout = 1.0
  local upstream_list = require "rspamd_upstream_list"

  local function try_load_redis_servers(options)
    -- Try to get read servers:
    local upstreams_read, upstreams_write

    if options['read_servers'] then
      upstreams_read = upstream_list.create(rspamd_config,
        options['read_servers'], default_port)
    elseif options['servers'] then
      upstreams_read = upstream_list.create(rspamd_config,
        options['servers'], default_port)
    elseif options['server'] then
      upstreams_read = upstream_list.create(rspamd_config,
        options['server'], default_port)
    end

    if upstreams_read then
      if options['write_servers'] then
        upstreams_write = upstream_list.create(rspamd_config,
          options['write_servers'], default_port)
      else
        upstreams_write = upstreams_read
      end
    end

    -- Store options
    if not result['timeout'] then
      result['timeout'] = default_timeout
    end
    if options['timeout'] and not result['timeout'] then
      result['timeout'] = tonumber(options['timeout'])
    end
    if options['prefix'] and not result['prefix'] then
      result['prefix'] = options['prefix']
    end
    if not result['db'] then
      if options['db'] then
        result['db'] = options['db']
      elseif options['dbname'] then
        result['db'] = options['dbname']
      end
    end
    if options['password'] and not result['password'] then
      result['password'] = options['password']
    end

    if upstreams_write and upstreams_read then
      result.read_servers = upstreams_read
      result.write_servers = upstreams_write

      return true
    end

    return false
  end

  -- Try local options
  local opts = rspamd_config:get_all_opt(module_name)
  local ret = false

  if opts then
    ret = try_load_redis_servers(opts, result)
  end

  if ret then
    return result
  end

  -- Try global options
  opts = rspamd_config:get_all_opt('redis')

  if opts then
    if opts[module_name] then
      ret = try_load_redis_servers(opts[module_name], result)
      if ret then
        return result
      end
    else
      ret = try_load_redis_servers(opts, result)

      -- Exclude disabled
      if opts['disabled_modules'] then
        for _,v in ipairs(opts['disabled_modules']) do
          if v == module_name then
            logger.infox(rspamd_config, "NOT using default redis server for module %s: it is disabled",
              module_name)

              return nil
          end
        end
      end

      if ret then
        logger.infox(rspamd_config, "using default redis server for module %s",
          module_name)
      end
    end
  end

  if result.read_servers then
    return result
  else
    return nil
  end
end

-- Performs async call to redis hiding all complexity inside function
-- task - rspamd_task
-- redis_params - valid params returned by rspamd_parse_redis_server
-- key - key to select upstream or nil to select round-robin/master-slave
-- is_write - true if need to write to redis server
-- callback - function to be called upon request is completed
-- command - redis command
-- args - table of arguments
function rspamd_redis_make_request(task, redis_params, key, is_write, callback, command, args)
  local addr
  local function rspamd_redis_make_request_cb(err, data)
    if err then
      addr:fail()
    else
      addr:ok()
    end
    callback(err, data, addr)
  end
  if not task or not redis_params or not callback or not command then
    return false,nil,nil
  end

  local rspamd_redis = require "rspamd_redis"

  if key then
    if is_write then
      addr = redis_params['write_servers']:get_upstream_by_hash(key)
    else
      addr = redis_params['read_servers']:get_upstream_by_hash(key)
    end
  else
    if is_write then
      addr = redis_params['write_servers']:get_upstream_master_slave(key)
    else
      addr = redis_params['read_servers']:get_upstream_round_robin(key)
    end
  end

  if not addr then
    logger.errx(task, 'cannot select server to make redis request')
  end

  local options = {
    task = task,
    callback = rspamd_redis_make_request_cb,
    host = addr:get_addr(),
    timeout = redis_params['timeout'],
    cmd = command,
    args = args
  }

  if redis_params['password'] then
    options['password'] = redis_params['password']
  end

  if redis_params['db'] then
    options['dbname'] = redis_params['db']
  end

  local ret,conn = rspamd_redis.make_request(options)
  return ret,conn,addr
end

local split_grammar = {}
function rspamd_str_split(s, sep)
  local lpeg = require "lpeg"
  local gr = split_grammar[sep]

  if not gr then
    local _sep = lpeg.P(sep)
    local elem = lpeg.C((1 - _sep)^0)
    local p = lpeg.Ct(elem * (_sep * elem)^0)
    gr = p
    split_grammar[sep] = gr
  end

  return gr:match(s)
end

-- Metafunctions
local function meta_size_function(task)
  local sizes = {
    100,
    200,
    500,
    1000,
    2000,
    4000,
    10000,
    20000,
    30000,
    100000,
    200000,
    400000,
    800000,
    1000000,
    2000000,
    8000000,
  }

  local size = task:get_size()
  for i = 1,#sizes do
    if sizes[i] >= size then
      return {(1.0 * i) / #sizes}
    end
  end

  return {0}
end

local function meta_images_function(task)
  local images = task:get_images()
  local ntotal = 0
  local njpg = 0
  local npng = 0
  local nlarge = 0
  local nsmall = 0

  if images then
    for _,img in ipairs(images) do
      if img:get_type() == 'png' then
        npng = npng + 1
      elseif img:get_type() == 'jpeg' then
        njpg = njpg + 1
      end

      local w = img:get_width()
      local h = img:get_height()

      if w > 0 and h > 0 then
        if w + h > 256 then
          nlarge = nlarge + 1
        else
          nsmall = nsmall + 1
        end
      end

      ntotal = ntotal + 1
    end
  end
  if ntotal > 0 then
    njpg = 1.0 * njpg / ntotal
    npng = 1.0 * npng / ntotal
    nlarge = 1.0 * nlarge / ntotal
    nsmall = 1.0 * nsmall / ntotal
  end
  return {ntotal,njpg,npng,nlarge,nsmall}
end

local function meta_nparts_function(task)
  local nattachments = 0
  local ntextparts = 0
  local totalparts = 1

  local tp = task:get_text_parts()
  if tp then
    ntextparts = #tp
  end

  local parts = task:get_parts()

  if parts then
    for _,p in ipairs(parts) do
      if p:get_filename() then
        nattachments = nattachments + 1
      end
      totalparts = totalparts + 1
    end
  end

  return {(1.0 * ntextparts)/totalparts, (1.0 * nattachments)/totalparts}
end

local function meta_encoding_function(task)
  local nutf = 0
  local nother = 0

  local tp = task:get_text_parts()
  if tp then
    for _,p in ipairs(tp) do
      if p:is_utf() then
        nutf = nutf + 1
      else
        nother = nother + 1
      end
    end
  end

  return {nutf, nother}
end

local function meta_recipients_function(task)
  local nmime = 0
  local nsmtp = 0

  if task:has_recipients('mime') then
    nmime = #(task:get_recipients('mime'))
  end
  if task:has_recipients('smtp') then
    nsmtp = #(task:get_recipients('smtp'))
  end

  if nmime > 0 then nmime = 1.0 / nmime end
  if nsmtp > 0 then nsmtp = 1.0 / nsmtp end

  return {nmime,nsmtp}
end

local function meta_received_function(task)
  local count_factor = 0
  local invalid_factor = 0
  local rh = task:get_received_headers()
  local time_factor = 0
  local secure_factor = 0
  local fun = require "fun"

  if rh and #rh > 0 then

    local ntotal = 0.0
    local init_time = 0

    fun.each(function(rc)
      ntotal = ntotal + 1.0

      if not rc.by_hostname then
        invalid_factor = invalid_factor + 1.0
      end
      if init_time == 0 and rc.timestamp then
        init_time = rc.timestamp
      elseif rc.timestamp then
        time_factor = time_factor + math.abs(init_time - rc.timestamp)
        init_time = rc.timestamp
      end
      if rc.flags and (rc.flags['ssl'] or rc.flags['authenticated']) then
        secure_factor = secure_factor + 1.0
      end
    end,
    fun.filter(function(rc) return not rc.flags or not rc.flags['artificial'] end, rh))

    invalid_factor = invalid_factor / ntotal
    secure_factor = secure_factor / ntotal
    count_factor = 1.0 / ntotal

    if time_factor ~= 0 then
      time_factor = 1.0 / time_factor
    end
  end

  return {count_factor, invalid_factor, time_factor, secure_factor}
end

local function meta_urls_function(task)
  if task:has_urls() then
    return {1.0 / #(task:get_urls())}
  end

  return {0}
end

local metafunctions = {
  {
    cb = meta_size_function,
    ninputs = 1,
  },
  {
    cb = meta_images_function,
    ninputs = 5,
    -- 1 - number of images,
    -- 2 - number of png images,
    -- 3 - number of jpeg images
    -- 4 - number of large images (> 128 x 128)
    -- 5 - number of small images (< 128 x 128)
  },
  {
    cb = meta_nparts_function,
    ninputs = 2,
    -- 1 - number of text parts
    -- 2 - number of attachments
  },
  {
    cb = meta_encoding_function,
    ninputs = 2,
    -- 1 - number of utf parts
    -- 2 - number of non-utf parts
  },
  {
    cb = meta_recipients_function,
    ninputs = 2,
    -- 1 - number of mime rcpt
    -- 2 - number of smtp rcpt
  },
  {
    cb = meta_received_function,
    ninputs = 4,
  },
  {
    cb = meta_urls_function,
    ninputs = 1,
  },
}

function rspamd_gen_metatokens(task)
  local ipairs = ipairs
  local metatokens = {}
  local cached = task:cache_get('metatokens')

  if cached then
    return cached
  else
    for _,mt in ipairs(metafunctions) do
      local ct = mt.cb(task)

      for _,tok in ipairs(ct) do
        table.insert(metatokens, tok)
      end
    end

    task:cache_set('metatokens', metatokens)
  end

  return metatokens
end

function rspamd_count_metatokens()
  local ipairs = ipairs
  local total = 0
  for _,mt in ipairs(metafunctions) do
    total = total + mt.ninputs
  end

  return total
end

function rspamd_map_add(mname, optname, mtype, description)
  local ret = {
    get_key = function(t, k)
      if t.__data then
        return t.__data:get_key(k)
      end

      return nil
    end
  }
  local ret_mt = {
    __index = function(t, k)
      if t.__data then
        return t.get_key(k)
      end

      return nil
    end
  }
  local opt = rspamd_config:get_module_opt(mname, optname)

  if not opt then
    return nil
  end

  if type(opt) == 'string' then
    -- We have a single string, so we treat it as a map
    local map = rspamd_config:add_map{
      type = mtype,
      description = description,
      url = opt,
    }

    if map then
      ret.__data = map
      setmetatable(ret, ret_mt)
      return ret
    end
  elseif type(opt) == 'table' then
    -- it might be plain map or map of plain elements
    if opt[1] then
      if mtype == 'radix' then

        if string.find(opt[1], '^%d') then
          local map = rspamd_config:radix_from_config(mname, optname)

          if map then
            ret.__data = map
            setmetatable(ret, ret_mt)
            return ret
          end
        else
          -- Plain table
          local map = rspamd_config:add_map{
            type = mtype,
            description = description,
            url = opt,
          }
          if map then
            ret.__data = map
            setmetatable(ret, ret_mt)
            return ret
          end
        end
      elseif mtype == 'regexp' then
        -- Plain table
        local map = rspamd_config:add_map{
          type = mtype,
          description = description,
          url = opt,
        }
        if map then
          ret.__data = map
          setmetatable(ret, ret_mt)
          return ret
        end
      else
        if string.find(opt[1], '^/%a') or string.find(opt[1], '^http') then
          -- Plain table
          local map = rspamd_config:add_map{
            type = mtype,
            description = description,
            url = opt,
          }
          if map then
            ret.__data = map
            setmetatable(ret, ret_mt)
            return ret
          end
        else
          local data = {}
          local nelts = 0
          for _,elt in ipairs(opt) do
            if type(elt) == 'string' then
              data[elt] = true
              nelts = nelts + 1
            end
          end

          if nelts > 0 then
            ret.__data = data
            ret.get_key = function(t, k)
              if k ~= '__data' then
                return t.__data[k]
              end

              return nil
            end
            return ret
          end
        end
      end
    else
      local map = rspamd_config:add_map{
        type = mtype,
        description = description,
        url = opt,
      }
      if map then
        ret.__data = map
        setmetatable(ret, ret_mt)
        return ret
      end
    end
  end

  return nil
end
