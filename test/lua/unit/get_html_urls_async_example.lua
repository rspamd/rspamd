--[[
  Async HTML URL Rewriting Example

  This is an example demonstrating how to use task:get_html_urls() with
  async operations to batch-check URLs against an external service before
  rewriting them.

  Usage pattern:
  1. Extract all URLs from HTML parts using task:get_html_urls()
  2. Send all URLs to external service via async HTTP/Redis/etc
  3. Receive URL replacements from service
  4. Apply rewrites using task:rewrite_html_urls() with lookup table
]]

-- Example rule implementation
local function register_async_url_rewriter(rspamd_config)
  rspamd_config:register_symbol({
    name = 'ASYNC_URL_REWRITER',
    type = 'postfilter',
    callback = function(task)
      -- Step 1: Extract all URLs from HTML parts
      local urls_by_part = task:get_html_urls()

      if not urls_by_part then
        return -- No HTML URLs to process
      end

      -- Flatten URLs for batched API request
      local all_urls = {}
      local url_to_info = {}

      for part_id, url_list in pairs(urls_by_part) do
        for _, url_info in ipairs(url_list) do
          table.insert(all_urls, url_info.url)
          url_to_info[url_info.url] = url_info
        end
      end

      if #all_urls == 0 then
        return
      end

      rspamd_logger.infox(task, "Found %s HTML URLs to check", #all_urls)

      -- Step 2: Make async request to URL checking service
      local http = require "rspamd_http"
      local ucl = require "ucl"

      http.request({
        task = task,
        url = 'http://url-checker.example.com/api/check-batch',
        callback = function(err, code, body)
          if err then
            rspamd_logger.errx(task, 'URL check failed: %s', err)
            return
          end

          if code ~= 200 then
            rspamd_logger.errx(task, 'URL check service returned HTTP %s', code)
            return
          end

          -- Step 3: Parse response containing URL replacements
          local parser = ucl.parser()
          local ok, parse_err = parser:parse_string(body)

          if not ok then
            rspamd_logger.errx(task, 'Failed to parse response: %s', parse_err)
            return
          end

          local response = parser:get_object()

          -- Build replacement map: original_url -> new_url
          local replacements = {}

          for original_url, result in pairs(response.urls or {}) do
            if result.action == 'rewrite' and result.new_url then
              replacements[original_url] = result.new_url
              rspamd_logger.infox(task, "Will rewrite %s -> %s",
                                 original_url, result.new_url)
            elseif result.action == 'block' then
              -- Redirect blocked URLs to warning page
              replacements[original_url] = 'https://warning.example.com/blocked'
              rspamd_logger.infox(task, "Blocking URL %s", original_url)

              -- Optionally set a symbol
              task:insert_result('BLOCKED_URL', 1.0, original_url)
            end
          end

          -- Step 4: Apply rewrites using lookup table callback
          if next(replacements) then
            local rewritten = task:rewrite_html_urls(function(task, url)
              -- Simple lookup - returns nil if URL shouldn't be rewritten
              return replacements[url]
            end)

            if rewritten then
              rspamd_logger.infox(task, 'Rewritten URLs in parts: %s',
                                 table.concat(table_keys(rewritten), ', '))

              -- Optionally set a symbol to track rewrites
              task:insert_result('URL_REWRITTEN', 1.0,
                                string.format('%d URLs', count_rewrites(replacements)))
            end
          end
        end,

        -- Request configuration
        headers = {
          ['Content-Type'] = 'application/json',
          ['Authorization'] = 'Bearer YOUR_API_TOKEN'
        },
        body = ucl.to_format({
          urls = all_urls,
          -- Include additional context if needed
          message_id = task:get_message_id(),
          from = (task:get_from('smtp') or {})[1]
        }, 'json'),
        timeout = 5.0
      })
    end,
    priority = 10 -- Postfilter priority
  })
end

-- Helper functions
local function table_keys(t)
  local keys = {}
  for k, _ in pairs(t) do
    table.insert(keys, tostring(k))
  end
  return keys
end

local function count_rewrites(replacements)
  local count = 0
  for _, _ in pairs(replacements) do
    count = count + 1
  end
  return count
end

--[[
  Alternative: Using Redis for caching URL check results
]]

local function register_redis_cached_url_rewriter(rspamd_config)
  rspamd_config:register_symbol({
    name = 'REDIS_CACHED_URL_REWRITER',
    type = 'postfilter',
    callback = function(task)
      local redis = require "rspamd_redis"
      local urls_by_part = task:get_html_urls()

      if not urls_by_part then
        return
      end

      -- Collect all URLs
      local all_urls = {}
      for part_id, url_list in pairs(urls_by_part) do
        for _, url_info in ipairs(url_list) do
          table.insert(all_urls, url_info.url)
        end
      end

      if #all_urls == 0 then
        return
      end

      -- Build Redis MGET command to check all URLs at once
      local redis_keys = {}
      for _, url in ipairs(all_urls) do
        table.insert(redis_keys, 'url:rewrite:' .. url)
      end

      redis.make_request({
        task = task,
        cmd = 'MGET',
        args = redis_keys,
        callback = function(err, data)
          if err then
            rspamd_logger.errx(task, 'Redis error: %s', err)
            return
          end

          -- Build replacement map from Redis results
          local replacements = {}
          for i, url in ipairs(all_urls) do
            if data[i] and data[i] ~= '' then
              replacements[url] = data[i]
            end
          end

          -- Apply rewrites
          if next(replacements) then
            local rewritten = task:rewrite_html_urls(function(task, url)
              return replacements[url]
            end)

            if rewritten then
              rspamd_logger.infox(task, 'Applied %d URL rewrites from Redis',
                                 count_rewrites(replacements))
            end
          end
        end
      })
    end
  })
end

--[[
  Simpler example: Rewrite specific domains without external service
]]

local function register_simple_domain_rewriter(rspamd_config)
  -- Mapping of domains to redirect targets
  local domain_redirects = {
    ['evil.com'] = 'https://warning.example.com/blocked?domain=evil.com',
    ['phishing.net'] = 'https://warning.example.com/blocked?domain=phishing.net',
  }

  rspamd_config:register_symbol({
    name = 'SIMPLE_DOMAIN_REWRITER',
    type = 'postfilter',
    callback = function(task)
      local urls_by_part = task:get_html_urls()

      if not urls_by_part then
        return
      end

      -- Check if any URLs match blocked domains
      local needs_rewrite = false
      for part_id, url_list in pairs(urls_by_part) do
        for _, url_info in ipairs(url_list) do
          for blocked_domain, _ in pairs(domain_redirects) do
            if url_info.url:find(blocked_domain, 1, true) then
              needs_rewrite = true
              break
            end
          end
        end
      end

      if not needs_rewrite then
        return
      end

      -- Apply rewrites
      local rewritten = task:rewrite_html_urls(function(task, url)
        for blocked_domain, redirect_url in pairs(domain_redirects) do
          if url:find(blocked_domain, 1, true) then
            return redirect_url
          end
        end
        return nil -- Don't rewrite
      end)

      if rewritten then
        task:insert_result('DOMAIN_REWRITTEN', 1.0)
      end
    end
  })
end

return {
  register_async_url_rewriter = register_async_url_rewriter,
  register_redis_cached_url_rewriter = register_redis_cached_url_rewriter,
  register_simple_domain_rewriter = register_simple_domain_rewriter,
}
