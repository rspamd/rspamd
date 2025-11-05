--[[
Copyright (c) 2024, Vsevolod Stakhov <vsevolod@rspamd.com>

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
]] --

--[[
Web search context module for LLM-based spam detection

This module extracts domains from email URLs, queries a search API to fetch
relevant information about those domains, and formats the results as context
for LLM-based classification.

Main function:
  - fetch_and_format(task, opts, callback, debug_module): Fetch search context and format for LLM

Options (all optional with safe defaults):
  enabled: boolean (default: false)
  search_url: string (default: "https://leta.mullvad.net/api/search")
  max_domains: number (default: 3) - max domains to search
  max_results_per_query: number (default: 3) - max results per domain
  timeout: number (default: 5) - HTTP request timeout in seconds
  cache_ttl: number (default: 3600) - cache TTL in seconds
  cache_key_prefix: string (default: "gpt_search")
  retry_count: number (default: 3) - number of retry attempts
  retry_delay: number (default: 1) - initial retry delay in seconds
  as_system: boolean (default: true) - inject as system message vs user message
  enable_expression: table - optional gating expression
  disable_expression: table - optional negative gating expression
]]

local M = {}

local rspamd_http = require "rspamd_http"
local rspamd_logger = require "rspamd_logger"
local rspamd_util = require "rspamd_util"
local lua_util = require "lua_util"
local lua_redis = require "lua_redis"
local ucl = require "ucl"

local DEFAULTS = {
  enabled = false,
  search_url = "https://leta.mullvad.net/api/search",
  max_domains = 3,
  max_results_per_query = 3,
  timeout = 5,
  cache_ttl = 3600, -- 1 hour
  cache_key_prefix = "gpt_search",
  retry_count = 3,
  retry_delay = 1, -- seconds
  as_system = true,
  enable_expression = nil,
  disable_expression = nil,
}

-- Extract unique domains from task URLs
local function extract_domains(task, max_domains)
  local domains = {}
  local seen = {}

  -- Get URLs from the task
  local urls = task:get_urls() or {}

  for _, url in ipairs(urls) do
    if #domains >= max_domains then
      break
    end

    local host = url:get_host()
    if host and not seen[host] then
      -- Skip common domains that won't provide useful context
      local skip_domains = {
        ['localhost'] = true,
        ['127.0.0.1'] = true,
        ['example.com'] = true,
        ['example.org'] = true,
      }

      if not skip_domains[host:lower()] then
        seen[host] = true
        table.insert(domains, host)
      end
    end
  end

  return domains
end

-- Generate cache key for a domain
local function get_cache_key(domain, opts)
  local key_prefix = opts.cache_key_prefix or DEFAULTS.cache_key_prefix
  local hash = rspamd_util.hash_create()
  hash:update(domain)
  return string.format("%s:%s", key_prefix, hash:hex())
end

-- Query search API for a single domain
local function query_search_api(domain, opts, callback, debug_module)
  local debug_m = debug_module or 'llm_search_context'
  local url = opts.search_url or DEFAULTS.search_url
  local timeout = opts.timeout or DEFAULTS.timeout
  local max_results = opts.max_results_per_query or DEFAULTS.max_results_per_query

  -- Prepare search query
  local query_params = {
    q = domain,
    limit = tostring(max_results),
  }

  -- Build query string
  local query_string = ""
  for k, v in pairs(query_params) do
    if query_string ~= "" then
      query_string = query_string .. "&"
    end
    query_string = query_string .. k .. "=" .. rspamd_util.url_encode(v)
  end

  local full_url = url .. "?" .. query_string

  rspamd_logger.debugm(debug_m, nil, "querying search API: %s", full_url)

  local function http_callback(err, code, body, _)
    if err then
      rspamd_logger.errx(debug_m, "search API error for %s: %s", domain, err)
      callback(nil, domain, err)
      return
    end

    if code ~= 200 then
      rspamd_logger.warnx(debug_m, "search API returned code %s for %s", code, domain)
      callback(nil, domain, string.format("HTTP %s", code))
      return
    end

    -- Parse JSON response
    local parser = ucl.parser()
    local ok, parse_err = parser:parse_string(body)
    if not ok then
      rspamd_logger.errx(debug_m, "failed to parse search API response for %s: %s", domain, parse_err)
      callback(nil, domain, parse_err)
      return
    end

    local results = parser:get_object()
    callback(results, domain, nil)
  end

  rspamd_http.request({
    url = full_url,
    timeout = timeout,
    callback = http_callback,
  })
end

-- Query with retry logic
local function query_with_retry(domain, opts, callback, debug_module, attempt)
  local debug_m = debug_module or 'llm_search_context'
  attempt = attempt or 1
  local max_attempts = opts.retry_count or DEFAULTS.retry_count

  if attempt > max_attempts then
    rspamd_logger.warnx(debug_m, "max retries exceeded for domain %s", domain)
    callback(nil, domain, "max retries exceeded")
    return
  end

  query_search_api(domain, opts, function(results, dom, err)
    if err and attempt < max_attempts then
      -- Calculate exponential backoff delay
      local delay = (opts.retry_delay or DEFAULTS.retry_delay) * (2 ^ (attempt - 1))
      rspamd_logger.debugm(debug_m, nil, "retrying search for %s after %ss (attempt %s/%s)",
        domain, delay, attempt + 1, max_attempts)

      -- Schedule retry
      rspamd_config:add_delayed_callback(delay, function()
        query_with_retry(domain, opts, callback, debug_module, attempt + 1)
      end)
    else
      callback(results, dom, err)
    end
  end, debug_module)
end

-- Format search results as context
local function format_search_results(all_results, opts)
  if not all_results or #all_results == 0 then
    return nil
  end

  local context_lines = {
    "Web search context for domains in email:"
  }

  for _, domain_result in ipairs(all_results) do
    local domain = domain_result.domain
    local results = domain_result.results

    if results and results.results and #results.results > 0 then
      table.insert(context_lines, string.format("\nDomain: %s", domain))

      for i, result in ipairs(results.results) do
        if i > (opts.max_results_per_query or DEFAULTS.max_results_per_query) then
          break
        end

        local title = result.title or "No title"
        local snippet = result.snippet or result.description or "No description"

        -- Truncate snippet if too long
        if #snippet > 200 then
          snippet = snippet:sub(1, 197) .. "..."
        end

        table.insert(context_lines, string.format("  - %s: %s", title, snippet))
      end
    else
      table.insert(context_lines, string.format("\nDomain: %s - No search results found", domain))
    end
  end

  return table.concat(context_lines, "\n")
end

-- Check Redis cache for domain search results
local function check_cache(redis_params, domain, opts, callback, debug_module)
  local debug_m = debug_module or 'llm_search_context'
  local cache_key = get_cache_key(domain, opts)

  local function redis_callback(err, data)
    if err then
      rspamd_logger.debugm(debug_m, nil, "Redis error for cache key %s: %s", cache_key, err)
      callback(nil, domain)
      return
    end

    if data and type(data) == 'string' then
      -- Parse cached data
      local parser = ucl.parser()
      local ok, parse_err = parser:parse_string(data)
      if ok then
        rspamd_logger.debugm(debug_m, nil, "cache hit for domain %s", domain)
        callback(parser:get_object(), domain)
      else
        rspamd_logger.warnx(debug_m, "failed to parse cached data for %s: %s", domain, parse_err)
        callback(nil, domain)
      end
    else
      rspamd_logger.debugm(debug_m, nil, "cache miss for domain %s", domain)
      callback(nil, domain)
    end
  end

  lua_redis.redis_make_request(nil, redis_params, cache_key, false,
    redis_callback, 'GET', { cache_key })
end

-- Store search results in Redis cache
local function store_cache(redis_params, domain, results, opts, debug_module)
  local debug_m = debug_module or 'llm_search_context'
  local cache_key = get_cache_key(domain, opts)
  local ttl = opts.cache_ttl or DEFAULTS.cache_ttl

  if not results then
    return
  end

  local data = ucl.to_format(results, 'json-compact')

  local function redis_callback(err, _)
    if err then
      rspamd_logger.warnx(debug_m, "failed to cache results for %s: %s", domain, err)
    else
      rspamd_logger.debugm(debug_m, nil, "cached results for domain %s (TTL: %ss)", domain, ttl)
    end
  end

  lua_redis.redis_make_request(nil, redis_params, cache_key, true,
    redis_callback, 'SETEX', { cache_key, tostring(ttl), data })
end

-- Main function to fetch and format search context
function M.fetch_and_format(task, redis_params, opts, callback, debug_module)
  local debug_m = debug_module or 'llm_search_context'

  -- Apply defaults
  opts = lua_util.override_defaults(DEFAULTS, opts or {})

  if not opts.enabled then
    rspamd_logger.debugm(debug_m, task, "search context disabled")
    callback(task, false, nil)
    return
  end

  -- Extract domains from task
  local domains = extract_domains(task, opts.max_domains)

  if #domains == 0 then
    rspamd_logger.debugm(debug_m, task, "no domains to search")
    callback(task, false, nil)
    return
  end

  rspamd_logger.debugm(debug_m, task, "extracted %s domain(s) for search: %s",
    #domains, table.concat(domains, ", "))

  local pending_queries = #domains
  local all_results = {}

  -- Callback for each domain query
  local function domain_callback(results, domain, err)
    pending_queries = pending_queries - 1

    if results then
      table.insert(all_results, {
        domain = domain,
        results = results
      })
    elseif err then
      rspamd_logger.debugm(debug_m, task, "search failed for domain %s: %s", domain, err)
    end

    if pending_queries == 0 then
      -- All queries complete
      if #all_results == 0 then
        rspamd_logger.debugm(debug_m, task, "no search results obtained")
        callback(task, false, nil)
      else
        local context_snippet = format_search_results(all_results, opts)
        rspamd_logger.debugm(debug_m, task, "search context formatted (%s bytes)",
          context_snippet and #context_snippet or 0)
        callback(task, true, context_snippet)
      end
    end
  end

  -- Process each domain
  for _, domain in ipairs(domains) do
    if redis_params then
      -- Check cache first
      check_cache(redis_params, domain, opts, function(cached_results, dom)
        if cached_results then
          -- Use cached results
          domain_callback(cached_results, dom, nil)
        else
          -- Query API and cache results
          query_with_retry(dom, opts, function(api_results, d, api_err)
            if api_results and redis_params then
              store_cache(redis_params, d, api_results, opts, debug_module)
            end
            domain_callback(api_results, d, api_err)
          end, debug_module)
        end
      end, debug_module)
    else
      -- No Redis, query directly
      query_with_retry(domain, opts, domain_callback, debug_module)
    end
  end
end

return M