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
  - fetch_and_format(task, redis_params, opts, callback, debug_module): Fetch search context and format for LLM

Options (all optional with safe defaults):
  enabled: boolean (default: false)
  search_url: string (default: "https://leta.mullvad.net/api/search")
  max_domains: number (default: 3) - max domains to search
  max_results_per_query: number (default: 3) - max results per domain
  timeout: number (default: 5) - HTTP request timeout in seconds
  cache_ttl: number (default: 3600) - cache TTL in seconds
  cache_key_prefix: string (default: "gpt_search")
  as_system: boolean (default: true) - inject as system message vs user message
  enable_expression: table - optional gating expression
  disable_expression: table - optional negative gating expression
]]

local N = 'llm_search_context'

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
  as_system = true,
  enable_expression = nil,
  disable_expression = nil,
}

-- Extract unique domains from task URLs
local function extract_domains(task, max_domains)
  local domains = {}
  local seen = {}

  -- Get URLs from the task using extract_specific_urls
  local urls = lua_util.extract_specific_urls({
    task = task,
    limit = max_domains * 3, -- Get more to filter
    esld_limit = max_domains,
  }) or {}

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
local function query_search_api(task, domain, opts, callback)
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

  lua_util.debugm(N, task, "querying search API: %s", full_url)

  local function http_callback(err, code, body, _)
    if err then
      lua_util.debugm(N, task, "search API error for %s: %s", domain, err)
      callback(nil, domain, err)
      return
    end

    if code ~= 200 then
      lua_util.debugm(N, task, "search API returned code %s for %s", code, domain)
      callback(nil, domain, string.format("HTTP %s", code))
      return
    end

    -- Parse JSON response
    local parser = ucl.parser()
    local ok, parse_err = parser:parse_string(body)
    if not ok then
      rspamd_logger.errx(task, "%s: failed to parse search API response for %s: %s",
        N, domain, parse_err)
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
    task = task,
    log_obj = task,
  })
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
local function check_cache(task, redis_params, domain, opts, callback)
  local cache_key = get_cache_key(domain, opts)

  local function redis_callback(err, data)
    if err then
      lua_util.debugm(N, task, "Redis error for cache key %s: %s", cache_key, err)
      callback(nil, domain)
      return
    end

    if data and type(data) == 'string' then
      -- Parse cached data
      local parser = ucl.parser()
      local ok, parse_err = parser:parse_string(data)
      if ok then
        lua_util.debugm(N, task, "cache hit for domain %s", domain)
        callback(parser:get_object(), domain)
      else
        rspamd_logger.warnx(task, "%s: failed to parse cached data for %s: %s",
          N, domain, parse_err)
        callback(nil, domain)
      end
    else
      lua_util.debugm(N, task, "cache miss for domain %s", domain)
      callback(nil, domain)
    end
  end

  lua_redis.redis_make_request(task, redis_params, cache_key, false,
    redis_callback, 'GET', { cache_key })
end

-- Store search results in Redis cache
local function store_cache(task, redis_params, domain, results, opts)
  local cache_key = get_cache_key(domain, opts)
  local ttl = opts.cache_ttl or DEFAULTS.cache_ttl

  if not results then
    return
  end

  local data = ucl.to_format(results, 'json-compact')

  local function redis_callback(err, _)
    if err then
      rspamd_logger.warnx(task, "%s: failed to cache results for %s: %s",
        N, domain, err)
    else
      lua_util.debugm(N, task, "cached results for domain %s (TTL: %ss)", domain, ttl)
    end
  end

  lua_redis.redis_make_request(task, redis_params, cache_key, true,
    redis_callback, 'SETEX', { cache_key, tostring(ttl), data })
end

-- Main function to fetch and format search context
function M.fetch_and_format(task, redis_params, opts, callback, debug_module)
  local Np = debug_module or N

  -- Apply defaults
  opts = lua_util.override_defaults(DEFAULTS, opts or {})

  if not opts.enabled then
    lua_util.debugm(Np, task, "search context disabled")
    callback(task, false, nil)
    return
  end

  -- Extract domains from task
  local domains = extract_domains(task, opts.max_domains)

  if #domains == 0 then
    lua_util.debugm(Np, task, "no domains to search")
    callback(task, false, nil)
    return
  end

  lua_util.debugm(Np, task, "extracted %s domain(s) for search: %s",
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
      lua_util.debugm(Np, task, "search failed for domain %s: %s", domain, err)
    end

    if pending_queries == 0 then
      -- All queries complete
      if #all_results == 0 then
        lua_util.debugm(Np, task, "no search results obtained")
        callback(task, false, nil)
      else
        local context_snippet = format_search_results(all_results, opts)
        lua_util.debugm(Np, task, "search context formatted (%s bytes)",
          context_snippet and #context_snippet or 0)
        callback(task, true, context_snippet)
      end
    end
  end

  -- Process each domain
  for _, domain in ipairs(domains) do
    if redis_params then
      -- Check cache first
      check_cache(task, redis_params, domain, opts, function(cached_results, dom)
        if cached_results then
          -- Use cached results
          domain_callback(cached_results, dom, nil)
        else
          -- Query API and cache results (no retry, fail gracefully)
          query_search_api(task, dom, opts, function(api_results, d, api_err)
            if api_results and redis_params then
              store_cache(task, redis_params, d, api_results, opts)
            end
            domain_callback(api_results, d, api_err)
          end)
        end
      end)
    else
      -- No Redis, query directly (no retry, fail gracefully)
      query_search_api(task, domain, opts, domain_callback)
    end
  end
end

return M
