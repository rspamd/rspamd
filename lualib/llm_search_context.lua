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
local lua_util = require "lua_util"
local lua_cache = require "lua_cache"
local ucl = require "ucl"

local DEFAULTS = {
  enabled = false,
  search_url = "https://leta.mullvad.net/search/__data.json",
  search_engine = "brave", -- Search engine to use (brave, google, etc.)
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

-- Query search API for a single domain
local function query_search_api(task, domain, opts, callback, debug_module)
  local Np = debug_module or N

  -- Prepare search query for Leta Mullvad API
  local query_params = {
    q = domain,
    engine = opts.search_engine,
  }

  -- Build query string
  local query_string = ""
  for k, v in pairs(query_params) do
    if query_string ~= "" then
      query_string = query_string .. "&"
    end
    query_string = query_string .. k .. "=" .. lua_util.url_encode_string(v)
  end

  local full_url = opts.search_url .. "?" .. query_string

  local function http_callback(err, code, body, _)
    if err then
      lua_util.debugm(Np, task, "search API error for domain '%s': %s", domain, err)
      callback(nil, domain, err)
      return
    end

    if code ~= 200 then
      rspamd_logger.infox(task, "search API returned code %s for domain '%s', url: %s, body: %s",
        code, domain, full_url, body and body:sub(1, 200) or 'nil')
      callback(nil, domain, string.format("HTTP %s", code))
      return
    end

    lua_util.debugm(Np, task, "search API success for domain '%s', url: %s", domain, full_url)

    -- Parse Leta Mullvad JSON response
    local parser = ucl.parser()
    local ok, parse_err = parser:parse_string(body)
    if not ok then
      rspamd_logger.errx(task, "%s: failed to parse search API response for %s: %s",
        Np, domain, parse_err)
      callback(nil, domain, parse_err)
      return
    end

    local data = parser:get_object()

    -- Extract search results from Leta Mullvad's nested structure
    -- Structure: data.nodes[3].data is a flat array with indices as pointers
    -- data[1] = metadata with pointers, data[5] = items array (Lua 1-indexed)
    local search_results = { results = {} }

    if data and data.nodes and type(data.nodes) == 'table' and #data.nodes >= 3 then
      local search_node = data.nodes[3]  -- Third node contains search data (Lua 1-indexed)

      if search_node and search_node.data and type(search_node.data) == 'table' then
        local flat_data = search_node.data
        local metadata = flat_data[1]

        lua_util.debugm(Np, task, "parsing domain '%s': flat_data has %d elements, metadata type: %s",
          domain, #flat_data, type(metadata))

        if metadata and metadata.items and type(metadata.items) == 'number' then
          -- metadata.items is a 0-indexed pointer, add 1 for Lua
          local items_idx = metadata.items + 1
          local items = flat_data[items_idx]

          if items and type(items) == 'table' then
            lua_util.debugm(Np, task, "found %d item indices for domain '%s', items_idx=%d",
              #items, domain, items_idx)

            local count = 0

            for _, result_idx in ipairs(items) do
              if count >= opts.max_results_per_query then
                break
              end

              -- result_idx is 0-indexed, add 1 for Lua
              local result_template_idx = result_idx + 1
              local result_template = flat_data[result_template_idx]

              if result_template and type(result_template) == 'table' then
                -- Extract values using the template's pointers (also 0-indexed)
                local link = result_template.link and flat_data[result_template.link + 1]
                local snippet = result_template.snippet and flat_data[result_template.snippet + 1]
                local title = result_template.title and flat_data[result_template.title + 1]

                lua_util.debugm(Np, task, "result %d template: link_idx=%s, snippet_idx=%s, title_idx=%s",
                  count + 1, tostring(result_template.link), tostring(result_template.snippet),
                  tostring(result_template.title))

                if link or title or snippet then
                  table.insert(search_results.results, {
                    title = title or "",
                    snippet = snippet or "",
                    url = link or ""
                  })
                  count = count + 1
                  lua_util.debugm(Np, task, "extracted result %d: title='%s', snippet_len=%d",
                    count, title or "nil", snippet and #snippet or 0)
                end
              else
                lua_util.debugm(Np, task, "result_template at idx %d is not a table: %s",
                  result_template_idx, type(result_template))
              end
            end
          else
            lua_util.debugm(Np, task, "items is not a table for domain '%s', type: %s",
              domain, type(items))
          end
        else
          lua_util.debugm(Np, task, "no valid metadata.items for domain '%s'", domain)
        end
      end
    end

    lua_util.debugm(Np, task, "extracted %d search results for domain '%s'",
      #search_results.results, domain)
    callback(search_results, domain, nil)
  end

  rspamd_http.request({
    url = full_url,
    timeout = opts.timeout,
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
        if i > opts.max_results_per_query then
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

  -- Create cache context
  local cache_ctx = nil
  if redis_params then
    cache_ctx = lua_cache.create_cache_context(redis_params, {
      cache_prefix = opts.cache_key_prefix,
      cache_ttl = opts.cache_ttl,
      cache_format = 'messagepack',
      cache_hash_len = 16,
      cache_use_hashing = true,
    }, Np)
  end

  local pending_queries = #domains
  local all_results = {}

  -- Callback for each domain query complete
  local function domain_complete(domain, results)
    pending_queries = pending_queries - 1

    if results then
      table.insert(all_results, {
        domain = domain,
        results = results
      })
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
    local cache_key = string.format("search:%s:%s", opts.search_engine, domain)

    if cache_ctx then
      -- Use lua_cache for caching
      lua_cache.cache_get(task, cache_key, cache_ctx, opts.timeout,
        function()
          -- Cache miss - query API
          query_search_api(task, domain, opts, function(api_results, d, api_err)
            if api_results then
              lua_cache.cache_set(task, cache_key, api_results, cache_ctx)
              domain_complete(d, api_results)
            else
              lua_util.debugm(Np, task, "search failed for domain %s: %s", d, api_err)
              domain_complete(d, nil)
            end
          end, Np)
        end,
        function(_, err, data)
          -- Cache hit or after miss callback
          if data and type(data) == 'table' then
            lua_util.debugm(Np, task, "cache hit for domain %s", domain)
            domain_complete(domain, data)
          -- If no data and no error, the miss callback was already invoked
          elseif err then
            lua_util.debugm(Np, task, "cache error for domain %s: %s", domain, err)
            domain_complete(domain, nil)
          end
        end)
    else
      -- No Redis, query directly
      query_search_api(task, domain, opts, function(api_results, d, api_err)
        if not api_results then
          lua_util.debugm(Np, task, "search failed for domain %s: %s", d, api_err)
        end
        domain_complete(d, api_results)
      end, Np)
    end
  end
end

return M
