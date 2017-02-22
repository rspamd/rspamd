---
layout: doc_lua
title: Lua API documentation
---

# Lua API documentation {#top}

[Lua](http://www.lua.org) is used for writing rules and plugins in Rspamd. Rspamd exposes various core functionality through its Lua API.

## Using Lua API from rules {#luarules}

Many Lua rules are shipped with Rspamd. These are included via `rspamd.lua` which is referenced using **lua** tag in `common.conf`:

~~~ucl
lua = "$CONFDIR/lua/rspamd.lua"
~~~

### Global configuration tables {#luaglobal}

While loading this file Rspamd defines two global variables:
- *config* - a global table of modules configuration. Here is a sample of usage of this table:

~~~lua
-- Init empty module configuration
config['module'] = {}

-- Rewrite module configuration
config['regexp'] = {
    RULE_NAME = '/some_re/'
}

-- Insert by index
config['regexp']['RULE_NAME2'] = '/more_re/'

~~~

- *metrics* - a global table of metrics definitions. This variable is a table that is indexed by metric name and provides the ability to set up symbols' properties:

~~~lua

metrics['default'] = {
    -- Set weight and description
    SYMBOL = { weight = 9.0, description = 'description'},
    -- Just set weight
    SYMBOL2 = 9.0,
}
-- Add symbol definition
metrics['default']['SYMBOL3'] = { weight = 1, description = 'description' }
~~~

* *classifiers* - a table of classifiers pre-filters. Pre-filter must be a function that accepts 4 parameters: `classifier`, `task`, `is_learn` and `is_spam`. Pre-filter must return a table of statfiles to be checked or learned for this message or nil if all suitable statfiles must be learned or checked. Here is an example of language detection for classification:

~~~lua

-- Detect language of message and selects appropriate statfiles for it

classifiers['bayes'] = function(classifier, task, is_learn, is_spam)
    -- Subfunction for detection of message's language
    local detect_language = function(task)
        local parts = task:get_text_parts()
        for _,p in ipairs(parts) do
            local l = p:get_language()
            if l then
                return l
            end
        end
        return nil
    end

    -- Main procedure
    language = detect_language(task)
    if language then
        -- Find statfiles with specified language
        local selected = {}
        for _,st in pairs(classifier:get_statfiles()) do
            local st_l = st:get_param('language')
            if st_l and st_l == language then
                -- Insert statfile with specified language
                table.insert(selected, st)
            end
        end
        if table.maxn(selected) > 1 then
            return selected
        end
    else
        -- Language not detected
        local selected = {}
        for _,st in ipairs(classifier:get_statfiles()) do
            local st_l = st:get_param('language')
            -- Insert only statfiles without language
            if not st_l then
                table.insert(selected, st)
            end
        end
        if table.maxn(selected) > 1 then
            return selected
        end
    end

    return nil
end
~~~

* *rspamd_config* - is a global object that allows you to modify configuration and register new symbols.

## Writing advanced rules {#luarules}

So by using these two tables it is possible to configure rules and metrics. Also note that it is possible to use any Lua functions and Rspamd libraries:

~~~lua
-- Declare variable that contains regexp rule definition
local rulebody = string.format('%s & !%s', '/re1/', '/re2')
-- Set global table element config['regexp']['test_rule'] = rulebody
-- Write message to log
rspamd_logger.info('Loaded test rule: ' .. rulebody)
~~~

Also it is possible to declare functions and use `closures` when defining Rspamd rules:

~~~lua
-- Here is a sample of using closure function inside rule
local function check_headers_tab(task, header_name)
    -- Extract raw headers from message
    local raw_headers = task:get_raw_header(header_name)
    -- Make match of headers, that are separated with tabs, not spaces
    if raw_headers then
        for _,rh in ipairs(raw_headers) do
            if rh['tab_separated'] then
                -- We have header value separated by tab symbol
                return true,rh['name']
            end
        end
    end
    return false
end

rspamd_config.HEADER_TAB_FROM_WHITELISTED = function(task) return check_headers_tab(task, "From") end
rspamd_config.HEADER_TAB_TO_WHITELISTED = function(task) return check_headers_tab(task, "To") end
rspamd_config.HEADER_TAB_DATE_WHITELISTED = function(task) return check_headers_tab(task, "Date") end

-- Table form of rule definition
rspamd_config.R_EMPTY_IMAGE = {
    callback = function(task)
      local tp = task:get_text_parts() -- get text parts in a message

      for _,p in ipairs(tp) do -- iterate over text parts array using `ipairs`
        if p:is_html() then -- if the current part is html part
          local hc = p:get_html() -- we get HTML context
          local len = p:get_length() -- and part's length

          if len < 50 then -- if we have a part that has less than 50 bytes of text
            local images = hc:get_images() -- then we check for HTML images

            if images then -- if there are images
              for _,i in ipairs(images) do -- then iterate over images in the part
                if i['height'] + i['width'] >= 400 then -- if we have a large image
                  return true -- add symbol
                end
              end
            end
          end
        end
      end
    end,
    score = 10.0,
    condition = function(task)
        if task:get_header('Subject') then
            return true
        end
        return false
    end,
    description = 'No text parts and a large image',
    score = 3.1,
}
~~~

Using Lua in rules provides many abilities to write complex mail filtering rules.

## Writing Lua plugins {#luaplugins}

Plugins are more complex filters than ordinary rules. Plugins can have their own configuration parameters and multiple callbacks. Plugins can make DNS requests, read from Rspamd maps and insert custom results.

### Structure of the typical plugin

Each Rspamd plugin has a common structure:

- Registering configuration parameters
- Reading configuration parameters and set up callbacks
- Callbacks that are called by Rspamd during message processing

Here is a simple plugin example:

~~~lua
local config_param = 'default'

local function sample_callback(task)
end


-- Reading configuration

-- Get all options for this plugin
local opts =  rspamd_config:get_all_opt('sample')
if opts then
    if opts['config'] then
        config_param = opts['config']
        -- Register callback
        rspamd_config:register_symbol('some_symbol', sample_callback)
    end
end
~~~

This plugin uses global variable *rspamd_config* to extract configuration options. Then it registers function `sample_callback` that will be called for processing symbol `some_symbol`.

### Using DNS requests inside plugins

It is often required to make DNS requests for messages checks. Here is an example of making asynchronous DNS request from Rspamd Lua plugin:

~~~lua
-- Function-callback of Rspamd rule
local function symbol_cb(task)
    -- Task is now local variable

    local function dns_cb(resolver, to_resolve, results, err, str)
        -- Increase total count of dns requests
        task:inc_dns_req()
        if results then
            task:insert_result('symbol', 1, str)
        end
    end
    -- Resolve 'example.com' using primitives from the task passed
    task:get_resolver():resolve_a(task:get_session(), task:get_mempool(),
            'example.com', dns_cb, 'sample string')
end
~~~

### Using maps from Lua plugin

Maps hold dynamically loaded data like lists or IP trees. It is possible to use 3 types of maps:

* **radix_tree** stores IP addresses
* **hash_map** stores plain strings (domains usually)
* **callback** call for a specified Lua callback when a map is loaded or changed, map's content is passed to that callback as a parameter

Here is a sample of using maps from Lua API:

~~~lua
local rspamd_logger = require "rspamd_logger"

-- Add two maps in configuration section
local hash_map = rspamd_config:add_hash_map('file:///path/to/file', 'sample map')
local radix_tree = rspamd_config:add_radix_map('http://somehost.com/test.dat', 'sample ip map')
local generic_map = rspamd_config:add_map('file:///path/to/file', 'sample generic map',
    function(str)
        -- This callback is called when a map is loaded or changed
        -- Str contains map content
        rspamd_logger.info('Got generic map content: ' .. str)
    end)

local function sample_symbol_cb(task)
    -- Check whether hash map contains from address of message
    if hash_map:get_key(task:get_from()) then
        -- Check whether radix map contains client's ip
        if radix_map:get_key(task:get_from_ip_num()) then
        ...
        end
    end
end
~~~

## Conclusions {#luaconclusion}

Lua plugins are a powerful tool for creating complex filters that can access practically all features of Rspamd. Lua plugins can be used for writing custom rules which could interact with Rspamd in many ways such as using maps and making DNS requests. Rspamd is shipped with a number of Lua plugins that could be used as examples while writing your own plugins.

## References {#luareference}

- [Lua manual](http://www.lua.org/manual/5.1/)
- [Programming in Lua](http://www.lua.org/pil/)
