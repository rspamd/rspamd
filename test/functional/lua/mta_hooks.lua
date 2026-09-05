-- Deterministic test policy; deliberately no network lookups or learning.
local ucl = require 'ucl'
local rspamd_util = require 'rspamd_util'
local rspamd_http = require 'rspamd_http'

local function slow_request(task)
  rspamd_http.request({
    task = task,
    url = 'http://127.0.0.1:' .. task:get_header('X-Hooks-Slow-Port') .. '/',
    timeout = 10,
    callback = function() end,
  })
end

rspamd_config:register_symbol({
  name = 'MTA_HOOKS_SLOW_PREFILTER',
  type = 'prefilter',
  callback = function(task)
    if task:get_header('X-Hooks-Test') == 'slow' then
      slow_request(task)
    end
    return false
  end,
})

rspamd_config:register_symbol({
  name = 'MTA_HOOKS_TEST',
  type = 'postfilter',
  flags = 'empty,ignore_passthrough',
  callback = function(task)
    local mode = task:get_header('X-Hooks-Test') or 'accept'
    if mode == 'slow' then
      slow_request(task)
    elseif mode == 'reject' or mode == 'soft reject' or mode == 'discard' or mode == 'quarantine' then
      task:set_pre_result(mode, 'Hooks test policy', 'mta_hooks_test')
    elseif mode == 'remove' then
      task:set_milter_reply({add_headers = {['X-Good'] = 'yes'}, remove_headers = {['X-Old'] = 0}})
    elseif mode == 'headers' then
      local ip = task:get_ip()
      local from = task:get_from('smtp') or {}
      local rcpt = task:get_recipients('smtp') or {}
      local metadata = {
        nonce = rspamd_util.random_hex(16),
        ip = ip and ip:is_valid() and ip:to_string() or 'none',
        from = from[1] and from[1].addr or '',
        rcpt = rcpt[1] and rcpt[1].addr or '',
        helo = task:get_helo(),
        queue = task:get_queue_id(),
        mail_args = task:get_mail_esmtp_args(),
        privileged = task:get_request_header('Settings') or task:get_request_header('Authorization'),
      }
      task:set_milter_reply({add_headers = {['X-Hooks-Metadata'] = ucl.to_format(metadata, 'json-compact')}})
    end
    return false
  end,
})
