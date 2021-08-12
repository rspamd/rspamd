--[[
Copyright (c) 2021, Vsevolod Stakhov <vsevolod@highsecure.ru>

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
]]--

local N = "aws_s3"
local lua_util = require "lua_util"
local lua_aws = require "lua_aws"
local rspamd_logger = require "rspamd_logger"
local ts = (require "tableshape").types
local rspamd_text = require "rspamd_text"
local rspamd_http = require "rspamd_http"

local settings = {
  s3_bucket = nil,
  s3_region = 'us-east-1',
  s3_secret_key = nil,
  s3_key_id = nil,
  s3_timeout = 10,
}

local settings_schema = ts.shape{
  s3_bucket = ts.string,
  s3_region = ts.string,
  s3_secret_key = ts.string,
  s3_key_id = ts.string,
  s3_timeout = ts.number + ts.string / lua_util.parse_time_interval,
  enabled = ts.boolean:is_optional(),
}

local function s3_aws_callback(task)
  local uri = string.format('https://%s.s3.amazonaws.com', settings.s3_bucket)
  -- Create a nonce
  local nonce = rspamd_text.randombytes(16):base32()
  local queue_id = task:get_queue_id()

  if not queue_id then
    queue_id = rspamd_text.randombytes(8):base32()
  end
  local path = string.format('/%s-%s', queue_id, nonce)
  -- Hack to pass host
  local aws_host = string.format('%s.s3.amazonaws.com', settings.s3_bucket)
  local hdrs = lua_aws.aws_request_enrich({
    region = settings.s3_region,
    headers = {
      ['Content-Type'] = 'message/rfc-822',
      ['Host'] = aws_host
    },
    uri = path,
    key_id = settings.s3_key_id,
    secret_key = settings.s3_secret_key,
    method = 'PUT',
  }, task:get_content())

  local function s3_http_callback(http_err, code, body, headers)
    rspamd_logger.errx('obj=%s, err=%s, code=%s, body=%s, headers=%s',
      path, http_err, code, body, headers)
  end

  rspamd_http.request({
    url = uri .. path,
    task = task,
    method = 'PUT',
    body = task:get_content(),
    callback = s3_http_callback,
    headers = hdrs,
    timeout = settings.s3_timeout,
  })
end

local opts = rspamd_config:get_all_opt('aws_s3')
if not opts then
  return
end

settings = lua_util.override_defaults(settings, opts)
local res,err = settings_schema:transform(settings)

if not res then
  rspamd_logger.warnx(rspamd_config, 'plugin is misconfigured: %s', err)

  return
end

rspamd_logger.infox(rspamd_config, 'enabled AWS s3 dump to %s', res.s3_bucket)

settings = res
rspamd_config:register_symbol({
  name = 'EXPORT_AWS_S3',
  type = 'idempotent',
  callback = s3_aws_callback,
  priority = 10,
  flags = 'empty,explicit_disable,ignore_passthrough,nostat',
})