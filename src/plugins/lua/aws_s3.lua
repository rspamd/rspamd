--[[
Copyright (c) 2022, Vsevolod Stakhov <vsevolod@rspamd.com>

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
local rspamd_util = require "rspamd_util"

local settings = {
  s3_bucket = nil,
  s3_region = 'us-east-1',
  s3_host = 's3.amazonaws.com',
  s3_secret_key = nil,
  s3_key_id = nil,
  s3_timeout = 10,
  save_raw = true,
  save_structure = false,
  inline_content_limit = nil,
}

local settings_schema = ts.shape{
  s3_bucket = ts.string,
  s3_region = ts.string,
  s3_host = ts.string,
  s3_secret_key = ts.string,
  s3_key_id = ts.string,
  s3_timeout = ts.number + ts.string / lua_util.parse_time_interval,
  enabled = ts.boolean:is_optional(),
  fail_action = ts.string:is_optional(),
  zstd_compress = ts.boolean:is_optional(),
  save_raw = ts.boolean:is_optional(),
  save_structure = ts.boolean:is_optional(),
  inline_content_limit = ts.number:is_optional(),
}

local function raw_data(task, nonce, queue_id)
  local ext, content, content_type

  if settings.zstd_compress then
    ext = 'eml.zst'
    content = rspamd_util.zstd_compress(task:get_content())
    content_type = 'application/zstd'
  else
    ext = 'eml'
    content = task:get_content()
    content_type = 'message/rfc-822'
  end

  local path = string.format('/%s-%s.%s', queue_id, nonce, ext)

  return path, content, content_type
end

local function gen_ext(base)
  local ext = base
  if settings.zstd_compress then
    ext = base .. '.zst'
  end

  return ext
end

local function convert_to_ref(task, nonce, queue_id, part, external_refs)
  local path = string.format('/%s-%s-%s.%s', queue_id, nonce,
      rspamd_text.randombytes(8):base32(), gen_ext('raw'))
  local content = part.content

  if settings.zstd_compress then
    external_refs[path] = rspamd_util.zstd_compress(content)
  else
    external_refs[path] = content
  end

  part.content = nil
  part.content_path = path

  return path
end

local function structured_data(task, nonce, queue_id)
  local content, content_type
  local external_refs = {}
  local lua_mime = require "lua_mime"
  local ucl = require "ucl"

  local message_split = lua_mime.message_to_ucl(task)
  if settings.inline_content_limit and settings.inline_content_limit > 0 then

    for i,part in ipairs(message_split.parts or {}) do
      if part.content and #part.content >= settings.inline_content_limit then
        local ref = convert_to_ref(task, nonce, queue_id, part, external_refs)
        lua_util.debugm(N, task, "convert part number %s to a reference %s",
          i, ref)
      end
    end
  end

  if settings.zstd_compress then
    content = rspamd_util.zstd_compress(ucl.to_format(message_split, 'msgpack'))
    content_type = 'application/zstd'
  else
    content = ucl.to_format(message_split, 'msgpack')
    content_type = 'application/msgpack'
  end

  local path = string.format('/%s-%s.%s', queue_id, nonce, gen_ext('msgpack'))

  return path, content, content_type, external_refs
end

local function s3_aws_callback(task)
  local uri = string.format('https://%s.%s', settings.s3_bucket, settings.s3_host)
  -- Create a nonce
  local nonce = rspamd_text.randombytes(16):base32()
  local queue_id = task:get_queue_id()
  if not queue_id then
    queue_id = rspamd_text.randombytes(8):base32()
  end
  -- Hack to pass host
  local aws_host = string.format('%s.%s', settings.s3_bucket, settings.s3_host)

  local function gen_s3_http_callback(path, what)
    return function (http_err, code, body, headers)

      if http_err then
        if settings.fail_action then
          task:set_pre_result(settings.fail_action,
              string.format('S3 save failed: %s', http_err), N,
              nil, nil, 'least')
        end
        rspamd_logger.errx(task, 'cannot save %s to AWS S3: %s', path, http_err)
      else
        rspamd_logger.messagex(task, 'saved %s successfully in S3 object %s', what, path)
      end
      lua_util.debugm(N, task, 'obj=%s, err=%s, code=%s, body=%s, headers=%s',
          path, http_err, code, body, headers)
    end
  end

  if settings.save_raw then
    local path, content, content_type = raw_data(task, nonce, queue_id)
    local hdrs = lua_aws.aws_request_enrich({
      region = settings.s3_region,
      headers = {
        ['Content-Type'] = content_type,
        ['Host'] = aws_host
      },
      uri = path,
      key_id = settings.s3_key_id,
      secret_key = settings.s3_secret_key,
      method = 'PUT',
    }, content)
    rspamd_http.request({
      url = uri .. path,
      task = task,
      method = 'PUT',
      body = content,
      callback = gen_s3_http_callback(path, 'raw message'),
      headers = hdrs,
      timeout = settings.s3_timeout,
    })
  end
  if settings.save_structure then
    local path, content, content_type, external_refs = structured_data(task, nonce, queue_id)
    local hdrs = lua_aws.aws_request_enrich({
      region = settings.s3_region,
      headers = {
        ['Content-Type'] = content_type,
        ['Host'] = aws_host
      },
      uri = path,
      key_id = settings.s3_key_id,
      secret_key = settings.s3_secret_key,
      method = 'PUT',
    }, content)
    rspamd_http.request({
      url = uri .. path,
      task = task,
      method = 'PUT',
      body = content,
      callback = gen_s3_http_callback(path, 'structured message'),
      headers = hdrs,
      upstream = settings.upstreams:get_upstream_round_robin(),
      timeout = settings.s3_timeout,
    })

    for ref,part_content in pairs(external_refs) do
      local part_hdrs = lua_aws.aws_request_enrich({
        region = settings.s3_region,
        headers = {
          ['Content-Type'] = content_type,
          ['Host'] = aws_host
        },
        uri = ref,
        key_id = settings.s3_key_id,
        secret_key = settings.s3_secret_key,
        method = 'PUT',
      }, part_content)
      rspamd_http.request({
        url = uri .. ref,
        task = task,
        upstream = settings.upstreams:get_upstream_round_robin(),
        method = 'PUT',
        body = part_content,
        callback = gen_s3_http_callback(ref, 'part content'),
        headers = part_hdrs,
        timeout = settings.s3_timeout,
      })
    end
  end


end

local opts = rspamd_config:get_all_opt('aws_s3')
if not opts then
  return
end

settings = lua_util.override_defaults(settings, opts)
local res,err = settings_schema:transform(settings)

if not res then
  rspamd_logger.warnx(rspamd_config, 'plugin is misconfigured: %s', err)
  lua_util.disable_module(N, "config")
  return
end

rspamd_logger.infox(rspamd_config, 'enabled AWS s3 dump to %s', res.s3_bucket)

settings = res

settings.upstreams = lua_util.http_upstreams_by_url(rspamd_config:get_mempool(),
    string.format('https://%s.%s', settings.s3_bucket, settings.s3_host))

if not settings.upstreams then
  rspamd_logger.warnx(rspamd_config, 'cannot parse hostname: %s',
      string.format('https://%s.%s', settings.s3_bucket, settings.s3_host))
  lua_util.disable_module(N, "config")
  return
end

rspamd_config:register_symbol({
  name = 'EXPORT_AWS_S3',
  type = settings.fail_action and 'postfilter' or 'idempotent',
  callback = s3_aws_callback,
  priority = settings.fail_action and lua_util.symbols_priorities.high or nil,
  flags = 'empty,explicit_disable,ignore_passthrough,nostat',
})