--[[
Static embedding provider for neural feature fusion.

The cheap, multilingual successor to fasttext_embed: words produced by
rspamd's regular tokenization pipeline are re-tokenized into WordPiece
subword tokens and embedded by mean-pooling rows of a static
token-embedding matrix (Model2Vec style). No neural forward pass is
involved; all heavy lifting (tokenizer, mmap-ed float32 matrix, pooling)
lives in the rspamd_static_embed C module, so the model is shared between
workers and never copied into the Lua heap.

The WordPiece tokenizer is internal to the vectorizer: the global
word-breaking / statistics tokenization is not affected, so Bayes tokens
and fuzzy hashes stay exactly as they were.

A model directory must contain config.json, vocab.txt and the matrix file
(see the rspamd_static_embed module docs); models are shipped separately
as data, like FastText models. Any deviation from the supported spec
disables the provider with an explicit error - there is no silent
fallback.

Note: the rspamd_static_embed module also exposes per-token sequence
access (model:get_token_vectors) for external consumers such as offline
trainers exporting order-aware text features. The provider path is not
affected: fusion vectors must stay fixed-dim, so only the pooled
get_sentence_vector is used here.

Configuration example in neural.conf:
  providers = [
    {
      type = "static_embed";
      model = "/path/to/model_dir";
      weight = 1.0;
    }
  ];
]] --

local rspamd_logger = require "rspamd_logger"
local lua_mime = require "lua_mime"

local N = "neural.static_embed"

local exports = {}

-- May be nil on incomplete builds; checked in load_model
local se_ok, rspamd_static_embed = pcall(require, "rspamd_static_embed")

-- Cache of loaded models: dir -> model; load errors are cached too so that
-- a broken config is reported once instead of on every scanned message
local loaded_models = {}
local failed_models = {}

exports.load_model = function(dir)
  if loaded_models[dir] then
    return loaded_models[dir]
  end
  if failed_models[dir] then
    return nil, failed_models[dir]
  end

  local model, err
  if not se_ok then
    err = 'rspamd_static_embed module is not available'
  else
    model, err = rspamd_static_embed.load(dir)
  end

  if not model then
    failed_models[dir] = err or 'unknown error'
    return nil, failed_models[dir]
  end

  loaded_models[dir] = model
  return model
end

-- Extract words exactly like fasttext_embed does
local function extract_words(task, opts)
  local words = {}
  local how = opts.word_form or 'norm'

  local parts
  if opts.all_parts then
    parts = task:get_text_parts()
  else
    local sel = lua_mime.get_displayed_text_part(task)
    if sel then
      parts = { sel }
    else
      parts = task:get_text_parts()
    end
  end

  if not parts then
    return words
  end

  for _, part in ipairs(parts) do
    local pw = part:get_words(how)
    if pw then
      for _, w in ipairs(pw) do
        if type(w) == 'string' and #w > 0 then
          words[#words + 1] = w
        end
      end
    end
  end

  return words
end

-- Provider registration is skipped when neural is not loadable (e.g. in
-- unit tests); the exported helpers are still usable in that case
local neural_ok, neural_common = pcall(require, "plugins/neural")

if neural_ok then
  neural_common.register_provider('static_embed', {
    init = function(pcfg)
      if not pcfg.model then
        rspamd_logger.errx(rspamd_config, '%s: no model directory specified', N)
        return
      end

      local model, err = exports.load_model(pcfg.model)
      if model then
        rspamd_logger.infox(rspamd_config, '%s: loaded model from %s: %s tokens, dim=%s',
          N, pcfg.model, model:get_vocab_size(), model:get_dimension())
      else
        rspamd_logger.errx(rspamd_config, '%s: cannot load model from %s: %s; provider disabled',
          N, pcfg.model, err)
      end
    end,
    collect_async = function(task, ctx, cont)
      local pcfg = ctx.config or {}

      local model = pcfg.model and exports.load_model(pcfg.model) or nil
      if not model then
        rspamd_logger.debugm(N, task, 'static_embed: no model available; skip')
        cont(nil)
        return
      end

      local words = extract_words(task, {
        word_form = pcfg.word_form or 'norm',
        all_parts = pcfg.all_parts,
      })

      -- Optionally prepend subject words; case/punctuation are handled by
      -- the model's own normalizer, so no extra preprocessing is needed
      if pcfg.include_subject ~= false then
        local subj = task:get_subject()
        if subj and #subj > 0 then
          for w in subj:gmatch('%S+') do
            table.insert(words, 1, w)
          end
        end
      end

      -- Empty input produces a zero vector: dimensionality stays stable
      local vec, ntokens = model:get_sentence_vector(words)

      local meta = {
        name = pcfg.name or 'static_embed',
        type = 'static_embed',
        dim = model:get_dimension(),
        weight = ctx.weight or 1.0,
        tokens = ntokens,
      }

      rspamd_logger.debugm(N, task, 'static_embed: produced %s-dim vector from %s tokens (%s words)',
        meta.dim, ntokens, #words)
      cont(vec, meta)
    end,
  })
end

return exports
