--[[
FastText embedding provider for neural feature fusion.
Loads a FastText model (supervised or unsupervised) and computes sentence
embeddings from message text. Supports per-language models for multilingual
deployments.

By default, all configured language_models are used for every message
(multi_model = true), producing richer cross-lingual representations.
Set multi_model = false to select a single model based on detected language.

Pooling modes (pooling = "mean_max" by default):
  "mean"     - average of word vectors (classic fasttext sentence vector)
  "mean_max" - concatenation of mean and element-wise max pooling

Configuration example in neural.conf:
  providers = [
    {
      type = "fasttext_embed";
      model = "/path/to/default_model.bin";
      # Optional per-language models
      language_models = {
        en = "/path/to/en_model.bin";
        ru = "/path/to/ru_model.bin";
      };
      weight = 1.0;
      multi_model = true;    # use all language models (default)
      pooling = "mean_max";  # mean + max pooling (default)
    }
  ];
]] --

local rspamd_logger = require "rspamd_logger"
local lua_mime = require "lua_mime"
local neural_common = require "plugins/neural"

local N = "neural.fasttext_embed"

-- Cache of loaded FastText models: path -> model userdata
local loaded_models = {}

-- Try to load rspamd_fasttext; may be nil if not compiled with FastText
local ok, rspamd_fasttext = pcall(require, "rspamd_fasttext")
if not ok then
  rspamd_fasttext = nil
end

local function load_model(path)
  if not rspamd_fasttext then
    rspamd_logger.errx(rspamd_config, '%s: rspamd_fasttext module not available (compiled without FastText?)', N)
    return nil
  end

  if loaded_models[path] then
    return loaded_models[path]
  end

  rspamd_logger.infox(rspamd_config, '%s: loading FastText model from %s', N, path)
  local model = rspamd_fasttext.load(path)

  if model and model:is_loaded() then
    rspamd_logger.infox(rspamd_config, '%s: loaded FastText model %s, dimension=%s',
      N, path, model:get_dimension())
    loaded_models[path] = model
    return model
  else
    rspamd_logger.errx(rspamd_config, '%s: failed to load FastText model from %s', N, path)
    return nil
  end
end

-- Collect all available models (for multi_model mode)
local function collect_all_models(pcfg)
  local models = {}

  if pcfg.language_models then
    -- Sort by language key for deterministic order
    local langs = {}
    for lang, _ in pairs(pcfg.language_models) do
      langs[#langs + 1] = lang
    end
    table.sort(langs)

    for _, lang in ipairs(langs) do
      local path = pcfg.language_models[lang]
      local model = load_model(path)
      if model then
        models[#models + 1] = { model = model, path = path, lang = lang }
      end
    end
  end

  -- Add default model if configured and not already loaded
  if pcfg.model then
    local already_loaded = false
    for _, m in ipairs(models) do
      if m.path == pcfg.model then
        already_loaded = true
        break
      end
    end
    if not already_loaded then
      local model = load_model(pcfg.model)
      if model then
        models[#models + 1] = { model = model, path = pcfg.model, lang = 'default' }
      end
    end
  end

  return models
end

-- Select a single model based on language (for single-model mode)
local function select_model(pcfg, language)
  -- Check per-language models first
  if language and pcfg.language_models then
    local lang_path = pcfg.language_models[language]
    if lang_path then
      local model = load_model(lang_path)
      if model then
        return { { model = model, path = lang_path, lang = language } }
      end
    end
  end

  -- Fallback to default model
  if pcfg.model then
    local model = load_model(pcfg.model)
    if model then
      return { { model = model, path = pcfg.model, lang = 'default' } }
    end
  end

  return {}
end

-- Extract words from text parts
local function extract_words(task, opts)
  local words = {}
  local how = opts.word_form or 'norm'

  -- Get text parts
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

-- Compute mean and optionally max pooling from word vectors
local function compute_pooled_vectors(model, words, pooling)
  local dim = model:get_dimension()
  local mean_vec = {}
  local max_vec = {}
  local need_max = (pooling == 'mean_max')

  for d = 1, dim do
    mean_vec[d] = 0.0
    if need_max then
      max_vec[d] = -math.huge
    end
  end

  local count = 0
  for _, w in ipairs(words) do
    local wv = model:get_word_vector(w)
    if wv and #wv >= dim then
      count = count + 1
      for d = 1, dim do
        mean_vec[d] = mean_vec[d] + wv[d]
        if need_max and wv[d] > max_vec[d] then
          max_vec[d] = wv[d]
        end
      end
    end
  end

  if count == 0 then
    return nil
  end

  -- Normalize mean
  for d = 1, dim do
    mean_vec[d] = mean_vec[d] / count
  end

  -- L2-normalize mean vector (match fasttext behavior)
  local norm = 0.0
  for d = 1, dim do
    norm = norm + mean_vec[d] * mean_vec[d]
  end
  norm = math.sqrt(norm)
  if norm > 0 then
    for d = 1, dim do
      mean_vec[d] = mean_vec[d] / norm
    end
  end

  if need_max then
    -- L2-normalize max vector
    norm = 0.0
    for d = 1, dim do
      norm = norm + max_vec[d] * max_vec[d]
    end
    norm = math.sqrt(norm)
    if norm > 0 then
      for d = 1, dim do
        max_vec[d] = max_vec[d] / norm
      end
    end

    -- Concatenate mean + max
    for d = 1, dim do
      mean_vec[dim + d] = max_vec[d]
    end
  end

  return mean_vec
end

neural_common.register_provider('fasttext_embed', {
  collect_async = function(task, ctx, cont)
    local pcfg = ctx.config or {}

    if not rspamd_fasttext then
      rspamd_logger.debugm(N, task, 'fasttext_embed: rspamd_fasttext not available; skip')
      cont(nil)
      return
    end

    -- Select models: all models or single based on language
    local multi_model = pcfg.multi_model ~= false -- default true
    local models
    if multi_model and pcfg.language_models then
      models = collect_all_models(pcfg)
    else
      local language = task and (function()
        local part = lua_mime.get_displayed_text_part(task)
        if part then
          local lang = part:get_language()
          if lang and lang ~= '' then
            return lang
          end
        end
        return nil
      end)()
      models = select_model(pcfg, language)
    end

    if #models == 0 then
      rspamd_logger.debugm(N, task, 'fasttext_embed: no models available; skip')
      cont(nil)
      return
    end

    -- Extract words; use 'norm' by default for FastText (it expects lowercased tokens)
    local words = extract_words(task, {
      word_form = pcfg.word_form or 'norm',
      all_parts = pcfg.all_parts,
    })

    -- Optionally prepend subject words
    if pcfg.include_subject ~= false then
      local subj = task:get_subject()
      if subj and #subj > 0 then
        -- Simple whitespace tokenization for subject
        for w in subj:gmatch('%S+') do
          table.insert(words, 1, w:lower())
        end
      end
    end

    if #words == 0 then
      rspamd_logger.debugm(N, task, 'fasttext_embed: no words found; skip')
      cont(nil)
      return
    end

    local pooling = pcfg.pooling or 'mean_max'
    local combined_vec = {}
    local model_names = {}
    local total_dim = 0

    for _, m in ipairs(models) do
      local vec = compute_pooled_vectors(m.model, words, pooling)
      if vec then
        for _, v in ipairs(vec) do
          combined_vec[#combined_vec + 1] = v
        end
        total_dim = total_dim + #vec
        model_names[#model_names + 1] = m.lang
      end
    end

    if #combined_vec == 0 then
      rspamd_logger.debugm(N, task, 'fasttext_embed: empty vectors from all models; skip')
      cont(nil)
      return
    end

    local meta = {
      name = pcfg.name or 'fasttext_embed',
      type = 'fasttext_embed',
      dim = total_dim,
      weight = ctx.weight or 1.0,
      models = table.concat(model_names, '+'),
      pooling = pooling,
    }

    rspamd_logger.debugm(N, task, 'fasttext_embed: produced %s-dim vector (%s models, %s pooling, %s words)',
      total_dim, #models, pooling, #words)
    cont(combined_vec, meta)
  end,
})
