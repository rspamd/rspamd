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

Conv1d output mode (output_mode = "conv1d"):
  Multi-scale max-over-time pooling over sliding word windows.
  For each kernel size, averages word vectors in a window, then
  max-pools across all window positions per channel.
  Produces compact features: n_scales * pools_per_scale * channels.
  Options:
    kernel_sizes = [1, 3, 5]  - window sizes (default)
    conv_pooling = "max"      - per-scale pooling: "max", "mean", "mean_max"
    max_words = 32            - max word positions (default)

SIF (Smooth Inverse Frequency) weighting is enabled by default (sif_weight = true).
Common words (the, is, a) get near-zero weight, distinctive words get high weight.
Tune with sif_a parameter (default 1e-3). Set sif_weight = false to disable.

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
      sif_weight = true;     # SIF word weighting (default)
      sif_a = 1e-3;          # SIF smoothing parameter (default)
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
-- When sif_a > 0, uses SIF (Smooth Inverse Frequency) weighting:
--   w(word) = a / (a + p(word))
-- where p(word) is the word probability from the model's vocabulary.
-- Common words get near-zero weight, distinctive words get high weight.
local function compute_pooled_vectors(model, words, pooling, sif_a)
  local dim = model:get_dimension()
  local mean_vec = {}
  local max_vec = {}
  local need_max = (pooling == 'mean_max')
  local use_sif = sif_a and sif_a > 0

  for d = 1, dim do
    mean_vec[d] = 0.0
    if need_max then
      max_vec[d] = -math.huge
    end
  end

  local total_weight = 0.0
  for _, w in ipairs(words) do
    local wv = model:get_word_vector(w)
    if wv and #wv >= dim then
      -- SIF weight: a / (a + p(word)); unknown words get weight 1.0
      local weight = 1.0
      if use_sif then
        local freq = model:get_word_frequency(w)
        if freq > 0 then
          weight = sif_a / (sif_a + freq)
        end
      end

      total_weight = total_weight + weight
      for d = 1, dim do
        mean_vec[d] = mean_vec[d] + wv[d] * weight
        if need_max and wv[d] > max_vec[d] then
          max_vec[d] = wv[d]
        end
      end
    end
  end

  if total_weight == 0 then
    return nil
  end

  -- Normalize weighted mean
  for d = 1, dim do
    mean_vec[d] = mean_vec[d] / total_weight
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

-- Multi-scale pooling for conv1d feature extraction.
-- Instead of storing raw NCW matrices and relying on KANN conv1d,
-- we apply fixed convolution-like operations in Lua and store compact features.
--
-- For each window size k in kernel_sizes (default {1, 3, 5}):
--   1. Slide a window of k words over the sequence
--   2. Average word vectors within each window (like a fixed conv filter)
--   3. Max-pool (and optionally mean-pool) over all window positions
-- Each scale's features are L2-normalized independently for balanced contribution.
-- Output: flat table of n_scales * n_pool * C floats (e.g., 3 * 2 * 100 = 600 for mean_max)
local function compute_conv1d_features(models, words, max_words, sif_a, opts)
  opts = opts or {}
  local use_sif = sif_a and sif_a > 0
  local nwords = math.min(#words, max_words)
  local kernel_sizes = opts.kernel_sizes or { 1, 3, 5 }
  local conv_pooling = opts.conv_pooling or 'mean_max'
  local need_mean = (conv_pooling == 'mean_max' or conv_pooling == 'mean')
  local need_max = (conv_pooling == 'mean_max' or conv_pooling == 'max')

  if nwords == 0 then
    return nil, 0, 0
  end

  -- Compute total channels (sum of all model dimensions)
  local total_channels = 0
  for _, m in ipairs(models) do
    total_channels = total_channels + m.model:get_dimension()
  end

  -- Collect word vectors: word_vecs[w][c] for word position w, channel c
  local word_vecs = {}
  for w = 1, nwords do
    local wv_all = {}
    for _, m in ipairs(models) do
      local wv = m.model:get_word_vector(words[w])
      local dim = m.model:get_dimension()
      if wv and #wv >= dim then
        local weight = 1.0
        if use_sif then
          local freq = m.model:get_word_frequency(words[w])
          if freq > 0 then
            weight = sif_a / (sif_a + freq)
          end
        end
        for d = 1, dim do
          wv_all[#wv_all + 1] = wv[d] * weight
        end
      else
        for _ = 1, dim do
          wv_all[#wv_all + 1] = 0.0
        end
      end
    end
    word_vecs[w] = wv_all
  end

  -- Multi-scale pooling with per-scale L2 normalization
  local output = {}

  for _, k in ipairs(kernel_sizes) do
    local scale_mean = need_mean and {} or nil
    local scale_max = need_max and {} or nil

    -- Initialize per-scale accumulators
    for c = 1, total_channels do
      if scale_mean then
        scale_mean[c] = 0.0
      end
      if scale_max then
        scale_max[c] = -math.huge
      end
    end

    -- Slide window of size k over word positions
    local n_windows = nwords - k + 1
    if n_windows < 1 then
      -- Sequence too short for this kernel; treat each word as a window
      n_windows = nwords
      for c = 1, total_channels do
        for w = 1, nwords do
          local val = word_vecs[w][c] or 0.0
          if scale_mean then
            scale_mean[c] = scale_mean[c] + val
          end
          if scale_max and val > scale_max[c] then
            scale_max[c] = val
          end
        end
        if scale_mean then
          scale_mean[c] = scale_mean[c] / nwords
        end
      end
    else
      for c = 1, total_channels do
        for start = 1, n_windows do
          -- Average word vectors within this window
          local sum = 0.0
          for w = start, start + k - 1 do
            sum = sum + (word_vecs[w][c] or 0.0)
          end
          local avg = sum / k
          if scale_mean then
            scale_mean[c] = scale_mean[c] + avg
          end
          if scale_max and avg > scale_max[c] then
            scale_max[c] = avg
          end
        end
        if scale_mean then
          scale_mean[c] = scale_mean[c] / n_windows
        end
      end
    end

    -- L2-normalize and append mean features for this scale
    if scale_mean then
      local norm = 0.0
      for c = 1, total_channels do
        norm = norm + scale_mean[c] * scale_mean[c]
      end
      norm = math.sqrt(norm)
      for c = 1, total_channels do
        output[#output + 1] = norm > 0 and (scale_mean[c] / norm) or 0.0
      end
    end

    -- L2-normalize and append max features for this scale
    if scale_max then
      local norm = 0.0
      for c = 1, total_channels do
        norm = norm + scale_max[c] * scale_max[c]
      end
      norm = math.sqrt(norm)
      for c = 1, total_channels do
        output[#output + 1] = norm > 0 and (scale_max[c] / norm) or 0.0
      end
    end
  end

  local pools_per_scale = (need_mean and 1 or 0) + (need_max and 1 or 0)
  return output, total_channels, pools_per_scale
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

    -- Conv1d output mode: multi-scale max-over-time pooling.
    -- For each kernel size, averages word vectors in sliding windows, then
    -- max-pools across all positions per channel. Produces compact features:
    -- n_scales * pools_per_scale * total_channels.
    if pcfg.output_mode == 'conv1d' then
      local max_words = pcfg.max_words or 32
      local sif_a = pcfg.sif_a
      if sif_a == nil then
        sif_a = (pcfg.sif_weight ~= false) and 1e-3 or 0
      end

      local kernel_sizes = pcfg.kernel_sizes or { 1, 3, 5 }
      local conv_pooling = pcfg.conv_pooling or 'max'
      local model_names = {}
      for _, m in ipairs(models) do
        model_names[#model_names + 1] = m.lang
      end

      local combined_vec, total_channels, pools_per_scale = compute_conv1d_features(
        models, words, max_words, sif_a,
        { kernel_sizes = kernel_sizes, conv_pooling = conv_pooling })

      if not combined_vec or #combined_vec == 0 then
        rspamd_logger.debugm(N, task, 'fasttext_embed: conv1d produced empty features; skip')
        cont(nil)
        return
      end

      local meta = {
        name = pcfg.name or 'fasttext_embed',
        type = 'fasttext_embed',
        output_mode = 'conv1d',
        channels = total_channels,
        n_scales = #kernel_sizes,
        pools_per_scale = pools_per_scale,
        dim = #combined_vec,
        weight = ctx.weight or 1.0,
        models = table.concat(model_names, '+'),
      }

      rspamd_logger.debugm(N, task,
        'fasttext_embed: conv1d k=%s pool=%s dim=%s (%s models, %s words)',
        table.concat(kernel_sizes, ','), conv_pooling,
        #combined_vec, #models, math.min(#words, max_words))
      cont(combined_vec, meta)
      return
    end

    local pooling = pcfg.pooling or 'mean_max'
    -- SIF weighting: enabled by default with a=1e-3
    local sif_a = pcfg.sif_a
    if sif_a == nil then
      sif_a = (pcfg.sif_weight ~= false) and 1e-3 or 0
    end
    local combined_vec = {}
    local model_names = {}
    local total_dim = 0

    for _, m in ipairs(models) do
      local vec = compute_pooled_vectors(m.model, words, pooling, sif_a)
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
