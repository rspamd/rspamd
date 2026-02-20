--[[
FastText embedding provider for neural feature fusion.
Loads a FastText model (supervised or unsupervised) and computes sentence
embeddings from message text. Supports per-language models for multilingual
deployments.

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

-- Detect primary language from the displayed text part
local function detect_language(task)
  local part = lua_mime.get_displayed_text_part(task)
  if part then
    local lang = part:get_language()
    if lang and lang ~= '' then
      return lang
    end
  end
  return nil
end

-- Select the appropriate model based on language
local function select_model(pcfg, language)
  -- Check per-language models first
  if language and pcfg.language_models then
    local lang_path = pcfg.language_models[language]
    if lang_path then
      local model = load_model(lang_path)
      if model then
        return model, lang_path
      end
    end
  end

  -- Fallback to default model
  if pcfg.model then
    local model = load_model(pcfg.model)
    if model then
      return model, pcfg.model
    end
  end

  return nil, nil
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

neural_common.register_provider('fasttext_embed', {
  collect_async = function(task, ctx, cont)
    local pcfg = ctx.config or {}

    if not rspamd_fasttext then
      rspamd_logger.debugm(N, task, 'fasttext_embed: rspamd_fasttext not available; skip')
      cont(nil)
      return
    end

    local language = detect_language(task)
    local model, model_path = select_model(pcfg, language)

    if not model then
      rspamd_logger.debugm(N, task, 'fasttext_embed: no model available; skip')
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

    local dim = model:get_dimension()
    rspamd_logger.debugm(N, task, 'fasttext_embed: computing %s-dim vector from %s words (lang=%s, model=%s)',
      dim, #words, language or 'unknown', model_path)

    local vec = model:get_sentence_vector(words)

    if not vec or #vec == 0 then
      rspamd_logger.debugm(N, task, 'fasttext_embed: empty vector; skip')
      cont(nil)
      return
    end

    local meta = {
      name = pcfg.name or 'fasttext_embed',
      type = 'fasttext_embed',
      dim = dim,
      weight = ctx.weight or 1.0,
      model = model_path,
      language = language,
    }

    rspamd_logger.debugm(N, task, 'fasttext_embed: produced %s-dim vector', #vec)
    cont(vec, meta)
  end,
})
