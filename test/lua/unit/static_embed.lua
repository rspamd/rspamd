-- Static embedding model tests (WordPiece tokenizer + mean pooling).
-- Fixture files (tiny vocab/matrix/config, mimicking the model artifact
-- layout) are generated at runtime into a temporary directory.

context("Static embed model", function()
  local rspamd_util = require "rspamd_util"
  local rspamd_static_embed = require "rspamd_static_embed"

  local function write_file(path, content)
    local f = assert(io.open(path, 'wb'))
    f:write(content)
    f:close()
  end

  local function make_dir()
    local path = os.tmpname()
    os.remove(path)
    local ok, err = rspamd_util.mkdir(path)
    assert(ok, err)
    return path
  end

  -- Pack a float32 little-endian (string.pack semantics, works on any Lua
  -- version); all fixture values are exactly representable in float32
  local function f32_le(x)
    return rspamd_util.pack('<f', x)
  end

  -- Line i == token id i, no trailing newline (like the reference artifact)
  local vocab = table.concat({
    '[PAD]', -- 0
    '[UNK]', -- 1
    'hello', -- 2
    'world', -- 3
    'un', -- 4
    '##aff', -- 5
    '##able', -- 6
    ',', -- 7
    '中', -- 8
    '##ly', -- 9
  }, '\n')

  local config = [[{
    "dim": 4, "vocab_size": 10, "pooling": "mean", "unk_id": 1,
    "continuing_subword_prefix": "##",
    "normalizer": {"lowercase": true, "strip_accents": null,
                   "handle_chinese_chars": true, "clean_text": true},
    "matrix": "matrix.f32", "matrix_dtype": "float32"
  }]]

  -- Row i == {i, i/2, -i, i/4}; all values are exact in float32
  local function matrix_bytes()
    local chunks = {}
    for i = 0, 9 do
      chunks[#chunks + 1] = f32_le(i)
      chunks[#chunks + 1] = f32_le(i * 0.5)
      chunks[#chunks + 1] = f32_le(-i)
      chunks[#chunks + 1] = f32_le(i * 0.25)
    end
    return table.concat(chunks)
  end

  local function make_model_dir(cfg)
    local dir = make_dir()
    write_file(dir .. '/config.json', cfg or config)
    write_file(dir .. '/vocab.txt', vocab)
    write_file(dir .. '/matrix.f32', matrix_bytes())
    return dir
  end

  local good_dir = make_model_dir()
  local model, load_err = rspamd_static_embed.load(good_dir)

  test("Loads the fixture model", function()
    assert_not_nil(model, load_err)
    assert_equal(10, model:get_vocab_size())
    assert_equal(1, model:get_unk_id())
    assert_equal(4, model:get_dimension())
  end)

  local tokenize_cases = {
    { 'hello world', '2,3', 'plain words' },
    { 'unaffable', '4,5,6', 'subword split' },
    { 'worldly', '3,9', 'greedy longest match' },
    { 'Héllo, WORLD', '2,7,3', 'lowercase + strip accents + punctuation isolation' },
    { 'hello中world', '2,8,3', 'CJK char padding' },
    { 'hello zzz', '2,1', 'unknown word maps to unk' },
    { 'hel\0lo', '2', 'clean_text removes control chars' },
    { '', '', 'empty input' },
    { ' \t\n  ', '', 'whitespace-only input' },
  }

  for _, case in ipairs(tokenize_cases) do
    test("Tokenize: " .. case[3], function()
      assert_not_nil(model, load_err)
      local ids = model:tokenize(case[1])
      assert_equal(case[2], table.concat(ids, ','))
    end)
  end

  test("Sentence vector is the mean of subword rows", function()
    assert_not_nil(model, load_err)

    -- 'unaffable' -> ids {4, 5, 6}; mean of rows == {5, 2.5, -5, 1.25}
    local vec, ntokens = model:get_sentence_vector({ 'unaffable' })
    assert_equal(3, ntokens)
    local expected = { 5.0, 2.5, -5.0, 1.25 }
    for d = 1, 4 do
      assert_lte(math.abs(vec[d] - expected[d]), 1e-4)
    end
  end)

  test("Word list and joined text produce the same vector", function()
    assert_not_nil(model, load_err)

    local vec_words, n_words = model:get_sentence_vector({ 'hello', 'unaffable', 'worldly' })
    local vec_text, n_text = model:get_sentence_vector('hello unaffable worldly')
    assert_equal(n_words, n_text)
    for d = 1, 4 do
      assert_equal(vec_words[d], vec_text[d])
    end
  end)

  test("Empty input produces a zero vector", function()
    assert_not_nil(model, load_err)

    local vec, ntokens = model:get_sentence_vector({})
    assert_equal(0, ntokens)
    assert_equal(4, #vec)
    for d = 1, 4 do
      assert_equal(0.0, vec[d])
    end
  end)

  test("Rejects an unsupported model type (BPE)", function()
    local dir = make_model_dir()
    write_file(dir .. '/tokenizer.json',
      [[{"model": {"type": "BPE", "unk_token": "[UNK]"}}]])
    local bad, err = rspamd_static_embed.load(dir)
    assert_nil(bad)
    assert_match('BPE', err)
  end)

  test("Rejects a vocab_size mismatch", function()
    local dir = make_model_dir((config:gsub('"vocab_size": 10', '"vocab_size": 42')))
    local bad, err = rspamd_static_embed.load(dir)
    assert_nil(bad)
    assert_match('mismatch', err)
  end)

  test("Rejects unsupported pooling", function()
    local dir = make_model_dir((config:gsub('"pooling": "mean"', '"pooling": "max"')))
    local bad, err = rspamd_static_embed.load(dir)
    assert_nil(bad)
    assert_match('pooling', err)
  end)

  test("Rejects a matrix size mismatch", function()
    local dir = make_model_dir()
    write_file(dir .. '/matrix.f32', matrix_bytes():sub(1, 64))
    local bad, err = rspamd_static_embed.load(dir)
    assert_nil(bad)
    assert_match('matrix size mismatch', err)
  end)

  test("Loads a HF tokenizer.json spec", function()
    local dir = make_model_dir()
    write_file(dir .. '/tokenizer.json', [[{
      "normalizer": {"type": "BertNormalizer", "clean_text": true,
                     "handle_chinese_chars": true, "strip_accents": null,
                     "lowercase": true},
      "pre_tokenizer": {"type": "BertPreTokenizer"},
      "model": {"type": "WordPiece", "unk_token": "[UNK]",
                "continuing_subword_prefix": "##",
                "max_input_chars_per_word": 100}
    }]])
    local hf_model, err = rspamd_static_embed.load(dir)
    assert_not_nil(hf_model, err)
    assert_equal('2,7,3', table.concat(hf_model:tokenize('Héllo, WORLD'), ','))
  end)

  test("Token vectors align 1:1 with tokenize ids", function()
    assert_not_nil(model, load_err)

    local text = 'hello unaffable worldly'
    local ids = model:tokenize(text)
    local vecs, ntokens = model:get_token_vectors(text)
    assert_equal(#ids, ntokens)
    assert_equal(#ids, #vecs)
    -- row for id == {id, id/2, -id, id/4} in the fixture matrix
    for i = 1, ntokens do
      local id = ids[i]
      local expected = { id, id * 0.5, -id, id * 0.25 }
      for d = 1, 4 do
        assert_equal(expected[d], vecs[i][d])
      end
    end
  end)

  local pooled_samples = {
    { { 'unaffable' }, 'subwords' },
    { { 'hello', 'unaffable', 'worldly' }, 'several words' },
    { { 'zzz', 'qqq', 'hello' }, 'unk-heavy input' },
    { { 'zzz', '中', 'Héllo,' }, 'mixed unk/cjk/punct' },
  }

  for _, s in ipairs(pooled_samples) do
    test("Mean of token vectors equals sentence vector: " .. s[2], function()
      assert_not_nil(model, load_err)

      local vecs, n = model:get_token_vectors(s[1])
      local pooled, n_pooled = model:get_sentence_vector(s[1])
      assert_equal(n_pooled, n)
      assert_gte(n, 1)
      for d = 1, 4 do
        local sum = 0.0
        for i = 1, n do
          sum = sum + vecs[i][d]
        end
        assert_lte(math.abs(sum / n - pooled[d]), 1e-5)
      end
    end)
  end

  test("Token vectors: word list and joined text are equal", function()
    assert_not_nil(model, load_err)

    local words = { 'hello', 'unaffable', 'worldly' }
    local v_words, n_words = model:get_token_vectors(words)
    local v_text, n_text = model:get_token_vectors(table.concat(words, ' '))
    assert_equal(n_words, n_text)
    for i = 1, n_words do
      for d = 1, 4 do
        assert_equal(v_words[i][d], v_text[i][d])
      end
    end
  end)

  test("Token vectors: max_tokens truncates after tokenization", function()
    assert_not_nil(model, load_err)

    local text = 'hello unaffable worldly' -- 6 subword tokens
    local full, n_full = model:get_token_vectors(text)
    assert_equal(6, n_full)

    local trunc, n_trunc = model:get_token_vectors(text, { max_tokens = 2 })
    assert_equal(2, n_trunc)
    assert_equal(2, #trunc)
    for i = 1, 2 do
      for d = 1, 4 do
        assert_equal(full[i][d], trunc[i][d])
      end
    end

    -- max_tokens larger than the sequence is a no-op
    local _, n_same = model:get_token_vectors(text, { max_tokens = 100 })
    assert_equal(6, n_same)
  end)

  test("Token vectors: raw packing matches the table form", function()
    assert_not_nil(model, load_err)

    local text = 'hello unaffable worldly'
    local vecs, n = model:get_token_vectors(text)
    local packed, n_raw = model:get_token_vectors(text, { raw = true })
    assert_equal(n, n_raw)
    assert_equal(n * 4 * 4, packed:len())

    -- All fixture values are float32-exact, so packing the table form as
    -- little-endian float32 must reproduce the raw bytes exactly
    local chunks = {}
    for i = 1, n do
      for d = 1, 4 do
        chunks[#chunks + 1] = f32_le(vecs[i][d])
      end
    end
    assert_equal(table.concat(chunks), packed:str())

    -- Cross-check via rspamd_util.unpack (string.unpack semantics, works
    -- with rspamd_text directly and on any Lua version)
    local off = 1
    for i = 1, n do
      for d = 1, 4 do
        local v
        v, off = rspamd_util.unpack('<f', packed, off)
        assert_lte(math.abs(v - vecs[i][d]), 1e-6)
      end
    end
  end)

  test("Token vectors: empty input", function()
    assert_not_nil(model, load_err)

    local vecs, n = model:get_token_vectors({})
    assert_equal(0, n)
    assert_equal(0, #vecs)

    local packed, n_raw = model:get_token_vectors({}, { raw = true })
    assert_equal(0, n_raw)
    assert_equal(0, packed:len())
  end)

  test("Token vectors: invalid opts raise errors", function()
    assert_not_nil(model, load_err)

    assert_error(function()
      model:get_token_vectors('hello', 'not a table')
    end)
    assert_error(function()
      model:get_token_vectors('hello', { max_tokens = 'x' })
    end)
    assert_error(function()
      model:get_token_vectors('hello', { max_tokens = 0 })
    end)
    assert_error(function()
      model:get_token_vectors('hello', { max_tokens = 1.5 })
    end)
    assert_error(function()
      model:get_token_vectors('hello', { raw = 1 })
    end)
  end)

  test("Provider helper caches loaded models", function()
    local se = require "plugins/neural/providers/static_embed"
    local m1, err = se.load_model(good_dir)
    assert_not_nil(m1, err)
    local m2 = se.load_model(good_dir)
    assert_equal(m1, m2)

    local bad_dir = make_dir()
    local bad, err1 = se.load_model(bad_dir)
    assert_nil(bad)
    -- The failure must be cached with the same message
    local bad2, err2 = se.load_model(bad_dir)
    assert_nil(bad2)
    assert_equal(err1, err2)
  end)
end)
