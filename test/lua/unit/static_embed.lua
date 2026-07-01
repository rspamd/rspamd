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

  -- Pack a float32 little-endian without FFI; all fixture values are
  -- exactly representable so the conversion is lossless
  local function f32_le(x)
    if x == 0 then
      return string.char(0, 0, 0, 0)
    end
    local sign = 0
    if x < 0 then
      sign = 1
      x = -x
    end
    local m, e = math.frexp(x) -- x = m * 2^e, m in [0.5, 1)
    local exp = e + 126        -- biased exponent of 1.f * 2^(e-1)
    local frac = math.floor((m * 2 - 1) * 2 ^ 23 + 0.5)
    return string.char(
      frac % 256,
      math.floor(frac / 256) % 256,
      math.floor(frac / 65536) + (exp % 2) * 128,
      sign * 128 + math.floor(exp / 2))
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
