context("Rspamd util for lua - check generic functions", function()
    local util  = require 'rspamd_util'


    local cases = {
        {
            input = "test1",
            result = false,
            mixed_script = false,
            range_start = 0x0000,
            range_end = 0x017f
        },
        {
            input = "test test xxx",
            result = false,
            mixed_script = false,
            range_start = 0x0000,
            range_end = 0x017f
        },
        {
            input = "АбЫрвАлг",
            result = true,
            mixed_script = false,
            range_start = 0x0000,
            range_end = 0x017f
        },
        {
            input = "АбЫрвАлг example",
            result = true,
            mixed_script = true,
            range_start = 0x0000,
            range_end = 0x017f
        },
        {
            input = "example ąłśćżłóę",
            result = false,
            mixed_script = false,
            range_start = 0x0000,
            range_end = 0x017f
        },
        {
            input = "ąłśćżłóę АбЫрвАлг",
            result = true,
            mixed_script = true,
            range_start = 0x0000,
            range_end = 0x017f
        },
    }

    for i,c in ipairs(cases) do
        test("is_utf_outside_range, test case #" .. i, function()
          local actual = util.is_utf_outside_range(c.input, c.range_start, c.range_end)

          assert_equal(c.result, actual)
        end)
    end

    test("is_utf_outside_range, check cache", function ()
        cache_size = 20
        for i = 1,cache_size do
            local res = util.is_utf_outside_range("a", 0x0000, 0x0000+i)
        end
    end)

    test("is_utf_outside_range, check empty string", function ()
        assert_error(util.is_utf_outside_range)
    end)

    test("get_string_stats, test case", function()
        local res = util.get_string_stats("this is test 99")
        assert_equal(res["letters"], 10)
        assert_equal(res["digits"], 2)
    end)

    -- Tests for get_text_quality
    test("get_text_quality, empty string", function()
        local res = util.get_text_quality("")
        assert_equal(res.total, 0)
        assert_equal(res.letters, 0)
        assert_equal(res.words, 0)
    end)

    test("get_text_quality, simple ASCII text", function()
        local res = util.get_text_quality("Hello World")
        assert_equal(res.total, 11)
        assert_equal(res.letters, 10)
        assert_equal(res.spaces, 1)
        assert_equal(res.words, 2)
        assert_equal(res.word_chars, 10)
        assert_equal(res.uppercase, 2)  -- H, W
        assert_equal(res.lowercase, 8)
        assert_equal(res.ascii_chars, 11)
        assert_equal(res.non_ascii_chars, 0)
        assert_equal(res.latin_vowels, 3)  -- e, o, o
        assert_equal(res.latin_consonants, 7)  -- H, l, l, W, r, l, d
    end)

    test("get_text_quality, Russian (Cyrillic) text", function()
        local res = util.get_text_quality("Привет мир")
        assert_equal(res.letters, 9)
        assert_equal(res.spaces, 1)
        assert_equal(res.words, 2)
        assert_equal(res.non_ascii_chars, 9)  -- all Cyrillic letters
        assert_equal(res.ascii_chars, 1)  -- space
        assert_equal(res.latin_vowels, 0)
        assert_equal(res.latin_consonants, 0)
        assert_equal(res.script_transitions, 0)  -- all same script
    end)

    test("get_text_quality, mixed Latin and Cyrillic (script transitions)", function()
        local res = util.get_text_quality("Hello Привет")
        assert_equal(res.letters, 11)
        assert_equal(res.words, 2)
        assert_true(res.script_transitions > 0)  -- at least one transition
        assert_true(res.latin_vowels > 0)
        assert_true(res.latin_consonants > 0)
    end)

    test("get_text_quality, digits only", function()
        local res = util.get_text_quality("12345")
        assert_equal(res.total, 5)
        assert_equal(res.digits, 5)
        assert_equal(res.letters, 0)
        assert_equal(res.words, 0)
        assert_equal(res.printable, 5)
    end)

    test("get_text_quality, punctuation", function()
        local res = util.get_text_quality("Hello, World!")
        assert_equal(res.punctuation, 2)  -- comma and exclamation
        assert_equal(res.words, 2)
    end)

    test("get_text_quality, double spaces", function()
        local res = util.get_text_quality("Hello  World   Test")
        assert_equal(res.double_spaces, 3)  -- 2 in "  " + 1 extra in "   "
        assert_equal(res.spaces, 5)
    end)

    test("get_text_quality, uppercase text", function()
        local res = util.get_text_quality("HELLO WORLD")
        assert_equal(res.uppercase, 10)
        assert_equal(res.lowercase, 0)
    end)

    test("get_text_quality, lowercase text", function()
        local res = util.get_text_quality("hello world")
        assert_equal(res.uppercase, 0)
        assert_equal(res.lowercase, 10)
    end)

    test("get_text_quality, single characters (no words)", function()
        local res = util.get_text_quality("A B C D E")
        assert_equal(res.letters, 5)
        assert_equal(res.words, 0)  -- single letters don't count as words
        assert_equal(res.word_chars, 0)
    end)

    test("get_text_quality, vowels vs consonants", function()
        local res = util.get_text_quality("aeiou")
        assert_equal(res.latin_vowels, 5)
        assert_equal(res.latin_consonants, 0)

        res = util.get_text_quality("bcdfg")
        assert_equal(res.latin_vowels, 0)
        assert_equal(res.latin_consonants, 5)
    end)

    test("get_text_quality, emojis", function()
        local res = util.get_text_quality("Hello 👋 World")
        assert_equal(res.emojis, 1)
        assert_equal(res.words, 2)  -- Hello and World
    end)

    test("get_text_quality, mixed content", function()
        local res = util.get_text_quality("Test123! Hello...")
        assert_equal(res.letters, 9)  -- Test + Hello
        assert_equal(res.digits, 3)
        assert_equal(res.punctuation, 4)  -- ! and ...
        assert_equal(res.words, 2)  -- Test and Hello
    end)

    for i,c in ipairs(cases) do
        test("is_utf_mixed_script, test case #" .. i, function()
          local actual = util.is_utf_mixed_script(c.input)

          assert_equal(c.mixed_script, actual)
        end)
    end

    test("is_utf_mixed_script, invalid utf str should return errror", function()
        assert_error(util.is_utf_mixed_script,'\200\213\202')
    end)

    test("is_utf_mixed_script, empty str should return errror", function()
        assert_error(util.is_utf_mixed_script,'\200\213\202')
    end)
end)

context("Rspamd string utility", function()
    local ok, ffi = pcall(require, "ffi")
    if not ok then
      ffi = require("cffi")
    end

    ffi.cdef[[
char ** rspamd_string_len_split (const char *in, size_t len,
		const char *spill, int max_elts, void *pool);
		void g_strfreev (char **str_array);
]]
    local NULL = ffi.new 'void*'
    local cases = {
        {'', ';,', {}},
        {'', '', {}},
        {'a', ';,', {'a'}},
        {'a', '', {'a'}},
        {'a;b', ';', {'a', 'b'}},
        {'a;;b', ';', {'a', 'b'}},
        {';a;;b;', ';', {'a', 'b'}},
        {'ab', ';', {'ab'}},
        {'a,;b', ',', {'a', ';b'}},
        {'a,;b', ';,', {'a', 'b'}},
        {',a,;b', ';,', {'a', 'b'}},
        {',,;', ';,', {}},
        {',,;a', ';,', {'a'}},
        {'a,,;', ';,', {'a'}},
    }

    for i,case in ipairs(cases) do
        test("rspamd_string_len_split: case " .. tostring(i), function()
            local ret = ffi.C.rspamd_string_len_split(case[1], #case[1],
                case[2], -1, NULL)
            local actual = {}

            while ret[#actual] ~= NULL do
                actual[#actual + 1] = ffi.string(ret[#actual])
            end

            assert_rspamd_table_eq({
                expect = case[3],
                actual = actual
            })

            ffi.C.g_strfreev(ret)
        end)
    end
end)