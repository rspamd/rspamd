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
    local ffi = require 'ffi'

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