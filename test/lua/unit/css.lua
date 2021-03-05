context("CSS parsing tests", function()
  local ffi = require("ffi")
  local rspamd_mempool = require "rspamd_mempool"
  local pool = rspamd_mempool.create()
  ffi.cdef[[
const char *rspamd_css_unescape (void *pool,
            const char *begin,
            size_t len,
            size_t *olen);
void* rspamd_css_parse_style (void *pool,
            const char *begin,
            size_t len, void *err);
]]

  local cases = {
    {'#\\31 a2b3c {', '#1a2b3c {'}
  }

  for _,t in ipairs(cases) do
    test("Unescape " .. t[1], function()
      local olen = ffi.new('size_t[1]')
      local escaped = ffi.C.rspamd_css_unescape(pool:topointer(), t[1], #t[1], olen)
      escaped = ffi.string(escaped, tonumber(olen[0]))
      assert_equal(escaped, t[2], escaped .. " not equal " .. t[2])
    end)
  end

  local cases = {[[
p {
  color: red;
  text-align: center;
}
]],
[[
.center {
  text-align: center;
  color: red;
}]],
[[
/* This is a single-line comment */
/* This is
a multi-line
comment */

p {
  color: red;
}
]],
[[
p:first-child {
  color: blue;
}
a[target=_blank] #id{
  background-color: yellow;
}
* {
  box-sizing: border-box;
}

body {
  margin: 0;
}

/* Style the header */
.header {
  background-color: #f1f1f1;
  padding: 20px;
  text-align: center;
}

/* Style the top navigation bar */
.topnav {
  overflow: hidden;
  background-color: #333;
}

/* Style the topnav links */
.topnav a{
  float: left;
  display: block;
  color: #f2f2f2;
  text-align: center;
  padding: 14px 16px;
  text-decoration: none;
}

/* Clear floats after the columns */
.row:after{
  content: "";
  display: table;
  clear: both;
}

/* Responsive layout - makes the three columns stack on top of each other instead of next to each other */
@media screen and (max-width: 600px) {
  .column.side, .column.middle {
    width: 100%;
  }
}
]],
[[
/* Colors */
* { color: hsl(0, 100%, 50%) !important }   /* red */
* { color: hsl(120, 100%, 50%) important } /* lime */
* { color: hsl(120, 100%, 25%) } /* dark green */
* { color: hsl(120, 100%, 75%) } /* light green */
* { color: hsl(120, 75%, 75%) }  /* pastel green, and so on */
em { color: #f00 }              /* #rgb */
em { color: #ff0000 }           /* #rrggbb */
em { color: rgb(255,0,0) }
em { color: rgb(100%, 0%, 0%) }
body {color: black; background: white }
h1 { color: maroon }
h2 { color: olive }
em { color: rgb(255,0,0) }       /* integer range 0 - 255 */
em { color: rgb(300,0,0) }       /* clipped to rgb(255,0,0) */
em { color: rgb(255,-10,0) }     /* clipped to rgb(255,0,0) */
em { color: rgb(110%, 0%, 0%) }  /* clipped to rgb(100%,0%,0%) */
em { color: rgb(255,0,0) }      /* integer range 0 - 255 */
em { color: rgba(255,0,0,1)     /* the same, with explicit opacity of 1 */
em { color: rgb(100%,0%,0%) }   /* float range 0.0% - 100.0% */
em { color: rgba(100%,0%,0%,1) } /* the same, with explicit opacity of 1 */
p { color: rgba(0,0,255,0.5) }        /* semi-transparent solid blue */
p { color: rgba(100%, 50%, 0%, 0.1) } /* very transparent solid orange */
]]
  }
  local NULL = ffi.new 'void*'
  for i,t in ipairs(cases) do
    test("Parse css sample " .. i, function()
      local escaped = ffi.C.rspamd_css_parse_style(pool:topointer(), t, #t, NULL)
      --assert_not_nil(escaped)
    end)
  end
end)