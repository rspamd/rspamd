-- URL parser tests

context("URL check functions", function()
  local mpool = require("rspamd_mempool")
  local ffi = require("ffi")
  
  ffi.cdef[[
  struct rspamd_url {
  char *string;
  int protocol;

  int ip_family;

  char *user;
  char *password;
  char *host;
  char *port;
  char *data;
  char *query;
  char *fragment;
  char *post;
  char *surbl;

  struct rspamd_url *phished_url;

  unsigned int protocollen;
  unsigned int userlen;
  unsigned int passwordlen;
  unsigned int hostlen;
  unsigned int portlen;
  unsigned int datalen;
  unsigned int querylen;
  unsigned int fragmentlen;
  unsigned int surbllen;

  /* Flags */
  int ipv6;  /* URI contains IPv6 host */
  int form;  /* URI originated from form */
  int is_phished; /* URI maybe phishing */
  };
  struct rspamd_url* rspamd_url_get_next (void *pool,
    const char *start, char const **pos);
  void * rspamd_mempool_new (unsigned long size);
  ]]
  
  test("Extract urls from text", function()
    local pool = ffi.C.rspamd_mempool_new(4096)
    local cases = {
      {"test.com text", {"test.com", nil}},
      {"mailto:A.User@example.com text", {"example.com", "A.User"}},
      {"http://Тест.Рф:18 text", {"тест.рф", nil}},
      {"http://user:password@тест2.РФ:18 text", {"тест2.рф", "user"}},
    }
    
    for _,c in ipairs(cases) do
      local res = ffi.C.rspamd_url_get_next(pool, c[1], nil)
      
      assert_not_nil(res, "cannot parse " .. c[1])
      assert_equal(c[2][1], ffi.string(res.host, res.hostlen))
      
      if c[2][2] then
        assert_equal(c[2][2], ffi.string(res.user, res.userlen))
      end
    end
  end)
end)