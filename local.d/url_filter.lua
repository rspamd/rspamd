--[[
URL Filter Configuration
This is a configuration template for the URL filter library.

The URL filter runs during parsing (before URL objects are created).
It provides fast validation to reject obvious garbage URLs.

Most users don't need to configure this - the defaults work well.
]]--

-- Enable/disable the filter
-- enabled = true;

-- Built-in filter configuration
-- builtin_filters = {
--   # Reject URLs with extremely long user fields
--   oversized_user = {
--     enabled = true;
--     max_length = 512;  # Absolute limit for user field length
--   };
--
--   # Reject URLs with invalid UTF-8
--   basic_unicode = {
--     enabled = true;
--     reject_invalid_utf8 = true;
--   };
--
--   # Reject obvious garbage patterns
--   garbage_pattern = {
--     enabled = true;
--     max_at_signs = 20;  # URLs with >20 @ signs are garbage
--   };
-- };

-- ADVANCED: Custom filters
-- You can add your own filters that run during URL parsing.
-- Filter function signature: function(url_text, url_obj, flags)
-- Return: "accept", "suspicious", or "reject"
--
-- Example:
-- custom_filters = {
--   my_domain_filter = function(url_text, url_obj, flags)
--     if url_obj then
--       local host = url_obj:get_host()
--       if host == "blocked-domain.com" then
--         return "reject"  -- Don't create URL object
--       end
--     end
--     return "accept"
--   end;
-- };
