-- The minimal functional configs do not include rules/rspamd.lua, so the
-- controller webui paths (e.g. plugins/fuzzy/*) are not registered by
-- default; load the controller plugin routes explicitly
dofile(rspamd_paths['RULESDIR'] .. '/controller/init.lua')
