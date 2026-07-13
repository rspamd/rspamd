-- Always-firing atomic symbols used as inputs for dynamic composites.
local atoms = { 'DYN_BASE_A', 'DYN_BASE_B', 'DYN_BASE_C' }
for _, name in ipairs(atoms) do
  rspamd_config:register_symbol({
    name = name,
    score = 0.1,
    callback = function()
      return true, 'fires always'
    end
  })
end
