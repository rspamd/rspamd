-- Copyright 2015-2020 Mitchell. See LICENSE.
-- Sponsored by the Library of the University of Antwerp.
-- Contributions from Ana Balan.
-- Lupa templating engine.

--[[ This comment is for LuaDoc.
---
-- Lupa is a Jinja2 template engine implementation written in Lua and supports
-- Lua syntax within tags and variables.
module('lupa')]]
local M = {}

local lpeg = require('lpeg')
lpeg.locale(lpeg)
local space, newline = lpeg.space, lpeg.P('\r')^-1 * '\n'
local P, S, V = lpeg.P, lpeg.S, lpeg.V
local C, Cc, Cg, Cp, Ct = lpeg.C, lpeg.Cc, lpeg.Cg, lpeg.Cp, lpeg.Ct

---
-- Lupa's expression filters.
-- @class table
-- @name filters
M.filters = {}

---
-- Lupa's value tests.
-- @class table
-- @name tests
M.tests = {}

---
-- Lupa's template loaders.
-- @class table
-- @name loaders
M.loaders = {}

-- Lua version compatibility.
if _VERSION == 'Lua 5.1' then
  function load(ld, source, mode, env)
    local f, err = loadstring(ld)
    if f and env then return setfenv(f, env) end
    return f, err
  end
  table.unpack = unpack
end

local newline_sequence, keep_trailing_newline, autoescape = '\n', false, false
local loader

-- Creates and returns a token pattern with token name *name* and pattern
-- *patt*.
-- The returned pattern captures three values: the token's position and name,
-- and either a string value or table of capture values.
-- Tokens are used to construct an Abstract Syntax Tree (AST) for a template.
-- @param name The name of the token.
-- @param patt The pattern to match. It must contain only one capture: either a
--   string or table of captures.
-- @see evaluate
local function token(name, patt) return Cp() * Cc(name) * patt end

-- Returns an LPeg pattern that immediately raises an error with message
-- *errmsg* for invalid syntax when parsing a template.
-- @param errmsg The error message to raise an error with.
local function lpeg_error(errmsg)
  return P(function(input, index)
    input = input:sub(1, index)
    local _, line_num = input:gsub('\n', '')
    local col_num = #input:match('[^\n]*$')
    error(string.format('Parse Error in file "%s" on line %d, column %d: %s',
                        M._FILENAME, line_num + 1, col_num, errmsg), 0)
  end)
end

---
-- Configures the basic delimiters and options for templates.
-- This function then regenerates the grammar for parsing templates.
-- Note: this function cannot be used iteratively to configure Lupa options.
-- Any options not provided are reset to their default values.
-- @param ts The tag start delimiter. The default value is '{%'.
-- @param te The tag end delimiter. The default value is '%}'.
-- @param vs The variable start delimiter. The default value is '{{'.
-- @param ve The variable end delimiter. The default value is '}}'.
-- @param cs The comment start delimiter. The default value is '{#'.
-- @param ce The comment end delimiter. The default value is '#}'.
-- @param options Optional set of options for templates:
--
--   * `trim_blocks`: Trim the first newline after blocks.
--   * `lstrip_blocks`: Strip line-leading whitespace in front of tags.
--   * `newline_sequence`: The end-of-line character to use.
--   * `keep_trailing_newline`: Whether or not to keep a newline at the end of
--     a template.
--   * `autoescape`: Whether or not to autoescape HTML entities. May be a
--     function that accepts the template's filename as an argument and returns
--     a boolean.
--   * `loader`: Function that receives a template name to load and returns the
--     path to that template.
-- @name configure
function M.configure(ts, te, vs, ve, cs, ce, options)
  if type(ts) == 'table' then options, ts = ts, nil end
  if not ts then ts = '{%' end
  if not te then te = '%}' end
  if not vs then vs = '{{' end
  if not ve then ve = '}}' end
  if not cs then cs = '{#' end
  if not ce then ce = '#}' end

  -- Tokens for whitespace control.
  local lstrip = token('lstrip', C('-')) + '+' -- '+' is handled by grammar
  local rstrip = token('rstrip', -(P(te) + ve + ce) * C('-'))

  -- Configure delimiters, including whitespace control.
  local tag_start = P(ts) * lstrip^-1 * space^0
  local tag_end = space^0 * rstrip^-1 * P(te)
  local variable_start = P(vs) * lstrip^-1 * space^0
  local variable_end = space^0 * rstrip^-1 * P(ve)
  local comment_start = P(cs) * lstrip^-1 * space^0
  local comment_end = space^0 * rstrip^-1 * P(ce)
  if options and options.trim_blocks then
    -- Consider whitespace, including a newline, immediately following a tag as
    -- part of that tag so it is not captured as plain text. Basically, strip
    -- the trailing newline from tags.
    tag_end = tag_end * S(' \t')^0 * newline^-1
    comment_end = comment_end * S(' \t')^0 * newline^-1
  end

  -- Error messages.
  local variable_end_error = lpeg_error('"'..ve..'" expected')
  local comment_end_error = lpeg_error('"'..ce..'" expected')
  local tag_end_error = lpeg_error('"'..te..'" expected')
  local endraw_error = lpeg_error('additional tag or "'..ts..' endraw '..te..
                                  '" expected')
  local expr_error = lpeg_error('expression expected')
  local endblock_error = lpeg_error('additional tag or "'..ts..' endblock '..
                                    te..'" expected')
  local endfor_error = lpeg_error('additional tag or "'..ts..' endfor '..te..
                                  '" expected')
  local endif_error = lpeg_error('additional tag or "'..ts..' endif '..te..
                                 '" expected')
  local endmacro_error = lpeg_error('additional tag or "'..ts..' endmacro '..
                                    te..'" expected')
  local endcall_error = lpeg_error('additional tag or "'..ts..' endcall '..te..
                                   '" expected')
  local endfilter_error = lpeg_error('additional tag or "'..ts..' endfilter '..
                                     te..'" expected')
  local tag_error = lpeg_error('unknown or unexpected tag')
  local main_error = lpeg_error('unexpected character; text or tag expected')

  -- Grammar.
  M.grammar = Ct(P{
    -- Utility patterns used by tokens.
    entity_start = tag_start + variable_start + comment_start,
    any_text = (1 - V('entity_start'))^1,
    -- Allow '{{' by default in expression text since it is valid in Lua.
    expr_text = (1 - tag_end - tag_start - comment_start)^1,
    -- When `options.lstrip_blocks` is enabled, ignore leading whitespace
    -- immediately followed by a tag (as long as '+' is not present) so that
    -- whitespace not captured as plain text. Basically, strip leading spaces
    -- from tags.
    line_text = (1 - newline - V('entity_start'))^1,
    lstrip_entity_start = -P(vs) * (P(ts) + cs) * -P('+'),
    lstrip_space = S(' \t')^1 * #V('lstrip_entity_start'),
    text_lines = V('line_text') * (newline * -(S(' \t')^0 * V('lstrip_entity_start')) * V('line_text'))^0 * newline^-1 + newline,

    -- Plain text.
    text = (not options or not options.lstrip_blocks) and
           token('text', C(V('any_text'))) or
           V('lstrip_space') + token('text', C(V('text_lines'))),

    -- Variables: {{ expr }}.
    lua_table = '{' * ((1 - S('{}')) + V('lua_table'))^0 * '}',
    variable = variable_start *
               token('variable', C((V('lua_table') + (1 - variable_end))^0)) *
               (variable_end + variable_end_error),

    -- Filters: handled in variable evaluation.

    -- Tests: handled in control structure expression evaluation.

    -- Comments: {# comment #}.
    comment = comment_start * (1 - comment_end)^0 * (comment_end + comment_end_error),

    -- Whitespace control: handled in tag/variable/comment start/end.

    -- Escaping: {% raw %} body {% endraw %}.
    raw_block = tag_start * 'raw' * (tag_end + tag_end_error) *
                token('text', C((1 - (tag_start * 'endraw' * tag_end))^0)) *
                (tag_start * 'endraw' * tag_end + endraw_error),

    -- Note: line statements are not supported since this grammer cannot parse
    -- Lua itself.

    -- Template inheritence.
    -- {% block ... %} body {% endblock %}
    block_block = tag_start * 'block' * space^1 * token('block', Ct((Cg(V('expr_text'), 'expression') + expr_error) * (tag_end + tag_end_error) *
                  V('body')^-1)) *
                  (tag_start * 'endblock' * tag_end + endblock_error),
    -- {% extends ... %}
    extends_tag = tag_start * 'extends' * space^1 * token('extends', C(V('expr_text')) + expr_error) * (tag_end + tag_end_error),
    -- Super blocks are handled in variables.
    -- Note: named block end tags are not supported since keeping track of that
    -- state information is difficult.
    -- Note: block nesting and scope is not applicable since blocks always have
    -- access to scoped variables in this implementation.

    -- Control Structures.
    -- {% for expr %} body {% else %} body {% endfor %}
    for_block = tag_start * 'for' * space^1 * token('for', Ct((Cg(V('expr_text'), 'expression') + expr_error) * (tag_end + tag_end_error) *
                V('body')^-1 *
                Cg(Ct(tag_start * 'else' * tag_end *
                      V('body')^-1), 'else')^-1)) *
                (tag_start * 'endfor' * tag_end + endfor_error),
    -- {% if expr %} body {% elseif expr %} body {% else %} body {% endif %}
    if_block = tag_start * 'if' * space^1 * token('if', Ct((Cg(V('expr_text'), 'expression') + expr_error) * (tag_end + tag_end_error) *
               V('body')^-1 *
               Cg(Ct(Ct(tag_start * 'elseif' * space^1 * (Cg(V('expr_text'), 'expression') + expr_error) * (tag_end + tag_end_error) *
                       V('body')^-1)^1), 'elseif')^-1 *
               Cg(Ct(tag_start * 'else' * tag_end *
                       V('body')^-1), 'else')^-1)) *
               (tag_start * 'endif' * tag_end + endif_error),
    -- {% macro expr %} body {% endmacro %}
    macro_block = tag_start * 'macro' * space^1 * token('macro', Ct((Cg(V('expr_text'), 'expression') + expr_error) * (tag_end + tag_end_error) *
                  V('body')^-1)) *
                  (tag_start * 'endmacro' * tag_end + endmacro_error),
    -- {% call expr %} body {% endcall %}
    call_block = tag_start * 'call' * (space^1 + #P('(')) * token('call', Ct((Cg(V('expr_text'), 'expression') + expr_error) * (tag_end + tag_end_error) *
                  V('body')^-1)) *
                  (tag_start * 'endcall' * tag_end + endcall_error),
    -- {% filter expr %} body {% endfilter %}
    filter_block = tag_start * 'filter' * space^1 * token('filter', Ct((Cg(V('expr_text'), 'expression') + expr_error) * (tag_end + tag_end_error) *
                   V('body')^-1)) *
                   (tag_start * 'endfilter' * tag_end + endfilter_error),
    -- {% set ... %}
    set_tag = tag_start * 'set' * space^1 * token('set', C(V('expr_text')) + expr_error) * (tag_end + tag_end_error),
    -- {% include ... %}
    include_tag = tag_start * 'include' * space^1 * token('include', C(V('expr_text')) + expr_error) * (tag_end + tag_end_error),
    -- {% import ... %}
    import_tag = tag_start * 'import' * space^1 * token('import', C(V('expr_text')) + expr_error) * (tag_end + tag_end_error),

    -- Note: i18n is not supported since it is out of scope for this
    -- implementation.

    -- Expression statement: {% do ... %}.
    do_tag = tag_start * 'do' * space^1 * token('do', C(V('expr_text')) + expr_error) * (tag_end + tag_end_error),

    -- Note: loop controls are not supported since that would require jumping
    -- between "scopes" (e.g. from within an "if" block to outside that "if"
    -- block's parent "for" block when coming across a {% break %} tag).

    -- Note: with statement is not supported since it is out of scope for this
    -- implementation.

    -- Note: autoescape is not supported since it is out of scope for this
    -- implementation.

    -- Any valid blocks of text or tags.
    body = (V('text') + V('variable') + V('comment') + V('raw_block') +
            V('block_block') + V('extends_tag') + V('for_block') +
            V('if_block') + V('macro_block') + V('call_block') +
            V('filter_block') + V('set_tag') + V('include_tag') +
            V('import_tag') + V('do_tag'))^0,

    -- Main pattern.
    V('body') * (-1 + tag_start * tag_error + main_error),
  })

  -- Other options.
  if options and options.newline_sequence then
    assert(options.newline_sequence:find('^\r?\n$'),
           'options.newline_sequence must be "\r\n" or "\n"')
    newline_sequence = options.newline_sequence
  else
    newline_sequence = '\n'
  end
  if options and options.keep_trailing_newline then
    keep_trailing_newline = options.keep_trailing_newline
  else
    keep_trailing_newline = false
  end
  if options and options.autoescape then
    autoescape = options.autoescape
  else
    autoescape = false
  end
  if options and options.loader then
    assert(type(options.loader) == 'function',
           'options.loader must be a function that returns a filename')
    loader = options.loader
  else
    loader = M.loaders.filesystem()
  end
end

-- Wraps Lua's `assert()` in template environment *env* such that, when called
-- in conjunction with another Lua function that produces an error message (e.g.
-- `load()` and `pcall()`), that error message's context (source and line
-- number) is replaced by the template's context.
-- This results in Lua's error messages pointing to a template position rather
-- than this library's source code.
-- @param env The environment for the currently running template. It must have
--   a `_SOURCE` field with the template's source text and a `_POSITION` field
--   with the current position of expansion.
-- @param ... Arguments to Lua's `assert()`.
local function env_assert(env, ...)
  if not select(1, ...) then
    local input = env._LUPASOURCE:sub(1, env._LUPAPOSITION)
    local _, line_num = input:gsub('\n', '')
    local col_num = #input:match('[^\n]*$')
    local errmsg = select(2, ...)
    errmsg = errmsg:match(':%d+: (.*)$') or errmsg -- reformat if necessary
    error(string.format('Runtime Error in file "%s" on line %d, column %d: %s',
                        env._LUPAFILENAME, line_num + 1, col_num, errmsg), 0)
  end
  return ...
end

-- Returns a generator that returns the position and filter in a list of
-- filters, taking into account '|'s that may be within filter arguments.
-- @usage for pos, filter in each_filter('foo|join("|")|bar') do ... end
local function each_filter(s)
  local init = 1
  return function(s)
    local pos, filter, e = s:match('^%s*()([^|(]+%b()[^|]*)|?()', init)
    if not pos then pos, filter, e = s:match('()([^|]+)|?()', init) end
    init = e
    return pos, filter
  end, s
end

-- Evaluates template variable *expression* subject to template environment
-- *env*, applying any filters given in *expression*.
-- @param expression The string expression to evaluate.
-- @param env The environment to evaluate the expression in.
local function eval(expression, env)
  local expr, pos, filters = expression:match('^([^|]*)|?()(.-)$')
  -- Evaluate base expression.
  local f = env_assert(env, load('return '..expr, nil, nil, env))
  local result = select(2, env_assert(env, pcall(f)))
  -- Apply any filters.
  local results, multiple_results = nil, false
  local p = env._LUPAPOSITION + pos - 1 -- mark position at first filter
  for pos, filter in each_filter(filters) do
    env._LUPAPOSITION = p + pos - 1 -- update position for error messages
    local name, params = filter:match('^%s*([%w_]+)%(?(.-)%)?%s*$')
    f = M.filters[name]
    env_assert(env, f, 'unknown filter "'..name..'"')
    local args = env_assert(env, load('return {'..params..'}', nil, nil, env),
                            'invalid filter parameter(s) for "'..name..'"')()
    if not multiple_results then
      results = {select(2,
                        env_assert(env, pcall(f, result, table.unpack(args))))}
    else
      for i = 1, #results do table.insert(args, i, results[i]) end
      results = {select(2, env_assert(env, pcall(f, table.unpack(args))))}
    end
    result, multiple_results = results[1], #results > 1
  end
  if multiple_results then return table.unpack(results) end
  return result
end

local iterate

-- Iterates over *ast*, a collection of tokens from a portion of a template's
-- Abstract Syntax Tree (AST), evaluating any expressions in template
-- environment *env*, and returns a concatenation of the results.
-- @param ast A template's AST or portion of its AST (e.g. portion inside a
--   'for' control structure).
-- @param env Environment to evaluate any expressions in.
local function evaluate(ast, env)
  local chunks = {}
  local extends -- text of a parent template
  local rstrip -- flag for stripping leading whitespace of next token
  for i = 1, #ast, 3 do
    local pos, token, block = ast[i], ast[i + 1], ast[i + 2]
    env._LUPAPOSITION = pos
    if token == 'text' then
      chunks[#chunks + 1] = block
    elseif token == 'variable' then
      local value = eval(block, env)
      if autoescape then
        local escape = autoescape
        if type(autoescape) == 'function' then
          escape = autoescape(env._LUPAFILENAME) -- TODO: test
        end
        if escape and type(value) == 'string' then
          value = M.filters.escape(value)
        end
      end
      chunks[#chunks + 1] = value ~= nil and tostring(value) or ''
    elseif token == 'extends' then
      env_assert(env, not extends,
                 'cannot have multiple "extends" in the same scope')
      local file = eval(block, env) -- covers strings and variables
      extends = file
      env._LUPAEXTENDED = true -- used by parent templates
    elseif token == 'block' then
      local name = block.expression:match('^[%w_]+$')
      env_assert(env, name, 'invalid block name')
      -- Store the block for potential use by the parent template if this
      -- template is a child template, or for use by `self`.
      if not env._LUPABLOCKS then env._LUPABLOCKS = {} end
      if not env._LUPABLOCKS[name] then env._LUPABLOCKS[name] = {} end
      table.insert(env._LUPABLOCKS[name], 1, block)
      -- Handle the block properly.
      if not extends then
        if not env._LUPAEXTENDED then
          -- Evaluate the block normally.
          chunks[#chunks + 1] = evaluate(block, env)
        else
          -- A child template is overriding this parent's named block. Evaluate
          -- the child's block and use it instead of the parent's.
          local blocks = env._LUPABLOCKS[name]
          local super_env = setmetatable({super = function()
            -- Loop through the chain of defined blocks, evaluating from top to
            -- bottom, and return the bottom block. In each sub-block, the
            -- 'super' variable needs to point to the next-highest block's
            -- evaluated result.
            local super = evaluate(block, env) -- start with parent block
            local sub_env = setmetatable({super = function() return super end},
                                         {__index = env})
            for i = 1, #blocks - 1 do super = evaluate(blocks[i], sub_env) end
            return super
          end}, {__index = env})
          chunks[#chunks + 1] = evaluate(blocks[#blocks], super_env)
        end
      end
    elseif token == 'for' then
      local expr = block.expression
      local p = env._LUPAPOSITION -- mark position at beginning of expression
      -- Extract variable list and generator.
      local patt = '^([%w_,%s]+)%s+in%s+()(.+)%s+if%s+(.+)$'
      local var_list, pos, generator, if_expr = expr:match(patt)
      if not var_list then
        var_list, pos, generator = expr:match('^([%w_,%s]+)%s+in%s+()(.+)$')
      end
      env_assert(env, var_list and generator, 'invalid for expression')
      -- Store variable names in a list for loop assignment.
      local variables = {}
      for variable, pos in var_list:gmatch('([^,%s]+)()') do
        env._LUPAPOSITION = p + pos - 1 -- update position for error messages
        env_assert(env, variable:find('^[%a_]') and variable ~= 'loop',
                   'invalid variable name')
        variables[#variables + 1] = variable
      end
      -- Evaluate the generator and perform the iteration.
      env._LUPAPOSITION = p + pos - 1 -- update position to generator
      if not generator:find('|') then
        generator = env_assert(env, load('return '..generator, nil, nil, env))
      else
        local generator_expr = generator
        generator = function() return eval(generator_expr, env) end
      end
      local new_env = setmetatable({}, {__index = env})
      chunks[#chunks + 1] = iterate(generator, variables, if_expr, block,
                                    new_env, 1, ast[i + 4] == 'lstrip')
    elseif token == 'if' then
      if eval(block.expression, env) then
        chunks[#chunks + 1] = evaluate(block, env)
      else
        local evaluate_else = true
        local elseifs = block['elseif']
        if elseifs then
          for j = 1, #elseifs do
            if eval(elseifs[j].expression, env) then
              chunks[#chunks + 1] = evaluate(elseifs[j], env)
              evaluate_else = false
              break
            end
          end
        end
        if evaluate_else and block['else'] then
          chunks[#chunks + 1] = evaluate(block['else'], env)
        end
      end
    elseif token == 'macro' then
      -- Parse the macro's name and parameter list.
      local signature = block.expression
      local name, param_list = signature:match('^([%w_]+)(%b())')
      env_assert(env, name and param_list, 'invalid macro expression')
      param_list = param_list:sub(2, -2)
      local p = env._LUPAPOSITION + #name + 1 -- mark pos at beginning of args
      local params, defaults = {}, {}
      for param, pos, default in param_list:gmatch('([%w_]+)=?()([^,]*)') do
        params[#params + 1] = param
        if default ~= '' then
          env._LUPAPOSITION = p + pos - 1 -- update position for error messages
          local f = env_assert(env, load('return '..default))
          defaults[param] = select(2, env_assert(env, pcall(f)))
        end
      end
      -- Create the function associated with the macro such that when the
      -- function is called (from within {{ ... }}), the macro's body is
      -- evaluated subject to an environment where parameter names are variables
      -- whose values are the ones passed to the macro itself.
      env[name] = function(...)
        local new_env = setmetatable({}, {__index = function(_, k)
          if k == 'caller' and type(env[k]) ~= 'function' then return nil end
          return env[k]
        end})
        local args = {...}
        -- Assign the given parameter values.
        for i = 1, #args do
          if i > #params then break end
          new_env[params[i]] = args[i]
        end
        -- Clear all other unspecified parameter values or set them to their
        -- defined defaults.
        for i = #args + 1, #params do
          new_env[params[i]] = defaults[params[i]]
        end
        -- Store extra parameters in "varargs" variable.
        new_env.varargs = {}
        for i = #params + 1, #args do
          new_env.varargs[#new_env.varargs + 1] = args[i]
        end
        local chunk = evaluate(block, new_env)
        if ast[i + 4] == 'lstrip' then chunk = chunk:gsub('%s*$', '') end
        return chunk
      end
    elseif token == 'call' then
      -- Parse the call block's parameter list (if any) and determine the macro
      -- to call.
      local param_list = block.expression:match('^(%b())')
      local params = {}
      if param_list then
        for param in param_list:gmatch('[%w_]+') do
          params[#params + 1] = param
        end
      end
      local macro = block.expression:match('^%b()(.+)$') or block.expression
      -- Evaluate the given macro, subject to a "caller" function that returns
      -- the contents of this call block. Any arguments passed to the caller
      -- function are used as values of this parameters parsed earlier.
      local old_caller = M.env.caller -- save
      M.env.caller = function(...)
        local new_env = setmetatable({}, {__index = env})
        local args = {...}
        -- Assign the given parameter values (if any).
        for i = 1, #args do new_env[params[i]] = args[i] end
        local chunk = evaluate(block, new_env)
        if ast[i + 4] == 'lstrip' then chunk = chunk:gsub('%s*$', '') end
        return chunk
      end
      chunks[#chunks + 1] = eval(macro, env)
      M.env.caller = old_caller -- restore
    elseif token == 'filter' then
      local text = evaluate(block, env)
      local p = env._LUPAPOSITION -- mark position at beginning of expression
      for pos, filter in each_filter(block.expression) do
        env._LUPAPOSITION = p + pos - 1 -- update position for error messages
        local name, params = filter:match('^%s*([%w_]+)%(?(.-)%)?%s*$')
        local f = M.filters[name]
        env_assert(env, f, 'unknown filter "'..name..'"')
        local args = env_assert(env, load('return {'..params..'}'),
                                'invalid filter parameter(s) for "'..name..
                                '"')()
        text = select(2, env_assert(env, pcall(f, text, table.unpack(args))))
      end
      chunks[#chunks + 1] = text
    elseif token == 'set' then
      local var, expr = block:match('^([%a_][%w_]*)%s*=%s*(.+)$')
      env_assert(env, var and expr, 'invalid variable name or expression')
      env[var] = eval(expr, env)
    elseif token == 'do' then
      env_assert(env, pcall(env_assert(env, load(block, nil, nil, env))))
    elseif token == 'include' then
      -- Parse the include block for flags.
      local without_context = block:find('without%s+context%s*')
      local ignore_missing = block:find('ignore%s+missing%s*')
      block = block:gsub('witho?u?t?%s+context%s*', '')
                   :gsub('ignore%s+missing%s*', '')
      -- Evaluate the include expression in order to determine the file to
      -- include. If the result is a table, use the first file that exists.
      local file = eval(block, env) -- covers strings and variables
      if type(file) == 'table' then
        local files = file
        for i = 1, #files do
          file = loader(files[i], env)
          if file then break end
        end
        if type(file) == 'table' then file = nil end
      elseif type(file) == 'string' then
        file = loader(file, env)
      else
        error('"include" requires a string or table of files')
      end
      -- If the file exists, include it. Otherwise throw an error unless the
      -- "ignore missing" flag was given.
      env_assert(env, file or ignore_missing, 'no file(s) found to include')
      if file then
        chunks[#chunks + 1] = M.expand_file(file, not without_context and env or
                                                  M.env)
      end
    elseif token == 'import' then
      local file, global = block:match('^%s*(.+)%s+as%s+([%a][%w_]*)%s*')
      local new_env = setmetatable({}, {
        __index = block:find('with%s+context%s*$') and env or M.env
      })
      M.expand_file(eval(file or block, env), new_env)
      -- Copy any defined macros and variables over into the proper namespace.
      if global then env[global] = {} end
      local namespace = global and env[global] or env
      for k, v in pairs(new_env) do if not env[k] then namespace[k] = v end end
    elseif token == 'lstrip' and chunks[#chunks] then
      chunks[#chunks] = chunks[#chunks]:gsub('%s*$', '')
    elseif token == 'rstrip' then
      rstrip = true -- can only strip after determining the next chunk
    end
    if rstrip and token ~= 'rstrip' then
      chunks[#chunks] = chunks[#chunks]:gsub('^%s*', '')
      rstrip = false
    end
  end
  return not extends and table.concat(chunks) or M.expand_file(extends, env)
end

local pairs_gen, ipairs_gen = pairs({}), ipairs({})

-- Iterates over the generator *generator* subject to string "if" expression
-- *if_expr*, assigns that generator's returned values to the variable names
-- listed in *variables* within template environment *env*, evaluates any
-- expressions in *block* (a portion of a template's AST), and returns a
-- concatenation of the results.
-- @param generator Either a function that returns a generator function, or a
--   table to iterate over. In the latter case, `ipairs()` is used as the
--   generator function.
-- @param variables List of variable names to assign values returned by
--   *generator* to.
-- @param if_expr A conditional expression that when `false`, skips the current
--   loop item.
-- @param block The portion inside the 'for' structure of a template's AST to
--   iterate with.
-- @param env The environment iteration variables are defined in and where
--   expressions are evaluated in.
-- @param depth The current recursion depth. Recursion is performed by calling
--   `loop(t)` with a table to iterate over.
-- @param lstrip Whether or not the "endfor" block strips whitespace on the
--   left. When `true`, all blocks produced by iteration are left-stripped.
iterate = function(generator, variables, if_expr, block, env, depth, lstrip)
  local chunks = {}
  local orig_variables = {} -- used to store original loop variables' values
  for i = 1, #variables do orig_variables[variables[i]] = env[variables[i]] end
  local i, n = 1 -- used for loop variables
  local _, s, v -- state variables
  if type(generator) == 'function' then
    _, generator, s, v = env_assert(env, pcall(generator))
    -- In practice, a generator's state variable is normally unused and hidden.
    -- This is not the case for 'pairs()' and 'ipairs', though.
    if variables[1] ~= '_index' and generator ~= pairs_gen and
       generator ~= ipairs_gen then
      table.insert(variables, 1, '_index')
    end
  end
  if type(generator) == 'table' then
    n = #generator
    generator, s, v = ipairs(generator)
    -- "for x in y" translates to "for _, x in ipairs(y)"; hide _ state variable
    if variables[1] ~= '_index' then table.insert(variables, 1, '_index') end
  end
  if generator then
    local first_results -- for preventing infinite loop from invalid generator
    while true do
      local results = {generator(s, v)}
      if results[1] == nil then break end
      -- If the results from the generator look like results returned by a
      -- generator itself (function, state, initial variable), verify last two
      -- results are different. If they are the same, then the original
      -- generator is invalid and will loop infinitely.
      if first_results == nil then
        first_results = #results == 3 and type(results[1]) == 'function' and
                        results
      elseif first_results then
        env_assert(env, results[3] ~= first_results[3] or
                        results[2] ~= first_results[2],
                   'invalid generator (infinite loop)')
      end
      -- Assign context variables and evaluate the body of the loop.
      -- As long as the result (ignoring the _index variable) is not a single
      -- table and there is only one loop variable defined (again, ignoring
      -- _index variable), assignment occurs as normal in Lua. Otherwise,
      -- unpacking on the table is done (like assignment to ...).
      if not (type(results[2]) == 'table' and #results == 2 and
              #variables > 2) then
        for j = 1, #variables do env[variables[j]] = results[j] end
      else
        for j = 2, #variables do env[variables[j]] = results[2][j - 1] end
      end
      if not if_expr or eval(if_expr, env) then
        env.loop = setmetatable({
          index = i, index0 = i - 1,
          revindex = n and n - (i - 1), revindex0 = n and n - i,
          first = i == 1, last = i == n, length = n,
          cycle = function(...)
            return select((i - 1) % select('#', ...) + 1, ...)
          end,
          depth = depth, depth0 = depth - 1
        }, {__call = function(_, t)
          return iterate(t, variables, if_expr, block, env, depth + 1, lstrip)
        end})
        chunks[#chunks + 1] = evaluate(block, env)
        if lstrip then chunks[#chunks] = chunks[#chunks]:gsub('%s*$', '') end
        i = i + 1
      end
      -- Prepare for next iteration.
      v = results[1]
    end
  end
  if i == 1 and block['else'] then
    chunks[#chunks + 1] = evaluate(block['else'], env)
  end
  for i = 1, #variables do env[variables[i]] = orig_variables[variables[i]] end
  return table.concat(chunks)
end

-- Expands string template *template* from source *source*, subject to template
-- environment *env*, and returns the result.
-- @param template String template to expand.
-- @param env Environment for the given template.
-- @param source Filename or identifier the template comes from for error
--   messages and debugging.
local function expand(template, env, source)
  template = template:gsub('\r?\n', newline_sequence) -- normalize
  if not keep_trailing_newline then template = template:gsub('\r?\n$', '') end
  -- Set up environment.
  if not env then env = {} end
  if not getmetatable(env) then env = setmetatable(env, {__index = M.env}) end
  env.self = setmetatable({}, {__index = function(_, k)
    env_assert(env, env._LUPABLOCKS and env._LUPABLOCKS[k],
               'undefined block "'..k..'"')
    return function() return evaluate(env._LUPABLOCKS[k][1], env) end
  end})
  -- Set context variables and expand the template.
  env._LUPASOURCE, env._LUPAFILENAME = template, source
  M._FILENAME = source -- for lpeg errors only
  local ast = assert(lpeg.match(M.grammar, template), "internal error")
  local result = evaluate(ast, env)
  return result
end

---
-- Expands the string template *template*, subject to template environment
-- *env*, and returns the result.
-- @param template String template to expand.
-- @param env Optional environment for the given template.
-- @name expand
function M.expand(template, env) return expand(template, env, '<string>') end

---
-- Expands the template within file *filename*, subject to template environment
-- *env*, and returns the result.
-- @param filename Filename containing the template to expand.
-- @param env Optional environment for the template to expand.
-- @name expand_file
function M.expand_file(filename, env)
  filename = loader(filename, env) or filename
  local f = (not env or not env._LUPASOURCE) and assert(io.open(filename)) or
            env_assert(env, io.open(filename))
  local template = f:read('*a')
  f:close()
  return expand(template, env, filename)
end

---
-- Returns a loader for templates that uses the filesystem starting at directory
-- *directory*.
-- When looking up the template for a given filename, the loader considers the
-- following: if no template is being expanded, the loader assumes the given
-- filename is relative to *directory* and returns the full path; otherwise the
-- loader assumes the given filename is relative to the current template's
-- directory and returns the full path.
-- The returned path may be passed to `io.open()`.
-- @param directory Optional the template root directory. The default value is
--   ".", which is the current working directory.
-- @name loaders.filesystem
-- @see configure
function M.loaders.filesystem(directory)
  return function(filename, env)
    if not filename then return nil end
    local current_dir = env and env._LUPAFILENAME and
                        env._LUPAFILENAME:match('^(.+)[/\\]')
    if not filename:find('^/') and not filename:find('^%a:[/\\]') then
      filename = (current_dir or directory or '.')..'/'..filename
    end
    local f = io.open(filename)
    if not f then return nil end
    f:close()
    return filename
  end
end

-- Globally defined functions.

---
-- Returns a sequence of integers from *start* to *stop*, inclusive, in
-- increments of *step*.
-- The complete sequence is generated at once -- no generator is returned.
-- @param start Optional number to start at. The default value is `1`.
-- @param stop Number to stop at.
-- @param step Optional increment between sequence elements. The default value
--   is `1`.
-- @name _G.range
function range(start, stop, step)
  if not stop and not step then stop, start = start, 1 end
  if not step then step = 1 end
  local t = {}
  for i = start, stop, step do t[#t + 1] = i end
  return t
end

---
-- Returns an object that cycles through the given values by calls to its
-- `next()` function.
-- A `current` field contains the cycler's current value and a `reset()`
-- function resets the cycler to its beginning.
-- @param ... Values to cycle through.
-- @usage c = cycler(1, 2, 3)
-- @usage c:next(), c:next() --> 1, 2
-- @usage c:reset() --> c.current == 1
-- @name _G.cycler
function cycler(...)
  local c = {...}
  c.n, c.i, c.current = #c, 1, c[1]
  function c:next()
    local current = self.current
    self.i = self.i + 1
    if self.i > self.n then self.i = 1 end
    self.current = self[self.i]
    return current
  end
  function c:reset() self.i, self.current = 1, self[1] end
  return c
end

-- Create the default sandbox environment for templates.
local safe = {
  -- Lua globals.
  '_VERSION', 'ipairs', 'math', 'pairs', 'select', 'tonumber', 'tostring',
  'type', 'bit32', 'os.date', 'os.time', 'string', 'table', 'utf8',
  -- Lupa globals.
  'range', 'cycler'
}
local sandbox_env = setmetatable({}, {__index = M.tests})
for i = 1, #safe do
  local v = safe[i]
  if not v:find('%.') then
    sandbox_env[v] = _G[v]
  else
    local mod, func = v:match('^([^.]+)%.(.+)$')
    if not sandbox_env[mod] then sandbox_env[mod] = {} end
    sandbox_env[mod][func] = _G[mod][func]
  end
end
sandbox_env._G = sandbox_env

---
-- Resets Lupa's default delimiters, options, and environments to their
-- original default values.
-- @name reset
function M.reset()
  M.configure('{%', '%}', '{{', '}}', '{#', '#}')
  M.env = setmetatable({}, {__index = sandbox_env})
end
M.reset()

---
-- The default template environment.
-- @class table
-- @name env
local env

-- Lupa filters.

---
-- Returns the absolute value of number *n*.
-- @param n The number to compute the absolute value of.
-- @name filters.abs
M.filters.abs = math.abs

-- Returns a table that, when indexed with an integer, indexes table *t* with
-- that integer along with string *attribute*.
-- This is used by filters that operate on particular attributes of table
-- elements.
-- @param t The table to index.
-- @param attribute The additional attribute to index with.
local function attr_accessor(t, attribute)
  return setmetatable({}, {__index = function(_, i)
    local value = t[i]
    attribute = tonumber(attribute) or attribute
    if type(attribute) == 'number' then return value[attribute] end
    for k in attribute:gmatch('[^.]+') do value = value[k] end
    return value
  end})
end

---
-- Returns a generator that produces all of the items in table *t* in batches
-- of size *size*, filling any empty spaces with value *fill*.
-- Combine this with the "list" filter to produce a list.
-- @param t The table to split into batches.
-- @param size The batch size.
-- @param fill The value to use when filling in any empty space in the last
--   batch.
-- @usage expand('{% for i in {1, 2, 3}|batch(2, 0) %}{{ i|string }}
--   {% endfor %}') --> {1, 2} {3, 0}
-- @see filters.list
-- @name filters.batch
function M.filters.batch(t, size, fill)
  assert(t, 'input to filter "batch" was nil instead of a table')
  local n = #t
  return function(t, i)
    if i > n then return nil end
    local batch = {}
    for j = i, i + size - 1 do batch[j - i + 1] = t[j] end
    if i + size > n and fill then
      for j = n + 1, i + size - 1 do batch[#batch + 1] = fill end
    end
    return i + size, batch
  end, t, 1
end

---
-- Capitalizes string *s*.
-- The first character will be uppercased, the others lowercased.
-- @param s The string to capitalize.
-- @usage expand('{{ "foo bar"|capitalize }}') --> Foo bar
-- @name filters.capitalize
function M.filters.capitalize(s)
  assert(s, 'input to filter "capitalize" was nil instead of a string')
  local first, rest = s:match('^(.)(.*)$')
  return first and first:upper()..rest:lower() or s
end

---
-- Centers string *s* within a string of length *width*.
-- @param s The string to center.
-- @param width The length of the centered string.
-- @usage expand('{{ "foo"|center(9) }}') --> "   foo   "
-- @name filters.center
function M.filters.center(s, width)
  assert(s, 'input to filter "center" was nil instead of a string')
  local padding = (width or 80) - #s
  local left, right = math.ceil(padding / 2), math.floor(padding / 2)
  return ("%s%s%s"):format((' '):rep(left), s, (' '):rep(right))
end

---
-- Returns value *value* or value *default*, depending on whether or not *value*
-- is "true" and whether or not boolean *false_defaults* is `true`.
-- @param value The value return if "true" or if `false` and *false_defaults*
--   is `true`.
-- @param default The value to return if *value* is `nil` or `false` (the latter
--   applies only if *false_defaults* is `true`).
-- @param false_defaults Optional flag indicating whether or not to return
--   *default* if *value* is `false`. The default value is `false`.
-- @usage expand('{{ false|default("no") }}') --> false
-- @usage expand('{{ false|default("no", true) }') --> no
-- @name filters.default
function M.filters.default(value, default, false_defaults)
  if value == nil or false_defaults and not value then return default end
  return value
end

---
-- Returns a table constructed from table *t* such that each element is a list
-- that contains a single key-value pair and all elements are sorted according
-- to string *by* (which is either "key" or "value") and boolean
-- *case_sensitive*.
-- @param value The table to sort.
-- @param case_sensitive Optional flag indicating whether or not to consider
--   case when sorting string values. The default value is `false`.
-- @param by Optional string that specifies which of the key-value to sort by,
--   either "key" or "value". The default value is `"key"`.
-- @usage expand('{{ {b = 1, a = 2}|dictsort|string }}') --> {{"a", 2},
--   {"b", 1}}
-- @name filters.dictsort
function M.filters.dictsort(t, case_sensitive, by)
  assert(t, 'input to filter "dictsort" was nil instead of a table')
  assert(not by or by == 'key' or by == 'value',
         'filter "dictsort" can only sort tables by "key" or "value"')
  local i = (not by or by == 'key') and 1 or 2
  local items = {}
  for k, v in pairs(t) do items[#items + 1] = {k, v} end
  table.sort(items, function(a, b)
    a, b = a[i], b[i]
    if not case_sensitive then
      if type(a) == 'string' then a = a:lower() end
      if type(b) == 'string' then b = b:lower() end
    end
    return a < b
  end)
  return items
end

---
-- Returns an HTML-safe copy of string *s*.
-- @param s String to ensure is HTML-safe.
-- @usage expand([[{{ '<">&'|e}}]]) --> &lt;&#34;&gt;&amp;
-- @name filters.escape
function M.filters.escape(s)
  assert(s, 'input to filter "escape" was nil instead of a string')
  return s:gsub('[<>"\'&]', {
    ['<'] = '&lt;', ['>'] = '&gt;', ['"'] = '&#34;', ["'"] = '&#39;',
    ['&'] = '&amp;'
  })
end

---
-- Returns an HTML-safe copy of string *s*.
-- @param s String to ensure is HTML-safe.
-- @usage expand([[{{ '<">&'|escape}}]]) --> &lt;&#34;&gt;&amp;
-- @name filters.e
function M.filters.e(s)
  assert(s, 'input to filter "e" was nil instead of a string')
  return M.filters.escape(s)
end

---
-- Returns a human-readable, decimal (or binary, depending on boolean *binary*)
-- file size for *bytes* number of bytes.
-- @param bytes The number of bytes to return the size for.
-- @param binary Flag indicating whether or not to report binary file size
--    as opposed to decimal file size. The default value is `false`.
-- @usage expand('{{ 1000|filesizeformat }}') --> 1.0 kB
-- @name filters.filesizeformat
function M.filters.filesizeformat(bytes, binary)
  assert(bytes, 'input to filter "filesizeformat" was nil instead of a number')
  local base = binary and 1024 or 1000
  local units = {
    binary and 'KiB' or 'kB', binary and 'MiB' or 'MB',
    binary and 'GiB' or 'GB', binary and 'TiB' or 'TB',
    binary and 'PiB' or 'PB', binary and 'EiB' or 'EB',
    binary and 'ZiB' or 'ZB', binary and 'YiB' or 'YB'
  }
  if bytes < base then
    return string.format('%d Byte%s', bytes, bytes > 1 and 's' or '')
  else
    local limit, unit
    for i = 1, #units do
      limit, unit = base^(i + 1), units[i]
      if bytes < limit then break end
    end
    return string.format('%.1f %s', (base * bytes / limit), unit)
  end
end

---
-- Returns the first element in table *t*.
-- @param t The table to get the first element of.
-- @usage expand('{{ range(10)|first }}') --> 1
-- @name filters.first
function M.filters.first(t)
  assert(t, 'input to filter "first" was nil instead of a table')
  return t[1]
end

---
-- Returns value *value* as a float.
-- This filter only works in Lua 5.3, which has a distinction between floats and
-- integers.
-- @param value The value to interpret as a float.
-- @usage expand('{{ 42|float }}') --> 42.0
-- @name filters.float
function M.filters.float(value)
  assert(value, 'input to filter "float" was nil instead of a number')
  return (tonumber(value) or 0) * 1.0
end

---
-- Returns an HTML-safe copy of value *value*, even if *value* was returned by
-- the "safe" filter.
-- @param value Value to ensure is HTML-safe.
-- @usage expand('{% set x = "<div />"|safe %}{{ x|forceescape }}') -->
--   &lt;div /&gt;
-- @name filters.forceescape
function M.filters.forceescape(value)
  assert(value, 'input to filter "forceescape" was nil instead of a string')
  return M.filters.escape(tostring(value))
end

---
-- Returns the given arguments formatted according to string *s*.
-- See Lua's `string.format()` for more information.
-- @param s The string to format subsequent arguments according to.
-- @param ... Arguments to format.
-- @usage expand('{{ "%s,%s"|format("a", "b") }}') --> a,b
-- @name filters.format
function M.filters.format(s, ...)
  assert(s, 'input to filter "format" was nil instead of a string')
  return string.format(s, ...)
end

---
-- Returns a generator that produces lists of items in table *t* grouped by
-- string attribute *attribute*.
-- @param t The table to group items from.
-- @param attribute The attribute of items in the table to group by. This may
--   be nested (e.g. "foo.bar" groups by t[i].foo.bar for all i).
-- @usage expand('{% for age, group in people|groupby("age") %}...{% endfor %}')
-- @name filters.groupby
function M.filters.groupby(t, attribute)
  assert(t, 'input to filter "groupby" was nil instead of a table')
  local n = #t
  local seen = {} -- keep track of groupers in order to avoid duplicates
  return function(t, i)
    if i > n then return nil end
    local ta = attr_accessor(t, attribute)
    -- Determine the next grouper.
    local grouper = ta[i]
    while seen[grouper] do
      i = i + 1
      if i > n then return nil end
      grouper = ta[i]
    end
    seen[grouper] = true
    -- Create and return the group.
    local group = {}
    for j = i, #t do if ta[j] == grouper then group[#group + 1] = t[j] end end
    return i + 1, grouper, group
  end, t, 1
end

---
-- Returns a copy of string *s* with all lines after the first indented by
-- *width* number of spaces.
-- If boolean *first_line* is `true`, indents the first line as well.
-- @param s The string to indent lines of.
-- @param width The number of spaces to indent lines with.
-- @param first_line Optional flag indicating whether or not to indent the
--   first line of text. The default value is `false`.
-- @usage expand('{{ "foo\nbar"|indent(2) }}') --> "foo\n  bar"
-- @name filters.indent
function M.filters.indent(s, width, first_line)
  assert(s, 'input to filter "indent" was nil instead of a string')
  local indent = (' '):rep(width)
  return (first_line and indent or '')..s:gsub('([\r\n]+)', '%1'..indent)
end

---
-- Returns value *value* as an integer.
-- @param value The value to interpret as an integer.
-- @usage expand('{{ 32.32|int }}') --> 32
-- @name filters.int
function M.filters.int(value)
  assert(value, 'input to filter "int" was nil instead of a number')
  return math.floor(tonumber(value) or 0)
end

---
-- Returns a string that contains all the elements in table *t* (or all the
-- attributes named *attribute* in *t*) separated by string *sep*.
-- @param t The table to join.
-- @param sep The string to separate table elements with.
-- @param attribute Optional attribute of elements to use for joining instead
--   of the elements themselves. This may be nested (e.g. "foo.bar" joins
--   `t[i].foo.bar` for all i).
-- @usage expand('{{ {1, 2, 3}|join("|") }}') --> 1|2|3
-- @name filters.join
function M.filters.join(t, sep, attribute)
  assert(t, 'input to filter "join" was nil instead of a table')
  if not attribute then
    local strings = {}
    for i = 1, #t do strings[#strings + 1] = tostring(t[i]) end
    return table.concat(strings, sep)
  end
  local ta = attr_accessor(t, attribute)
  local attributes = {}
  for i = 1, #t do attributes[#attributes + 1] = ta[i] end
  return table.concat(attributes, sep)
end

---
-- Returns the last element in table *t*.
-- @param t The table to get the last element of.
-- @usage expand('{{ range(10)|last }}') --> 10
-- @name filters.last
function M.filters.last(t)
  assert(t, 'input to filter "last" was nil instead of a table')
  return t[#t]
end

---
-- Returns the length of string or table *value*.
-- @param value The value to get the length of.
-- @usage expand('{{ "hello world"|length }}') --> 11
-- @name filters.length
function M.filters.length(value)
  assert(value, 'input to filter "length" was nil instead of a table or string')
  return #value
end

---
-- Returns the list of items produced by generator *generator*, subject to
-- initial state *s* and initial iterator variable *i*.
-- This filter should only be used after a filter that returns a generator.
-- @param generator Generator function that produces an item.
-- @param s Initial state for the generator.
-- @param i Initial iterator variable for the generator.
-- @usage expand('{{ range(4)|batch(2)|list|string }}') --> {{1, 2}, {3, 4}}
-- @see filters.batch
-- @see filters.groupby
-- @see filters.slice
-- @name filters.list
function M.filters.list(generator, s, i)
  assert(type(generator) == 'function',
         'input to filter "list" must be a generator')
  local list = {}
  for _, v in generator, s, i do list[#list + 1] = v end
  return list
end

---
-- Returns a copy of string *s* with all lowercase characters.
-- @param s The string to lowercase.
-- @usage expand('{{ "FOO"|lower }}') --> foo
-- @name filters.lower
function M.filters.lower(s)
  assert(s, 'input to filter "lower" was nil instead of a string')
  return string.lower(s)
end

---
-- Maps each element of table *t* to a value produced by filter name *filter*
-- and returns the resultant table.
-- @param t The table of elements to map.
-- @param filter The name of the filter to pass table elements through.
-- @param ... Any arguments for the filter.
-- @usage expand('{{ {"1", "2", "3"}|map("int")|sum }}') --> 6
-- @name filters.map
function M.filters.map(t, filter, ...)
  assert(t, 'input to filter "map" was nil instead of a table')
  local f = M.filters[filter]
  assert(f, 'unknown filter "'..filter..'"')
  local map = {}
  for i = 1, #t do map[i] = f(t[i], ...) end
  return map
end

---
-- Maps the value of each element's string *attribute* in table *t* to the
-- value produced by filter name *filter* and returns the resultant table.
-- @param t The table of elements with attributes to map.
-- @param attribute The attribute of elements in the table to filter. This may
--   be nested (e.g. "foo.bar" maps t[i].foo.bar for all i).
-- @param filter The name of the filter to pass table elements through.
-- @param ... Any arguments for the filter.
-- @usage expand('{{ users|mapattr("name")|join("|") }}')
-- @name filters.mapattr
function M.filters.mapattr(t, attribute, filter, ...)
  assert(t, 'input to filter "mapattr" was nil instead of a table')
  local ta = attr_accessor(t, attribute)
  local f = M.filters[filter]
  if filter then
    assert(f, 'unknown filter "'..filter..'" given to filter "mapattr"')
  end
  local map = {}
  for i = 1, #t do map[i] = filter and f(ta[i], ...) or ta[i] end
  return map
end

---
-- Returns a random element from table *t*.
-- @param t The table to get a random element from.
-- @usage expand('{{ range(100)|random }}')
-- @name filters.random
function M.filters.random(t)
  assert(t, 'input to filter "random" was nil instead of a table')
  math.randomseed(os.time())
  return t[math.random(#t)]
end

---
-- Returns a list of elements in table *t* that fail test name *test*.
-- @param t The table of elements to reject from.
-- @param test The name of the test to use on table elements.
-- @param ... Any arguments for the test.
-- @usage expand('{{ range(5)|reject(is_odd)|join("|") }}') --> 2|4
-- @name filters.reject
function M.filters.reject(t, test, ...)
  assert(t, 'input to filter "reject" was nil instead of a table')
  local f = test or function(value) return not not value end
  local items = {}
  for i = 1, #t do if not f(t[i], ...) then items[#items + 1] = t[i] end end
  return items
end

---
-- Returns a list of elements in table *t* whose string attribute *attribute*
-- fails test name *test*.
-- @param t The table of elements to reject from.
-- @param attribute The attribute of items in the table to reject from. This
--   may be nested (e.g. "foo.bar" tests t[i].foo.bar for all i).
-- @param test The name of the test to use on table elements.
-- @param ... Any arguments for the test.
-- @usage expand('{{ users|rejectattr("offline")|mapattr("name")|join(",") }}')
-- @name filters.rejectattr
function M.filters.rejectattr(t, attribute, test, ...)
  assert(t, 'input to filter "rejectattr" was nil instead of a table')
  local ta = attr_accessor(t, attribute)
  local f = test or function(value) return not not value end
  local items = {}
  for i = 1, #t do if not f(ta[i], ...) then items[#items + 1] = t[i] end end
  return items
end

---
-- Returns a copy of string *s* with all (or up to *n*) occurrences of string
-- *old* replaced by string *new*.
-- Identical to Lua's `string.gsub()` and handles Lua patterns.
-- @param s The subject string.
-- @param pattern The string or Lua pattern to replace.
-- @param repl The replacement text (may contain Lua captures).
-- @param n Optional number indicating the maximum number of replacements to
--   make. The default value is `nil`, which is unlimited.
-- @usage expand('{% filter upper|replace("FOO", "foo") %}foobar
--   {% endfilter %}') --> fooBAR
-- @name filters.replace
function M.filters.replace(s, pattern, repl, n)
  assert(s, 'input to filter "replace" was nil instead of a string')
  return string.gsub(s, pattern, repl, n)
end

---
-- Returns a copy of the given string or table *value* in reverse order.
-- @param value The value to reverse.
-- @usage expand('{{ {1, 2, 3}|reverse|string }}') --> {3, 2, 1}
-- @name filters.reverse
function M.filters.reverse(value)
  assert(type(value) == 'table' or type(value) == 'string',
         'input to filter "reverse" was nil instead of a table or string')
  if type(value) == 'string' then return value:reverse() end
  local t = {}
  for i = 1, #value do t[i] = value[#value - i + 1] end
  return t
end

---
-- Returns number *value* rounded to *precision* decimal places based on string
-- *method* (if given).
-- @param value The number to round.
-- @param precision Optional precision to round the number to. The default
--   value is `0`.
-- @param method Optional string rounding method, either `"ceil"` or
--   `"floor"`. The default value is `nil`, which uses the common rounding
--   method (if a number's fractional part is 0.5 or greater, rounds up;
--   otherwise rounds down).
-- @usage expand('{{ 2.1236|round(3, "floor") }}') --> 2.123
-- @name filters.round
function M.filters.round(value, precision, method)
  assert(value, 'input to filter "round" was nil instead of a number')
  assert(not method or method == 'ceil' or method == 'floor',
         'rounding method given to filter "round" must be "ceil" or "floor"')
  precision = precision or 0
  method = method or (select(2, math.modf(value)) >= 0.5 and 'ceil' or 'floor')
  local s = string.format('%.'..(precision >= 0 and precision or 0)..'f',
                          math[method](value * 10^precision) / 10^precision)
  return tonumber(s)
end

---
-- Marks string *s* as HTML-safe, preventing Lupa from modifying it when
-- configured to autoescape HTML entities.
-- This filter must be used at the end of a filter chain unless it is
-- immediately proceeded by the "forceescape" filter.
-- @param s The string to mark as HTML-safe.
-- @usage lupa.configure{autoescape = true}
-- @usage expand('{{ "<div>foo</div>"|safe }}') --> <div>foo</div>
-- @name filters.safe
function M.filters.safe(s)
  assert(s, 'input to filter "safe" was nil instead of a string')
  return setmetatable({}, {__tostring = function() return s end})
end

---
-- Returns a list of the elements in table *t* that pass test name *test*.
-- @param t The table of elements to select from.
-- @param test The name of the test to use on table elements.
-- @param ... Any arguments for the test.
-- @usage expand('{{ range(5)|select(is_odd)|join("|") }}') --> 1|3|5
-- @name filters.select
function M.filters.select(t, test, ...)
  assert(t, 'input to filter "select" was nil instead of a table')
  local f = test or function(value) return not not value end
  local items = {}
  for i = 1, #t do if f(t[i], ...) then items[#items + 1] = t[i] end end
  return items
end

---
-- Returns a list of elements in table *t* whose string attribute *attribute*
-- passes test name *test*.
-- @param t The table of elements to select from.
-- @param attribute The attribute of items in the table to select from. This
--   may be nested (e.g. "foo.bar" tests t[i].foo.bar for all i).
-- @param test The name of the test to use on table elements.
-- @param ... Any arguments for the test.
-- @usage expand('{{ users|selectattr("online")|mapattr("name")|join("|") }}')
-- @name filters.selectattr
function M.filters.selectattr(t, attribute, test, ...)
  assert(t, 'input to filter "selectattr" was nil instead of a table')
  local ta = attr_accessor(t, attribute)
  local f = test or function(value) return not not value end
  local items = {}
  for i = 1, #t do if f(ta[i], ...) then items[#items + 1] = t[i] end end
  return items
end

---
-- Returns a generator that produces all of the items in table *t* in *slices*
-- number of iterations, filling any empty spaces with value *fill*.
-- Combine this with the "list" filter to produce a list.
-- @param t The table to slice.
-- @param slices The number of slices to produce.
-- @param fill The value to use when filling in any empty space in the last
--   slice.
-- @usage expand('{% for i in {1, 2, 3}|slice(2, 0) %}{{ i|string }}
--   {% endfor %}') --> {1, 2} {3, 0}
-- @see filters.list
-- @name filters.slice
function M.filters.slice(t, slices, fill)
  assert(t, 'input to filter "slice" was nil instead of a table')
  local size, slices_with_extra = math.floor(#t / slices), #t % slices
  return function(t, i)
    if i > slices then return nil end
    local slice = {}
    local s = (i - 1) * size + math.min(i, slices_with_extra + 1)
    local e = i * size + math.min(i, slices_with_extra)
    for j = s, e do slice[j - s + 1] = t[j] end
    if slices_with_extra > 0 and i > slices_with_extra and fill then
      slice[#slice + 1] = fill
    end
    return i + 1, slice
  end, t, 1
end

---
-- Returns a copy of table or string *value* in sorted order by value (or by
-- an attribute named *attribute*), depending on booleans *reverse* and
-- *case_sensitive*.
-- @param value The table or string to sort.
-- @param reverse Optional flag indicating whether or not to sort in reverse
--   (descending) order. The default value is `false`, which sorts in ascending
--   order.
-- @param case_sensitive Optional flag indicating whether or not to consider
--   case when sorting string values. The default value is `false`.
-- @param attribute Optional attribute of elements to sort by instead of the
--   elements themselves.
-- @usage expand('{{ {2, 3, 1}|sort|string }}') --> {1, 2, 3}
-- @name filters.sort
function M.filters.sort(value, reverse, case_sensitive, attribute)
  assert(value, 'input to filter "sort" was nil instead of a table or string')
  assert(not attribute or type(attribute) == 'string' or
         type(attribute) == 'number',
         'attribute to filter "sort" must be a string or number')
  local t = {}
  local sort_string = type(value) == 'string'
  if not sort_string then
    for i = 1, #value do t[#t + 1] = value[i] end
  else
    for char in value:gmatch('.') do t[#t + 1] = char end -- chars in string
  end
  table.sort(t, function(a, b)
    if attribute then
      if type(attribute) == 'number' then
        a, b = a[attribute], b[attribute]
      else
        for k in attribute:gmatch('[^.]+') do a, b = a[k], b[k] end
      end
    end
    if not case_sensitive then
      if type(a) == 'string' then a = a:lower() end
      if type(b) == 'string' then b = b:lower() end
    end
    if not reverse then
      return a < b
    else
      return a > b
    end
  end)
  return not sort_string and t or table.concat(t)
end

---
-- Returns the string representation of value *value*, handling lists properly.
-- @param value Value to return the string representation of.
-- @usage expand('{{ {1 * 1, 2 * 2, 3 * 3}|string }}') --> {1, 4, 9}
-- @name filters.string
function M.filters.string(value)
  if type(value) ~= 'table' then return tostring(value) end
  local t = {}
  for i = 1, #value do
    local item = value[i]
    t[i] = type(item) == 'string' and '"'..item..'"' or M.filters.string(item)
  end
  return '{'..table.concat(t, ', ')..'}'
end

---
-- Returns a copy of string *s* with any HTML tags stripped.
-- Also cleans up whitespace.
-- @param s String to strip HTML tags from.
-- @usage expand('{{ "<div>foo</div>"|striptags }}') --> foo
-- @name filters.striptags
function M.filters.striptags(s)
  assert(s, 'input to filter "striptags" was nil instead of a string')
  return s:gsub('%b<>', ''):gsub('%s+', ' '):match('^%s*(.-)%s*$')
end

---
-- Returns the numeric sum of the elements in table *t* or the sum of all
-- attributes named *attribute* in *t*.
-- @param t The table to calculate the sum of.
-- @param attribute Optional attribute of elements to use for summing instead
--   of the elements themselves. This may be nested (e.g. "foo.bar" sums
--   `t[i].foo.bar` for all i).
-- @usage expand('{{ range(6)|sum }}') --> 21
-- @name filters.sum
function M.filters.sum(t, attribute)
  assert(t, 'input to filter "sum" was nil instead of a table')
  local ta = attribute and attr_accessor(t, attribute) or t
  local sum = 0
  for i = 1, #t do sum = sum + ta[i] end
  return sum
end

---
-- Returns a copy of all words in string *s* in titlecase.
-- @param s The string to titlecase.
-- @usage expand('{{ "foo bar"|title }}') --> Foo Bar
-- @name filters.title
function M.filters.title(s)
  assert(s, 'input to filter "title" was nil instead of a string')
  return s:gsub('[^-%s]+', M.filters.capitalize)
end

---
-- Returns a copy of string *s* truncated to *length* number of characters.
-- Truncated strings end with '...' or string *delimiter*. If boolean
-- *partial_words* is `false`, truncation will only happen at word boundaries.
-- @param s The string to truncate.
-- @param length The length to truncate the string to.
-- @param partial_words Optional flag indicating whether or not to allow
--   truncation within word boundaries. The default value is `false`.
-- @param delimiter Optional delimiter text. The default value is '...'.
-- @usage expand('{{ "foo bar"|truncate(4) }}') --> "foo ..."
-- @name filters.truncate
function M.filters.truncate(s, length, partial_words, delimiter)
  assert(s, 'input to filter "truncate" was nil instead of a string')
  if #s <= length then return s end
  local truncated = s:sub(1, length)
  if s:find('[%w_]', length) and not partial_words then
    truncated = truncated:match('^(.-)[%w_]*$') -- drop partial word
  end
  return truncated..(delimiter or '...')
end

---
-- Returns a copy of string *s* with all uppercase characters.
-- @param s The string to uppercase.
-- @usage expand('{{ "foo"|upper }}') --> FOO
-- @name filters.upper
function M.filters.upper(s)
  assert(s, 'input to filter "upper" was nil instead of a string')
  return string.upper(s)
end

---
-- Returns a string suitably encoded to be used in a URL from value *value*.
-- *value* may be a string, table of key-value query parameters, or table of
-- lists of key-value query parameters (for order).
-- @param value Value to URL-encode.
-- @usage expand('{{ {{'f', 1}, {'z', 2}}|urlencode }}') --> f=1&z=2
-- @name filters.urlencode
function M.filters.urlencode(value)
  assert(value,
         'input to filter "urlencode" was nil instead of a string or table')
  if type(value) ~= 'table' then
    return tostring(value):gsub('[^%w.-]', function(c)
      return string.format('%%%X', string.byte(c))
    end)
  end
  local params = {}
  if #value > 0 then
    for i = 1, #value do
      local k = M.filters.urlencode(value[i][1])
      local v = M.filters.urlencode(value[i][2])
      params[#params + 1] = k..'='..v
    end
  else
    for k, v in pairs(value) do
      params[#params + 1] = M.filters.urlencode(k)..'='..M.filters.urlencode(v)
    end
  end
  return table.concat(params, '&')
end

---
-- Replaces any URLs in string *s* with HTML links, limiting link text to
-- *length* characters.
-- @param s The string to replace URLs with HTML links in.
-- @param length Optional maximum number of characters to include in link text.
--   The default value is `nil`, which imposes no limit.
-- @param nofollow Optional flag indicating whether or not HTML links will get a
--   "nofollow" attribute.
-- @usage expand('{{ "example.com"|urlize }}') -->
--   <a href="http://example.com">example.com</a>
-- @name filters.urlize
function M.filters.urlize(s, length, nofollow)
  assert(s, 'input to filter "urlize" was nil instead of a string')
  -- Trims the given url.
  local function trim_url(url)
    return length and s:sub(1, length)..(#s > length and '...' or '') or url
  end
  local nofollow_attr = nofollow and ' rel="nofollow"' or ''
  local lead, trail = C((S('(<') + '&lt;')^0), C((S('.,)>\n') + '&gt;')^0) * -1
  local middle = C((1 - trail)^0)
  local patt = lpeg.Cs(lead * middle * trail / function(lead, middle, trail)
    local linked
    if middle:find('^www%.') or (not middle:find('@') and
                                 not middle:find('^https?://') and
                                 #middle > 0 and middle:find('^%w') and (
                                   middle:find('%.com$') or
                                   middle:find('%.net$') or
                                   middle:find('%.org$')
                                 )) then
      middle, linked = string.format('<a href="http://%s"%s>%s</a>', middle,
                                     nofollow_attr, trim_url(middle)), true
    end
    if middle:find('^https?://') then
      middle, linked = string.format('<a href="%s"%s>%s</a>', middle,
                                     nofollow_attr, trim_url(middle)), true
    end
    if middle:find('@') and not middle:find('^www%.') and
       not middle:find(':') and middle:find('^%S+@[%w._-]+%.[%w._-]+$') then
      middle, linked = string.format('<a href="mailto:%s">%s</a>', middle,
                                     middle), true
    end
    if linked then return lead..middle..trail end
  end)
  return M.filters.escape(s):gsub('%S+', function(word)
    return lpeg.match(patt, word)
  end)
end

---
-- Returns the number of words in string *s*.
-- A word is a sequence of non-space characters.
-- @param s The string to count words in.
-- @usage expand('{{ "foo bar baz"|wordcount }}') --> 3
-- @name filters.wordcount
function M.filters.wordcount(s)
  assert(s, 'input to filter "wordcount" was nil instead of a string')
  return select(2, s:gsub('%S+', ''))
end

---
-- Interprets table *t* as a list of XML attribute-value pairs, returning them
-- as a properly formatted, space-separated string.
-- @param t The table of XML attribute-value pairs.
-- @usage expand('<data {{ {foo = 42, bar = 23}|xmlattr }} />')
-- @name filters.xmlattr
function M.filters.xmlattr(t)
  assert(t, 'input to filter "xmlattr" was nil instead of a table')
  local attributes = {}
  for k, v in pairs(t) do
    attributes[#attributes + 1] = string.format('%s="%s"', k,
                                                M.filters.escape(tostring(v)))
  end
  return table.concat(attributes, ' ')
end

-- Lupa tests.

---
-- Returns whether or not number *n* is odd.
-- @param n The number to test.
-- @usage expand('{% for x in range(10) if is_odd(x) %}...{% endif %}')
-- @name tests.is_odd
function M.tests.is_odd(n) return n % 2 == 1 end

---
-- Returns whether or not number *n* is even.
-- @param n The number to test.
-- @usage expand('{% for x in range(10) if is_even(x) %}...{% endif %}')
-- @name tests.is_even
function M.tests.is_even(n) return n % 2 == 0 end

---
-- Returns whether or not number *n* is evenly divisible by number *num*.
-- @param n The dividend to test.
-- @param num The divisor to use.
-- @usage expand('{% if is_divisibleby(x, y) %}...{% endif %}')
-- @name tests.is_divisibleby
function M.tests.is_divisibleby(n, num) return n % num == 0 end

---
-- Returns whether or not value *value* is non-nil, and thus defined.
-- @param value The value to test.
-- @usage expand('{% if is_defined(x) %}...{% endif %}')
-- @name tests.is_defined
function M.tests.is_defined(value) return value ~= nil end

---
-- Returns whether or not value *value* is nil, and thus effectively undefined.
-- @param value The value to test.
-- @usage expand('{% if is_undefined(x) %}...{% endif %}')
-- @name tests.is_undefined
function M.tests.is_undefined(value) return value == nil end

---
-- Returns whether or not value *value* is nil.
-- @param value The value to test.
-- @usage expand('{% if is_none(x) %}...{% endif %}')
-- @name tests.is_none
function M.tests.is_none(value) return value == nil end

---
-- Returns whether or not value *value* is nil.
-- @param value The value to test.
-- @usage expand('{% if is_nil(x) %}...{% endif %}')
-- @name tests.is_nil
function M.tests.is_nil(value) return value == nil end

---
-- Returns whether or not string *s* is in all lower-case characters.
-- @param s The string to test.
-- @usage expand('{% if is_lower(s) %}...{% endif %}')
-- @name tests.is_lower
function M.tests.is_lower(s) return s:lower() == s end

---
-- Returns whether or not string *s* is in all upper-case characters.
-- @param s The string to test.
-- @usage expand('{% if is_upper(s) %}...{% endif %}')
-- @name tests.is_upper
function M.tests.is_upper(s) return s:upper() == s end

---
-- Returns whether or not value *value* is a string.
-- @param value The value to test.
-- @usage expand('{% if is_string(x) %}...{% endif %}')
-- @name tests.is_string
function M.tests.is_string(value) return type(value) == 'string' end

---
-- Returns whether or not value *value* is a table.
-- @param value The value to test.
-- @usage expand('{% if is_mapping(x) %}...{% endif %}')
-- @name tests.is_mapping
function M.tests.is_mapping(value) return type(value) == 'table' end

---
-- Returns whether or not value *value* is a table.
-- @param value The value to test.
-- @usage expand('{% if is_table(x) %}...{% endif %}')
-- @name tests.is_table
function M.tests.is_table(value) return type(value) == 'table' end

---
-- Returns whether or not value *value* is a number.
-- @param value The value to test.
-- @usage expand('{% if is_number(x) %}...{% endif %}')
-- @name tests.is_number
function M.tests.is_number(value) return type(value) == 'number' end

---
-- Returns whether or not value *value* is a sequence, namely a table with
-- non-zero length.
-- @param value The value to test.
-- @usage expand('{% if is_sequence(x) %}...{% endif %}')
-- @name tests.is_sequence
function M.tests.is_sequence(value)
  return type(value) == 'table' and #value > 0
end

---
-- Returns whether or not value *value* is a sequence (a table with non-zero
-- length) or a generator.
-- At the moment, all functions are considered generators.
-- @param value The value to test.
-- @usage expand('{% if is_iterable(x) %}...{% endif %}')
-- @name tests.is_iterable
function M.tests.is_iterable(value)
  return M.tests.is_sequence(value) or type(value) == 'function'
end

---
-- Returns whether or not value *value* is a function.
-- @param value The value to test.
-- @usage expand('{% if is_callable(x) %}...{% endif %}')
-- @name tests.is_callable
function M.tests.is_callable(value) return type(value) == 'function' end

---
-- Returns whether or not value *value* is the same as value *other*.
-- @param value The value to test.
-- @param other The value to compare with.
-- @usage expand('{% if is_sameas(x, y) %}...{% endif %}')
-- @name tests.is_sameas
function M.tests.is_sameas(value, other) return value == other end

---
-- Returns whether or not value *value* is HTML-safe.
-- @param value The value to test.
-- @usage expand('{% if is_escaped(x) %}...{% endif %}')
-- @name tests.is_escaped
function M.tests.is_escaped(value)
  return getmetatable(value) and getmetatable(value).__tostring ~= nil
end

return M
