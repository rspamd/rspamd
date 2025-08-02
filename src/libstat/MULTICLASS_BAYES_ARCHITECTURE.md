# Rspamd Multiclass Bayes Architecture

## Overview

This document describes the complete data flow for the multiclass Bayes classification system in Rspamd, covering the interaction between C++ core, Lua scripts, Redis backend, and the classification pipeline.

## High-Level Data Flow

```
[Task Processing] → [Tokenization] → [Redis Backend] → [Lua Scripts] → [Redis Scripts] → [Results] → [Classification]
```

## 1. Classification Pipeline Entry Point

### 1.1 Task Processing Start

```c
// src/libstat/stat_process.c
rspamd_stat_classify(struct rspamd_task *task, struct rspamd_config *cfg)
```

**Flow:**

1. Task arrives for classification
2. Iterates through configured classifiers
3. For each classifier, calls `rspamd_stat_classifiers[i].classify_func()`
4. For Bayes: calls `bayes_classify_multiclass()`

### 1.2 Bayes Classification Entry

```c
// src/libstat/classifiers/bayes.c
gboolean bayes_classify_multiclass(struct rspamd_classifier *ctx,
                                   GPtrArray *tokens,
                                   struct rspamd_task *task)
```

**Key Steps:**

1. Validates `ctx->cfg->class_names` array
2. Sets up `bayes_task_closure` with class information
3. **Calls Redis backend to fetch token data**
4. Processes returned token values
5. Calculates probabilities and inserts symbols

## 2. Redis Backend Data Flow

### 2.1 Backend Runtime Creation

```cpp
// src/libstat/backends/redis_backend.cxx
gpointer rspamd_redis_runtime(struct rspamd_task *task,
                              struct rspamd_statfile_config *stcf,
                              gboolean learn, gpointer c, int _id)
```

**Runtime Structure:**

```cpp
template<class T>
class redis_stat_runtime {
    struct redis_stat_ctx *ctx;              // Redis connection context
    struct rspamd_task *task;                // Current task
    struct rspamd_statfile_config *stcf;     // Statfile configuration
    const char *redis_object_expanded;       // Expanded key prefix
    int id;                                  // Statfile ID (critical!)
    std::optional<std::map<int, T>> results; // Token index → value mapping
};
```

**Critical Insight: Statfile ID Mapping**

-   Each statfile has a unique ID (`id`)
-   Token values are stored in `tok->values[id]` array
-   **The `id` must match exactly between runtime and statfile**

### 2.2 Multiple Runtime Creation (Classification Mode)

For multiclass classification, the system creates multiple runtimes:

```cpp
// For each statfile in classifier
for (cur = stcf->clcf->statfiles; cur; cur = g_list_next(cur)) {
    auto *other_stcf = (struct rspamd_statfile_config *) cur->data;

    // Find correct statfile ID
    struct rspamd_stat_ctx *st_ctx = rspamd_stat_get_ctx();
    int other_id = -1;
    for (i = 0; i < st_ctx->statfiles->len; i++) {
        struct rspamd_statfile *st = g_ptr_array_index(st_ctx->statfiles, i);
        if (st->stcf == other_stcf) {
            other_id = st->id;  // ← This is the critical mapping!
            break;
        }
    }

    // Create runtime with correct ID
    auto *other_rt = new redis_stat_runtime<float>(ctx, task, object_expanded);
    other_rt->id = other_id;  // ← Must be set correctly!
}
```

### 2.3 Token Processing Call

```cpp
gboolean rspamd_redis_process_tokens(struct rspamd_task *task,
                                     GPtrArray *tokens,
                                     int id, gpointer p)
```

**Flow:**

1. Serializes tokens to MessagePack format
2. Builds class labels string (e.g., "TABLE:H,S,N,T")
3. Calls Lua function to execute Redis script
4. Registers callback for async result processing

## 3. Lua Script Layer

### 3.1 Lua Function Entry Point

```lua
-- lualib/lua_bayes_redis.lua
local function gen_classify_functor(redis_params, classify_script_id)
  return function(task, expanded_key, id, stat_tokens, callback)
    -- Executes Redis script via lua_redis
    lua_redis.exec_redis_script(classify_script_id,
        { task = task, is_write = false, key = expanded_key },
        classify_redis_cb,
        { expanded_key, class_labels, stat_tokens })
  end
end
```

**Key Components:**

-   `expanded_key`: Redis key prefix (e.g., "BAYES{user@domain}")
-   `class_labels`: "TABLE:H,S,N,T" format for multiclass
-   `stat_tokens`: MessagePack-encoded token array
-   `callback`: Function to handle Redis script results

### 3.2 Class Labels Format

**Critical Detail**: The class labels format determines Redis script behavior:

```lua
-- Binary mode (legacy)
class_labels = "H"  -- Single class

-- Multiclass mode
class_labels = "TABLE:H,S,N,T"  -- Multiple classes with TABLE: prefix
```

## 4. Redis Script Execution

### 4.1 Script Structure

```lua
-- lualib/redis_scripts/bayes_classify.lua
local prefix = KEYS[1]              -- "BAYES{user@domain}"
local class_labels_arg = KEYS[2]    -- "TABLE:H,S,N,T"
local input_tokens = cmsgpack.unpack(KEYS[3])  -- [tok1, tok2, ...]
```

### 4.2 Class Label Parsing

```lua
local class_labels = {}
if string.match(class_labels_arg, "^TABLE:") then
  -- Multiclass mode
  local labels_str = string.sub(class_labels_arg, 7) -- Remove "TABLE:"
  for label in string.gmatch(labels_str, "([^,]+)") do
    table.insert(class_labels, label)  -- ["H", "S", "N", "T"]
  end
else
  -- Binary mode (single label)
  table.insert(class_labels, class_labels_arg)
end
```

### 4.3 Redis Key Structure

**Learning Counts:**

```
BAYES{user@domain}_H_learns  → { learns: 1500 }
BAYES{user@domain}_S_learns  → { learns: 800 }
BAYES{user@domain}_N_learns  → { learns: 200 }
BAYES{user@domain}_T_learns  → { learns: 150 }
```

**Token Counts:**

```
BAYES{user@domain}_H_tokens  → { token1: 45, token2: 12, ... }
BAYES{user@domain}_S_tokens  → { token1: 23, token2: 67, ... }
BAYES{user@domain}_N_tokens  → { token1: 5,  token2: 8,  ... }
BAYES{user@domain}_T_tokens  → { token1: 2,  token2: 3,  ... }
```

### 4.4 Token Lookup Process

```lua
-- Get learning counts for each class
local learned_counts = {}
for i, class_label in ipairs(class_labels) do
  local learns_key = prefix .. "_" .. class_label .. "_learns"
  learned_counts[i] = tonumber(redis.call('HGET', learns_key, 'learns') or '0')
end

-- Batch token lookup for all classes
local pipe = redis.call('MULTI')
for i, token in ipairs(input_tokens) do
  for j, class_label in ipairs(class_labels) do
    local token_key = prefix .. "_" .. class_label .. "_tokens"
    redis.call('HGET', token_key, token)
  end
end
local token_results = redis.call('EXEC')

-- Parse results into ordered arrays
local token_data = {}
for j, class_label in ipairs(class_labels) do
  token_data[j] = {}  -- token_data[class_index][token_index] = count
end

local result_idx = 1
for i, token in ipairs(input_tokens) do
  for j, class_label in ipairs(class_labels) do
    local count = tonumber(token_results[result_idx]) or 0
    if count > 0 then
      table.insert(token_data[j], {i, count})  -- {token_index, count}
    end
    result_idx = result_idx + 1
  end
end

-- Return: [learned_counts, token_data]
return {learned_counts, token_data}
```

### 4.5 Return Format

**Redis Script Returns:**

```lua
{
  [1] = {1500, 800, 200, 150},  -- learned_counts per class
  [2] = {                       -- token_data per class
    [1] = {{1,45}, {2,12}, ...}, -- Class H tokens: {token_idx, count}
    [2] = {{1,23}, {2,67}, ...}, -- Class S tokens
    [3] = {{1,5},  {2,8},  ...}, -- Class N tokens
    [4] = {{1,2},  {2,3},  ...}  -- Class T tokens
  }
}
```

## 5. Result Processing in C++

### 5.1 Redis Callback Handler

```cpp
// src/libstat/backends/redis_backend.cxx
static int rspamd_redis_classified(lua_State *L)
{
    auto *rt = REDIS_RUNTIME(rspamd_mempool_get_variable(task->task_pool, cookie));
    bool result = lua_toboolean(L, 2);

    if (result && lua_istable(L, 3)) {
        // Process learned_counts (table index 1)
        lua_rawgeti(L, 3, 1);
        if (lua_istable(L, -1)) {
            // Store learned counts (implementation detail)
        }
        lua_pop(L, 1);

        // Process token_results (table index 2)
        lua_rawgeti(L, 3, 2);
        if (lua_istable(L, -1)) {
            process_multiclass_token_results(L, rt, task);
        }
        lua_pop(L, 1);
    }
}
```

### 5.2 Token Results Processing

```cpp
static void process_multiclass_token_results(lua_State *L,
                                           redis_stat_runtime<float> *rt,
                                           struct rspamd_task *task)
{
    // L stack: token_results table at top
    // Format: {[1] = {{1,45}, {2,12}}, [2] = {{1,23}, {2,67}}, ...}

    if (rt->stcf->clcf && rt->stcf->clcf->statfiles) {
        GList *cur = rt->stcf->clcf->statfiles;
        int class_idx = 1;

        while (cur) {
            auto *stcf = (struct rspamd_statfile_config *)cur->data;

            // Find correct statfile ID
            int statfile_id = find_statfile_id_for_config(stcf);

            // Get or create runtime for this statfile
            auto maybe_statfile_rt = get_runtime_for_statfile(task, stcf, statfile_id);
            if (maybe_statfile_rt) {
                auto *statfile_rt = maybe_statfile_rt.value();

                // Get token data for this class (class_idx)
                lua_rawgeti(L, -1, class_idx);
                if (lua_istable(L, -1)) {
                    parse_class_token_data(L, statfile_rt);
                }
                lua_pop(L, 1);
            }

            cur = g_list_next(cur);
            class_idx++;
        }
    }
}
```

### 5.3 Token Value Assignment

```cpp
bool redis_stat_runtime<T>::process_tokens(GPtrArray *tokens) const
{
    rspamd_token_t *tok;

    if (!results) {
        return false;
    }

    // results maps: token_index → token_count
    for (auto [token_idx, token_count] : *results) {
        tok = (rspamd_token_t *) g_ptr_array_index(tokens, token_idx - 1);

        // CRITICAL: Set tok->values[id] where id is the statfile ID
        tok->values[id] = token_count;
    }

    return true;
}
```

## 6. Classification Algorithm Execution

### 6.1 Multiclass Processing

```c
// src/libstat/classifiers/bayes.c
gboolean bayes_classify_multiclass(struct rspamd_classifier *ctx,
                                   GPtrArray *tokens,
                                   struct rspamd_task *task)
{
    struct bayes_task_closure cl;

    // Initialize with class information from config
    cl.num_classes = ctx->cfg->class_names->len;
    cl.class_names = (char**)ctx->cfg->class_names->pdata;

    // Process all tokens
    for (i = 0; i < tokens->len; i++) {
        rspamd_token_t *tok = g_ptr_array_index(tokens, i);
        bayes_classify_token_multiclass(ctx, tok, &cl);
    }
}
```

### 6.2 Token Classification

```c
static void bayes_classify_token_multiclass(struct rspamd_classifier *ctx,
                                           rspamd_token_t *tok,
                                           struct bayes_task_closure *cl)
{
    // For each statfile, check if it has data for this token
    for (i = 0; i < ctx->statfiles_ids->len; i++) {
        int id = g_array_index(ctx->statfiles_ids, int, i);
        struct rspamd_statfile *st = g_ptr_array_index(ctx->ctx->statfiles, id);

        // CRITICAL: tok->values[id] must be set by Redis backend
        double val = tok->values[id];

        if (val > 0) {
            // Find which class this statfile belongs to
            for (j = 0; j < cl->num_classes; j++) {
                if (strcmp(st->stcf->class_name, cl->class_names[j]) == 0) {
                    // Accumulate token evidence for this class
                    process_token_for_class(cl, j, val, st);
                    break;
                }
            }
        }
    }
}
```

## 7. Critical Data Mapping

### 7.1 Statfile ID Assignment

**The Core Problem**: Ensuring correct mapping between:

1. **Redis script class order**: `[H, S, N, T]` (array indices 1,2,3,4)
2. **Statfile IDs**: Global statfile IDs assigned by `rspamd_stat_get_ctx()`
3. **Runtime IDs**: Must match statfile IDs for `tok->values[id]` assignment

### 7.2 Configuration to Runtime Mapping

```c
// Configuration defines classes
statfile "BAYES_HAM" { class = "ham"; symbol = "BAYES_HAM"; }      // Gets ID=0
statfile "BAYES_SPAM" { class = "spam"; symbol = "BAYES_SPAM"; }   // Gets ID=1
statfile "BAYES_NEWS" { class = "news"; symbol = "BAYES_NEWS"; }   // Gets ID=2

// Redis backend maps: class_name → backend_label
class_labels = {
    "ham" = "H";    // Maps to Redis "H"
    "spam" = "S";   // Maps to Redis "S"
    "news" = "N";   // Maps to Redis "N"
}

// Redis script processes in label order: ["H", "S", "N"]
// Returns data in same order: [ham_data, spam_data, news_data]

// C++ must map:
//   redis_result[0] → statfile_id=0 (ham)
//   redis_result[1] → statfile_id=1 (spam)
//   redis_result[2] → statfile_id=2 (news)
```

### 7.3 Token Array Structure

```c
// For each token in message
struct rspamd_token {
    uint64_t data;                    // Token hash
    float values[MAX_STATFILES];      // Values per statfile ID
    // ...
};

// After Redis processing:
// tok->values[0] = ham_count     (from redis_result[0])
// tok->values[1] = spam_count    (from redis_result[1])
// tok->values[2] = news_count    (from redis_result[2])
```
