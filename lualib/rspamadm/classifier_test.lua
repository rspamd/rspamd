local rspamd_util = require "rspamd_util"
local lua_util = require "lua_util"
local argparse = require "argparse"
local ucl = require "ucl"
local rspamd_logger = require "rspamd_logger"

local parser = argparse()
    :name "rspamadm classifier_test"
    :description "Learn classifier and evaluate its performance"
    :help_description_margin(32)

parser:option "-H --ham"
      :description("Ham directory")
      :argname("<dir>")
parser:option "-S --spam"
      :description("Spam directory")
      :argname("<dir>")
parser:option "-C --classifier"
      :description("Classifier type: bayes or llm_embeddings")
      :argname("<type>")
      :default('bayes')
parser:flag "-n --no-learning"
      :description("Do not learn classifier")
parser:flag "-T --train-only"
      :description("Only train, do not evaluate (llm_embeddings only)")
parser:option "--nconns"
      :description("Number of parallel connections")
      :argname("<N>")
      :convert(tonumber)
      :default(10)
parser:option "-t --timeout"
      :description("Timeout for client connections")
      :argname("<sec>")
      :convert(tonumber)
      :default(60)
parser:option "-c --connect"
      :description("Connect to specific host")
      :argname("<host>")
      :default('localhost:11334')
parser:option "-r --rspamc"
      :description("Use specific rspamc path")
      :argname("<path>")
      :default('rspamc')
parser:option "-f --cv-fraction"
      :description("Use specific fraction for cross-validation")
      :argname("<fraction>")
      :convert(tonumber)
      :default(0.7)
parser:option "--spam-symbol"
      :description("Use specific spam symbol (auto-detected from classifier type)")
      :argname("<symbol>")
parser:option "--ham-symbol"
      :description("Use specific ham symbol (auto-detected from classifier type)")
      :argname("<symbol>")
parser:option "--train-wait"
      :description("Seconds to wait after training for neural network (llm_embeddings only, should be > watch_interval)")
      :argname("<sec>")
      :convert(tonumber)
      :default(90)

local opts

-- Utility function to split a table into two parts randomly
local function split_table(t, fraction)
  local shuffled = {}
  for _, v in ipairs(t) do
    local pos = math.random(1, #shuffled + 1)
    table.insert(shuffled, pos, v)
  end
  local split_point = math.floor(#shuffled * tonumber(fraction))
  local part1 = { lua_util.unpack(shuffled, 1, split_point) }
  local part2 = { lua_util.unpack(shuffled, split_point + 1) }
  return part1, part2
end

-- Utility function to get all files in a directory
local function get_files(dir)
  return rspamd_util.glob(dir .. '/*')
end

local function list_to_file(list, fname)
  local out = assert(io.open(fname, "w"))
  for _, v in ipairs(list) do
    out:write(v)
    out:write("\n")
  end
  out:close()
end

-- Function to train the Bayes classifier with given files
local function train_bayes(files, command)
  local fname = os.tmpname()
  list_to_file(files, fname)
  local rspamc_command = string.format("%s --connect %s -j --compact -n %s -t %.3f %s --files-list=%s",
      opts.rspamc, opts.connect, opts.nconns, opts.timeout, command, fname)
  local handle = assert(io.popen(rspamc_command))
  handle:read("*all")
  handle:close()
  os.remove(fname)
end

-- Function to train with ANN-Train header (for llm_embeddings/neural)
-- Uses settings to enable only NEURAL_LEARN symbol, skipping full scan
local function train_neural(files, learn_type)
  local fname = os.tmpname()
  list_to_file(files, fname)

  -- Use ANN-Train header with settings to limit scan to NEURAL_LEARN only
  local rspamc_command = string.format(
    "%s --connect %s -j --compact -n %s -t %.3f " ..
    "--settings '{\"symbols_enabled\":[\"NEURAL_LEARN\"]}' " ..
    "--header 'ANN-Train=%s' --files-list=%s",
    opts.rspamc, opts.connect, opts.nconns, opts.timeout,
    learn_type, fname)

  local result = assert(io.popen(rspamc_command))
  local output = result:read("*all")
  result:close()
  os.remove(fname)

  -- Count successful submissions
  local count = 0
  for line in output:gmatch("[^\n]+") do
    local ucl_parser = ucl.parser()
    local is_good, _ = ucl_parser:parse_string(line)
    if is_good then
      count = count + 1
    end
  end

  return count
end

-- Function to classify files and return results
local function classify_files(files, known_spam_files, known_ham_files)
  local fname = os.tmpname()
  list_to_file(files, fname)

  local settings_header = string.format('--header Settings="{symbols_enabled=[%s, %s]}"',
      opts.spam_symbol, opts.ham_symbol)
  local rspamc_command = string.format("%s %s --connect %s --compact -n %s -t %.3f --files-list=%s",
      opts.rspamc,
      settings_header,
      opts.connect,
      opts.nconns,
      opts.timeout, fname)
  local result = assert(io.popen(rspamc_command))
  local results = {}
  for line in result:lines() do
    local ucl_parser = ucl.parser()
    local is_good, err = ucl_parser:parse_string(line)
    if not is_good then
      rspamd_logger.errx("Parser error: %1", err)
    else
      local obj = ucl_parser:get_object()
      local file = obj.filename
      local symbols = obj.symbols or {}

      if symbols[opts.spam_symbol] then
        local score = symbols[opts.spam_symbol].score
        table.insert(results, { result = "spam", file = file, score = score })
        if known_ham_files[file] then
          rspamd_logger.message("FP: %s is classified as spam but is known ham", file)
        end
      elseif symbols[opts.ham_symbol] then
        local score = symbols[opts.ham_symbol].score
        table.insert(results, { result = "ham", file = file, score = score })
        if known_spam_files[file] then
          rspamd_logger.message("FN: %s is classified as ham but is known spam", file)
        end
      else
        -- No classification result
        table.insert(results, { result = "unknown", file = file })
      end
    end
  end

  result:close()
  os.remove(fname)

  return results
end

-- Function to evaluate classifier performance
local function evaluate_results(results, spam_label, ham_label,
                                known_spam_files, known_ham_files, total_cv_files, elapsed)
  local true_positives, false_positives, true_negatives, false_negatives = 0, 0, 0, 0
  local classified, unclassified = 0, 0

  for _, res in ipairs(results) do
    if res.result == spam_label then
      if known_spam_files[res.file] then
        true_positives = true_positives + 1
      elseif known_ham_files[res.file] then
        false_positives = false_positives + 1
      end
      classified = classified + 1
    elseif res.result == ham_label then
      if known_spam_files[res.file] then
        false_negatives = false_negatives + 1
      elseif known_ham_files[res.file] then
        true_negatives = true_negatives + 1
      end
      classified = classified + 1
    else
      unclassified = unclassified + 1
    end
  end

  print(string.format("\n%-20s %-10s", "Metric", "Value"))
  print(string.rep("-", 35))
  print(string.format("%-20s %-10d", "True Positives", true_positives))
  print(string.format("%-20s %-10d", "False Positives", false_positives))
  print(string.format("%-20s %-10d", "True Negatives", true_negatives))
  print(string.format("%-20s %-10d", "False Negatives", false_negatives))
  print(string.format("%-20s %-10d", "Unclassified", unclassified))

  if classified > 0 then
    local accuracy = (true_positives + true_negatives) / classified
    local precision = true_positives > 0 and true_positives / (true_positives + false_positives) or 0
    local recall = true_positives > 0 and true_positives / (true_positives + false_negatives) or 0
    local f1_score = (precision + recall) > 0 and 2 * (precision * recall) / (precision + recall) or 0

    print(string.format("%-20s %-10.4f", "Accuracy", accuracy))
    print(string.format("%-20s %-10.4f", "Precision", precision))
    print(string.format("%-20s %-10.4f", "Recall", recall))
    print(string.format("%-20s %-10.4f", "F1 Score", f1_score))
  end

  print(string.format("%-20s %-10.2f%%", "Classified", classified / total_cv_files * 100))
  print(string.format("%-20s %-10.2f", "Elapsed (sec)", elapsed))
end

local function handler(args)
  opts = parser:parse(args)

  local ham_directory = opts['ham']
  local spam_directory = opts['spam']
  local classifier_type = opts['classifier']

  if not ham_directory or not spam_directory then
    print("Error: Both --ham and --spam directories are required")
    os.exit(1)
  end

  -- Set default symbols based on classifier type
  if not opts.spam_symbol then
    if classifier_type == 'llm_embeddings' then
      opts.spam_symbol = 'NEURAL_SPAM'
    else
      opts.spam_symbol = 'BAYES_SPAM'
    end
  end
  if not opts.ham_symbol then
    if classifier_type == 'llm_embeddings' then
      opts.ham_symbol = 'NEURAL_HAM'
    else
      opts.ham_symbol = 'BAYES_HAM'
    end
  end

  -- Get all files
  local spam_files = get_files(spam_directory)
  local known_spam_files = lua_util.list_to_hash(spam_files)
  local ham_files = get_files(ham_directory)
  local known_ham_files = lua_util.list_to_hash(ham_files)

  print(string.format("Classifier: %s", classifier_type))
  print(string.format("Found %d spam files, %d ham files", #spam_files, #ham_files))

  -- Split files into training and cross-validation sets
  local train_spam, cv_spam = split_table(spam_files, opts.cv_fraction)
  local train_ham, cv_ham = split_table(ham_files, opts.cv_fraction)

  print(string.format("Split: %d/%d spam (train/test), %d/%d ham (train/test)",
      #train_spam, #cv_spam, #train_ham, #cv_ham))

  -- Training phase
  if not opts.no_learning then
    print("\n=== Training Phase ===")

    local t, train_spam_time, train_ham_time

    if classifier_type == 'llm_embeddings' then
      -- Neural/LLM training using ANN-Train header
      -- Interleave spam and ham submissions for balanced training
      print(string.format("Training %d spam + %d ham messages (interleaved)...", #train_spam, #train_ham))
      t = rspamd_util.get_time()

      -- Create interleaved list of {file, type} pairs
      local interleaved = {}
      local spam_idx, ham_idx = 1, 1
      while spam_idx <= #train_spam or ham_idx <= #train_ham do
        if spam_idx <= #train_spam then
          table.insert(interleaved, { file = train_spam[spam_idx], type = 'spam' })
          spam_idx = spam_idx + 1
        end
        if ham_idx <= #train_ham then
          table.insert(interleaved, { file = train_ham[ham_idx], type = 'ham' })
          ham_idx = ham_idx + 1
        end
      end

      -- Submit in batches, grouped by type for efficiency
      local batch_size = math.max(1, math.floor(#interleaved / 10))
      local spam_batch, ham_batch = {}, {}
      local spam_trained, ham_trained = 0, 0

      for i, item in ipairs(interleaved) do
        if item.type == 'spam' then
          table.insert(spam_batch, item.file)
        else
          table.insert(ham_batch, item.file)
        end

        -- Submit batches periodically
        if i % batch_size == 0 or i == #interleaved then
          if #spam_batch > 0 then
            spam_trained = spam_trained + train_neural(spam_batch, "spam")
            spam_batch = {}
          end
          if #ham_batch > 0 then
            ham_trained = ham_trained + train_neural(ham_batch, "ham")
            ham_batch = {}
          end
        end
      end

      train_spam_time = rspamd_util.get_time() - t
      train_ham_time = 0 -- Combined time
      print(string.format("  Submitted %d spam + %d ham samples in %.2f seconds",
        spam_trained, ham_trained, train_spam_time))

      -- Wait for neural network to train using ev_base sleep
      print(string.format("\nWaiting %d seconds for neural network training...", opts.train_wait))
      rspamadm_ev_base:sleep(opts.train_wait)
      print("Training wait complete.")
    else
      -- Bayes training using learn_spam/learn_ham
      print(string.format("Start learn spam, %d messages, %d connections", #train_spam, opts.nconns))
      t = rspamd_util.get_time()
      train_bayes(train_spam, "learn_spam")
      train_spam_time = rspamd_util.get_time() - t

      print(string.format("Start learn ham, %d messages, %d connections", #train_ham, opts.nconns))
      t = rspamd_util.get_time()
      train_bayes(train_ham, "learn_ham")
      train_ham_time = rspamd_util.get_time() - t

      print(string.format("Learning done: %d spam in %.2f sec, %d ham in %.2f sec",
          #train_spam, train_spam_time, #train_ham, train_ham_time))
    end
  else
    print("\nSkipping training phase (--no-learning)")
  end

  if opts.train_only then
    print("\nTraining only mode - skipping evaluation")
    return
  end

  -- Cross-validation phase
  print("\n=== Evaluation Phase ===")

  local cv_files = {}
  for _, file in ipairs(cv_spam) do
    table.insert(cv_files, file)
  end
  for _, file in ipairs(cv_ham) do
    table.insert(cv_files, file)
  end

  -- Shuffle cross-validation files
  cv_files = split_table(cv_files, 1)

  print(string.format("Classifying %d test messages...", #cv_files))

  -- Get classification results
  local t = rspamd_util.get_time()
  local results = classify_files(cv_files, known_spam_files, known_ham_files)
  local elapsed = rspamd_util.get_time() - t

  -- Evaluate results
  evaluate_results(results, "spam", "ham",
      known_spam_files,
      known_ham_files,
      #cv_files,
      elapsed)
end

return {
  name = 'classifiertest',
  aliases = { 'classifier_test' },
  handler = handler,
  description = parser._description
}