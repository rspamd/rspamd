--[[ https://en.wikipedia.org/wiki/Normal_distribution ]]

-- The Box–Muller method
local function gaussian(mean, variance)
  local U = math.random()
  local V = math.random()
  return  math.sqrt(-2.0 * variance * math.log(U)) *
      math.cos(2.0 * math.pi * V) + mean
end

local function mean(t)
  local sum = 0
  local count = #t
  for i = 1, count do
    sum = sum + t[i]
  end
  return sum / count
end

local function std(t, mean)
  local squares = 0.0
  for i = 1, #t do
    local deviation = math.abs(mean - t[i])
    squares = squares + deviation * deviation
  end
  local variance = squares / #t
  return math.sqrt(variance)
end

local function do_the_call()
  local t = {}
  local mu = 34.0
  local sigma = 10.0

  for i = 1, 5 do
    table.insert(t, gaussian(mu, sigma))
  end

  return string.format("Got mean: %1.5f, mu: %1.5f\nstd deviance:%1.5f, expected: %1.5f",
    mean(t), mu,
    std(t, mu), math.sqrt(sigma))
end

math.randomseed(os.time())
return do_the_call
