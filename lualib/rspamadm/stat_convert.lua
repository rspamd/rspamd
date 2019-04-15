local lua_redis = require "lua_redis"
local stat_tools = require "lua_stat"
local ucl = require "ucl"
local logger = require "rspamd_logger"
local lua_util = require "lua_util"

return function (_, res)
  local redis_params = lua_redis.try_load_redis_servers(res.redis, nil)
  if res.expire then
    res.expire = lua_util.parse_time_interval(res.expire)
  end
  if not redis_params then
    logger.errx('cannot load redis server definition')

    return false
  end

  local sqlite_params = stat_tools.load_sqlite_config(res)

  if #sqlite_params == 0 then
    logger.errx('cannot load sqlite classifiers')
    return false
  end

  for _,cls in ipairs(sqlite_params) do
    if not stat_tools.convert_sqlite_to_redis(redis_params, cls.db_spam,
        cls.db_ham, cls.symbol_spam, cls.symbol_ham, cls.learn_cache, res.expire,
        res.reset_previous) then
      logger.errx('conversion failed')

      return false
    end
    logger.messagex('Converted classifier to the from sqlite to redis')
    logger.messagex('Suggested configuration:')
    logger.messagex(ucl.to_format(stat_tools.redis_classifier_from_sqlite(cls, res.expire),
      'config'))
  end
end
