-- ev_base:add_timer: a callback that returns a number is called again after
-- that many seconds, and it runs for a timer added from another callback too

rspamd_config:register_symbol({
  name = 'EV_BASE_TIMER_TEST',
  score = 1.0,
  callback = function(task)
    local ev_base = task:get_ev_base()
    local fired = 0
    local nested = 0

    ev_base:add_timer(0.05, function()
      fired = fired + 1
      if fired == 1 then
        -- A timer added from a timer callback
        ev_base:add_timer(0.05, function()
          nested = nested + 1
        end)
      end
      if fired < 3 then
        return 0.05
      end
    end)

    -- Keeps the task alive until the timers above are done
    task:add_timer(0.6, function()
      task:insert_result('EV_BASE_TIMER', 1.0, 'fired=' .. tostring(fired),
          'nested=' .. tostring(nested))
    end)
  end
})
