/*
 * Copyright 2026 Vsevolod Stakhov
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
 * Test-only fake-clock helper. Drives ev_now() and timer firing in our
 * bundled libev (see ev.h: ev_set_fake_time_cb / ev_now_resync) so unit
 * tests can advance virtual time deterministically instead of sleeping.
 *
 * Process-global by design — the libev hook is process-wide. Use one
 * fake_clock per scope, and don't run two in parallel within the same
 * process.
 */

#ifndef RSPAMD_TEST_FAKE_TIME_HXX
#define RSPAMD_TEST_FAKE_TIME_HXX

#include "contrib/libev/ev.h"

namespace rspamd_test {

class fake_clock {
public:
	/* Install the fake clock at `start` seconds. The optional `loop` is
	 * resynced so its cached realtime/monotonic state matches the new
	 * source — required when the loop was created before the hook was
	 * installed (otherwise ev_now() returns garbage from interpolation).
	 */
	explicit fake_clock(double start = 1000.0, struct ev_loop *loop = nullptr)
		: now_(start), loop_(loop)
	{
		instance_ = this;
		ev_set_fake_time_cb(&fake_clock::read);
		if (loop_) {
			ev_now_resync(loop_);
		}
	}

	~fake_clock()
	{
		ev_set_fake_time_cb(nullptr);
		instance_ = nullptr;
		if (loop_) {
			ev_now_resync(loop_);
		}
	}

	fake_clock(const fake_clock &) = delete;
	fake_clock &operator=(const fake_clock &) = delete;

	/* Move time forward by `seconds`. Negative values intentionally
	 * unsupported: backward jumps would defeat libev's monotonic
	 * assumption and produce garbage timer behaviour.
	 */
	void advance(double seconds)
	{
		if (seconds < 0.0) {
			seconds = 0.0;
		}
		now_ += seconds;
		if (loop_) {
			ev_now_resync(loop_);
		}
	}

	void set(double t)
	{
		now_ = t;
		if (loop_) {
			ev_now_resync(loop_);
		}
	}

	double now() const
	{
		return now_;
	}

private:
	static double read()
	{
		return instance_ ? instance_->now_ : 0.0;
	}

	double now_;
	struct ev_loop *loop_;

	static inline fake_clock *instance_ = nullptr;
};

}// namespace rspamd_test

#endif /* RSPAMD_TEST_FAKE_TIME_HXX */
