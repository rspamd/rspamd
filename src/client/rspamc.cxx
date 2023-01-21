/*-
 * Copyright 2016 Vsevolod Stakhov
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include "config.h"
#include "libutil/util.h"
#include "libserver/http/http_connection.h"
#include "libserver/http/http_private.h"
#include "libserver/cfg_file.h"
#include "rspamdclient.h"
#include "unix-std.h"

#include <vector>
#include <string>
#include <optional>
#include <algorithm>
#include <functional>
#include <cstdint>
#include <cstdio>
#include <cmath>

#include "frozen/string.h"
#include "frozen/unordered_map.h"
#include "fmt/format.h"
#include "fmt/color.h"
#include "libutil/cxx/file_util.hxx"
#include "libutil/cxx/util.hxx"

#ifdef HAVE_SYS_WAIT_H

#include <sys/wait.h>

#endif

#define DEFAULT_PORT 11333
#define DEFAULT_CONTROL_PORT 11334

static const char *connect_str = "localhost";
static const char *password = nullptr;
static const char *ip = nullptr;
static const char *from = nullptr;
static const char *deliver_to = nullptr;
static const char **rcpts = nullptr;
static const char *user = nullptr;
static const char *helo = nullptr;
static const char *hostname = nullptr;
static const char *classifier = nullptr;
static const char *local_addr = nullptr;
static const char *execute = nullptr;
static const char *sort = nullptr;
static const char **http_headers = nullptr;
static const char **exclude_patterns = nullptr;
static int weight = 0;
static int flag = 0;
static const char *fuzzy_symbol = nullptr;
static const char *dictionary = nullptr;
static int max_requests = 8;
static double timeout = 10.0;
static gboolean pass_all;
static gboolean tty = FALSE;
static gboolean verbose = FALSE;
static gboolean print_commands = FALSE;
static gboolean humanreport = FALSE;
static gboolean json = FALSE;
static gboolean compact = FALSE;
static gboolean headers = FALSE;
static gboolean raw = FALSE;
static gboolean ucl_reply = FALSE;
static gboolean extended_urls = FALSE;
static gboolean mime_output = FALSE;
static gboolean empty_input = FALSE;
static gboolean compressed = FALSE;
static gboolean profile = FALSE;
static gboolean skip_images = FALSE;
static gboolean skip_attachments = FALSE;
static const char *pubkey = nullptr;
static const char *user_agent = "rspamc";

std::vector<GPid> children;
static GPatternSpec **exclude_compiled = nullptr;
static struct rspamd_http_context *http_ctx;

static gint retcode = EXIT_SUCCESS;

static gboolean rspamc_password_callback(const gchar *option_name,
										 const gchar *value,
										 gpointer data,
										 GError **error);

static GOptionEntry entries[] =
	{
		{"connect",          'h',  0,                          G_OPTION_ARG_STRING,       &connect_str,
																															  "Specify host and port",                                                    nullptr},
		{"password",         'P',  G_OPTION_FLAG_OPTIONAL_ARG, G_OPTION_ARG_CALLBACK,
																						  (void *) &rspamc_password_callback, "Specify control password",                                                 nullptr},
		{"classifier",       'c',  0,                          G_OPTION_ARG_STRING,       &classifier,
																															  "Classifier to learn spam or ham",                                          nullptr},
		{"weight",           'w',  0,                          G_OPTION_ARG_INT,          &weight,
																															  "Weight for fuzzy operations",                                              nullptr},
		{"flag",             'f',  0,                          G_OPTION_ARG_INT,          &flag,                              "Flag for fuzzy operations",
																																																		  nullptr},
		{"pass-all",         'p',  0,                          G_OPTION_ARG_NONE,         &pass_all,                          "Pass all filters",
																																																		  nullptr},
		{"verbose",          'v',  0,                          G_OPTION_ARG_NONE,         &verbose,                           "More verbose output",
																																																		  nullptr},
		{"ip",               'i',  0,                          G_OPTION_ARG_STRING,       &ip,
																															  "Emulate that message was received from specified ip address",
																																																		  nullptr},
		{"user",             'u',  0,                          G_OPTION_ARG_STRING,       &user,
																															  "Emulate that message was received from specified authenticated user",      nullptr},
		{"deliver",          'd',  0,                          G_OPTION_ARG_STRING,       &deliver_to,
																															  "Emulate that message is delivered to specified user (for LDA/statistics)", nullptr},
		{"from",             'F',  0,                          G_OPTION_ARG_STRING,       &from,
																															  "Emulate that message has specified SMTP FROM address",                     nullptr},
		{"rcpt",             'r',  0,                          G_OPTION_ARG_STRING_ARRAY, &rcpts,
																															  "Emulate that message has specified SMTP RCPT address",                     nullptr},
		{"helo",             0,    0,                          G_OPTION_ARG_STRING,       &helo,
																															  "Imitate SMTP HELO passing from MTA",                                       nullptr},
		{"hostname",         0,    0,                          G_OPTION_ARG_STRING,       &hostname,
																															  "Imitate hostname passing from MTA",                                        nullptr},
		{"timeout",          't',  0,                          G_OPTION_ARG_DOUBLE,       &timeout,
																															  "Time in seconds to wait for a reply",                                      nullptr},
		{"bind",             'b',  0,                          G_OPTION_ARG_STRING,       &local_addr,
																															  "Bind to specified ip address",                                             nullptr},
		{"commands",         0,    0,                          G_OPTION_ARG_NONE,         &print_commands,
																															  "List available commands",                                                  nullptr},
		{"human",            'R',  0,                          G_OPTION_ARG_NONE,         &humanreport,                       "Output human readable report",                                             nullptr},
		{"json",             'j',  0,                          G_OPTION_ARG_NONE,         &json,                              "Output json reply",                                                        nullptr},
		{"compact",          '\0', 0,                          G_OPTION_ARG_NONE,         &compact,                           "Output compact json reply",                                                nullptr},
		{"headers",          0,    0,                          G_OPTION_ARG_NONE,         &headers,                           "Output HTTP headers",
																																																		  nullptr},
		{"raw",              0,    0,                          G_OPTION_ARG_NONE,         &raw,                               "Input is a raw file, not an email file",
																																																		  nullptr},
		{"ucl",              0,    0,                          G_OPTION_ARG_NONE,         &ucl_reply,                         "Output ucl reply from rspamd",
																																																		  nullptr},
		{"max-requests",     'n',  0,                          G_OPTION_ARG_INT,          &max_requests,
																															  "Maximum count of parallel requests to rspamd",                             nullptr},
		{"extended-urls",    0,    0,                          G_OPTION_ARG_NONE,         &extended_urls,
																															  "Output urls in extended format",                                           nullptr},
		{"key",              0,    0,                          G_OPTION_ARG_STRING,       &pubkey,
																															  "Use specified pubkey to encrypt request",                                  nullptr},
		{"exec",             'e',  0,                          G_OPTION_ARG_STRING,       &execute,
																															  "Execute the specified command and pass output to it",                      nullptr},
		{"mime",             'm',  0,                          G_OPTION_ARG_NONE,         &mime_output,
																															  "Write mime body of message with headers instead of just a scan's result",  nullptr},
		{"header",           0,    0,                          G_OPTION_ARG_STRING_ARRAY, &http_headers,
																															  "Add custom HTTP header to query (can be repeated)",                        nullptr},
		{"exclude",          0,    0,                          G_OPTION_ARG_STRING_ARRAY, &exclude_patterns,
																															  "Exclude specific glob patterns in file names (can be repeated)",           nullptr},
		{"sort",             0,    0,                          G_OPTION_ARG_STRING,       &sort,
																															  "Sort output in a specific order (name, weight, frequency, hits)",          nullptr},
		{"empty",            'E',  0,                          G_OPTION_ARG_NONE,         &empty_input,
																															  "Allow empty input instead of reading from stdin",                          nullptr},
		{"fuzzy-symbol",     'S',  0,                          G_OPTION_ARG_STRING,       &fuzzy_symbol,
																															  "Learn the specified fuzzy symbol",                                         nullptr},
		{"compressed",       'z',  0,                          G_OPTION_ARG_NONE,         &compressed,
																															  "Enable zstd compression",                                                  nullptr},
		{"profile",          '\0', 0,                          G_OPTION_ARG_NONE,         &profile,
																															  "Profile symbols execution time",                                           nullptr},
		{"dictionary",       'D',  0,                          G_OPTION_ARG_FILENAME,     &dictionary,
																															  "Use dictionary to compress data",                                          nullptr},
		{"skip-images",      '\0', 0,                          G_OPTION_ARG_NONE,         &skip_images,
																															  "Skip images when learning/unlearning fuzzy",                               nullptr},
		{"skip-attachments", '\0', 0,                          G_OPTION_ARG_NONE,         &skip_attachments,
																															  "Skip attachments when learning/unlearning fuzzy",                          nullptr},
		{"user-agent",       'U',  0,                          G_OPTION_ARG_STRING,       &user_agent,
																															  "Use specific User-Agent instead of \"rspamc\"",                            nullptr},
		{nullptr,            0,    0,                          G_OPTION_ARG_NONE,         nullptr,                            nullptr,                                                                    nullptr}
	};

static void rspamc_symbols_output(FILE *out, ucl_object_t *obj);

static void rspamc_uptime_output(FILE *out, ucl_object_t *obj);

static void rspamc_counters_output(FILE *out, ucl_object_t *obj);

static void rspamc_stat_output(FILE *out, ucl_object_t *obj);

enum rspamc_command_type {
	RSPAMC_COMMAND_UNKNOWN = 0,
	RSPAMC_COMMAND_CHECK,
	RSPAMC_COMMAND_SYMBOLS,
	RSPAMC_COMMAND_LEARN_SPAM,
	RSPAMC_COMMAND_LEARN_HAM,
	RSPAMC_COMMAND_FUZZY_ADD,
	RSPAMC_COMMAND_FUZZY_DEL,
	RSPAMC_COMMAND_FUZZY_DELHASH,
	RSPAMC_COMMAND_STAT,
	RSPAMC_COMMAND_STAT_RESET,
	RSPAMC_COMMAND_COUNTERS,
	RSPAMC_COMMAND_UPTIME,
	RSPAMC_COMMAND_ADD_SYMBOL,
	RSPAMC_COMMAND_ADD_ACTION
};

struct rspamc_command {
	enum rspamc_command_type cmd;
	const char *name;
	const char *path;
	const char *description;
	gboolean is_controller;
	gboolean is_privileged;
	gboolean need_input;

	void (*command_output_func)(FILE *, ucl_object_t *obj);
};

static const constexpr auto rspamc_commands = rspamd::array_of(
	rspamc_command{
		.cmd = RSPAMC_COMMAND_SYMBOLS,
		.name = "symbols",
		.path = "checkv2",
		.description = "scan message and show symbols (default command)",
		.is_controller = FALSE,
		.is_privileged = FALSE,
		.need_input = TRUE,
		.command_output_func = rspamc_symbols_output
	},
	rspamc_command{
		.cmd = RSPAMC_COMMAND_LEARN_SPAM,
		.name = "learn_spam",
		.path = "learnspam",
		.description = "learn message as spam",
		.is_controller = TRUE,
		.is_privileged = TRUE,
		.need_input = TRUE,
		.command_output_func = nullptr
	},
	rspamc_command{
		.cmd = RSPAMC_COMMAND_LEARN_HAM,
		.name = "learn_ham",
		.path = "learnham",
		.description = "learn message as ham",
		.is_controller = TRUE,
		.is_privileged = TRUE,
		.need_input = TRUE,
		.command_output_func = nullptr
	},
	rspamc_command{
		.cmd = RSPAMC_COMMAND_FUZZY_ADD,
		.name = "fuzzy_add",
		.path = "fuzzyadd",
		.description =
		"add hashes from a message to the fuzzy storage (check -f and -w options for this command)",
		.is_controller = TRUE,
		.is_privileged = TRUE,
		.need_input = TRUE,
		.command_output_func = nullptr
	},
	rspamc_command{
		.cmd = RSPAMC_COMMAND_FUZZY_DEL,
		.name = "fuzzy_del",
		.path = "fuzzydel",
		.description =
		"delete hashes from a message from the fuzzy storage (check -f option for this command)",
		.is_controller = TRUE,
		.is_privileged = TRUE,
		.need_input = TRUE,
		.command_output_func = nullptr
	},
	rspamc_command{
		.cmd = RSPAMC_COMMAND_FUZZY_DELHASH,
		.name = "fuzzy_delhash",
		.path = "fuzzydelhash",
		.description =
		"delete a hash from fuzzy storage (check -f option for this command)",
		.is_controller = TRUE,
		.is_privileged = TRUE,
		.need_input = FALSE,
		.command_output_func = nullptr
	},
	rspamc_command{
		.cmd = RSPAMC_COMMAND_STAT,
		.name = "stat",
		.path = "stat",
		.description = "show rspamd statistics",
		.is_controller = TRUE,
		.is_privileged = FALSE,
		.need_input = FALSE,
		.command_output_func = rspamc_stat_output,
	},
	rspamc_command{
		.cmd = RSPAMC_COMMAND_STAT_RESET,
		.name = "stat_reset",
		.path = "statreset",
		.description = "show and reset rspamd statistics (useful for graphs)",
		.is_controller = TRUE,
		.is_privileged = TRUE,
		.need_input = FALSE,
		.command_output_func = rspamc_stat_output
	},
	rspamc_command{
		.cmd = RSPAMC_COMMAND_COUNTERS,
		.name = "counters",
		.path = "counters",
		.description = "display rspamd symbols statistics",
		.is_controller = TRUE,
		.is_privileged = FALSE,
		.need_input = FALSE,
		.command_output_func = rspamc_counters_output
	},
	rspamc_command{
		.cmd = RSPAMC_COMMAND_UPTIME,
		.name = "uptime",
		.path = "auth",
		.description = "show rspamd uptime",
		.is_controller = TRUE,
		.is_privileged = FALSE,
		.need_input = FALSE,
		.command_output_func = rspamc_uptime_output
	},
	rspamc_command{
		.cmd = RSPAMC_COMMAND_ADD_SYMBOL,
		.name = "add_symbol",
		.path = "addsymbol",
		.description = "add or modify symbol settings in rspamd",
		.is_controller = TRUE,
		.is_privileged = TRUE,
		.need_input = FALSE,
		.command_output_func = nullptr
	},
	rspamc_command{
		.cmd = RSPAMC_COMMAND_ADD_ACTION,
		.name = "add_action",
		.path = "addaction",
		.description = "add or modify action settings",
		.is_controller = TRUE,
		.is_privileged = TRUE,
		.need_input = FALSE,
		.command_output_func = nullptr
	}
);

struct rspamc_callback_data {
	struct rspamc_command cmd;
	std::string filename;
};

template<typename T>
static constexpr auto emphasis_argument(const T &arg) -> auto {
	if (tty) {
		return fmt::format(fmt::emphasis::bold, "{}", arg);
	}

	return fmt::format("{}", arg);
}

template<typename T, typename std::enable_if_t<std::is_floating_point_v<T>, bool> = false>
static constexpr auto emphasis_argument(const T &arg, int precision) -> auto {
	if (tty) {
		return fmt::format(fmt::emphasis::bold, "{:.{}f}", arg, precision);
	}

	return fmt::format("{:.{}f}", arg, precision);
}

using sort_lambda = std::function<int(const ucl_object_t *, const ucl_object_t *)>;
static const auto sort_map = frozen::make_unordered_map<frozen::string, sort_lambda>({
	{"name", [](const ucl_object_t *o1, const ucl_object_t *o2) -> int {
		const auto *elt1 = ucl_object_lookup(o1, "symbol");
		const auto *elt2 = ucl_object_lookup(o2, "symbol");

		if (elt1 && elt2) {
			return strcmp(ucl_object_tostring(elt1),
				ucl_object_tostring(elt2));
		}
		else if (ucl_object_key(o1) != nullptr && ucl_object_key(o2) != nullptr) {
			return strcmp(ucl_object_key(o1),
				ucl_object_key(o2));
		}
		return 0;
	}},
	{"weight", [](const ucl_object_t *o1, const ucl_object_t *o2) -> int {
		const auto *elt1 = ucl_object_lookup(o1, "weight");
		const auto *elt2 = ucl_object_lookup(o2, "weight");

		if (elt1 && elt2) {
			return ucl_object_todouble(elt2) * 1000.0 - ucl_object_todouble(elt1) * 1000.0;
		}
		return 0;
	}},
	{"score", [](const ucl_object_t *o1, const ucl_object_t *o2) -> int {
		const auto *elt1 = ucl_object_lookup(o1, "score");
		const auto *elt2 = ucl_object_lookup(o2, "score");

		if (elt1 && elt2) {
			return std::fabs(ucl_object_todouble(elt2)) * 1000.0 -
				   std::fabs(ucl_object_todouble(elt1)) * 1000.0;
		}
		return 0;
	}},
	{"time", [](const ucl_object_t *o1, const ucl_object_t *o2) -> int {
		const auto *elt1 = ucl_object_lookup(o1, "time");
		const auto *elt2 = ucl_object_lookup(o2, "time");

		if (elt1 && elt2) {
			return ucl_object_todouble(elt2) * 1000.0 - ucl_object_todouble(elt1) * 1000.0;
		}
		return 0;
	}},
	{"frequency", [](const ucl_object_t *o1, const ucl_object_t *o2) -> int {
		const auto *elt1 = ucl_object_lookup(o1, "frequency");
		const auto *elt2 = ucl_object_lookup(o2, "frequency");

		if (elt1 && elt2) {
			return ucl_object_todouble(elt2) * 1000.0 - ucl_object_todouble(elt1) * 1000.0;
		}
		return 0;
	}},
	{"hits", [](const ucl_object_t *o1, const ucl_object_t *o2) -> int {
		const auto *elt1 = ucl_object_lookup(o1, "hits");
		const auto *elt2 = ucl_object_lookup(o2, "hits");

		if (elt1 && elt2) {
			return ucl_object_toint(elt2) - ucl_object_toint(elt1);
		}
		return 0;
	}},
});

/* TODO: remove once migrate to C++20 standard */
static constexpr auto
sv_ends_with(std::string_view inp, std::string_view suffix) -> bool {
	return inp.size() >= suffix.size() && inp.compare(inp.size() - suffix.size(), std::string_view::npos, suffix) == 0;
}

template<typename T>
auto sort_ucl_container_with_default(T &cont, const char *default_sort,
									 typename std::enable_if<std::is_same_v<typename T::value_type, const ucl_object_t *>>::type* = 0) -> void
{
	auto real_sort = sort ? sort : default_sort;
	if (real_sort) {
		auto sort_view = std::string_view{real_sort};
		auto inverse = false;

		if (sv_ends_with(sort_view, ":asc")) {
			inverse = true;
			sort_view = std::string_view{sort, strlen(sort) - sizeof(":asc") + 1};
		}

		const auto sort_functor = sort_map.find(sort_view);
		if (sort_functor != sort_map.end()) {
			std::stable_sort(std::begin(cont), std::end(cont),
				[&](const ucl_object_t *o1, const ucl_object_t *o2) -> int {
					auto order = sort_functor->second(o1, o2);

					return inverse ? order > 0 : order < 0;
				});
		}
	}
}


static gboolean
rspamc_password_callback(const gchar *option_name,
						 const gchar *value,
						 gpointer data,
						 GError **error)
{
	// Some efforts to keep password erased
	static std::vector<char, rspamd::secure_mem_allocator<char>> processed_passwd;
	processed_passwd.clear();

	if (value != nullptr) {
		std::string_view value_view{value};
		if (value_view[0] == '/' || value_view[0] == '.') {
			/* Try to open file */
			auto locked_mmap = rspamd::util::raii_mmaped_file::mmap_shared(value, O_RDONLY, PROT_READ);

			if (!locked_mmap.has_value() || locked_mmap.value().get_size() == 0) {
				/* Just use it as a string */
				processed_passwd.assign(std::begin(value_view), std::end(value_view));
				processed_passwd.push_back('\0');
			}
			else {
				/* Strip trailing spaces */
				auto *map = (char *) locked_mmap.value().get_map();
				auto *end = map + locked_mmap.value().get_size() - 1;

				while (g_ascii_isspace(*end) && end > map) {
					end--;
				}

				end++;
				value_view = std::string_view{map, static_cast<std::size_t>(end - map + 1)};
				processed_passwd.assign(std::begin(value_view), std::end(value_view));
				processed_passwd.push_back('\0');
			}
		}
		else {
			processed_passwd.assign(std::begin(value_view), std::end(value_view));
			processed_passwd.push_back('\0');
		}
	}
	else {
		/* Read password from console */
		auto plen = 8192;
		processed_passwd.resize(plen, '\0');
		plen = rspamd_read_passphrase(processed_passwd.data(), plen, 0, nullptr);
		if (plen == 0) {
			fmt::print(stderr, "Invalid password\n");
			exit(EXIT_FAILURE);
		}
		processed_passwd.resize(plen);
		processed_passwd.push_back('\0');
	}

	password = processed_passwd.data();

	return TRUE;
}

/*
 * Parse command line
 */
static void
read_cmd_line(gint *argc, gchar ***argv)
{
	GError *error = nullptr;
	GOptionContext *context;

	/* Prepare parser */
	context = g_option_context_new("- run rspamc client");
	g_option_context_set_summary(context,
		"Summary:\n  Rspamd client version " RVERSION "\n  Release id: " RID);
	g_option_context_add_main_entries(context, entries, nullptr);

	/* Parse options */
	if (!g_option_context_parse(context, argc, argv, &error)) {
		fmt::print(stderr, "option parsing failed: {}\n", error->message);
		g_option_context_free(context);
		exit(EXIT_FAILURE);
	}

	if (json || compact) {
		ucl_reply = TRUE;
	}
	/* Argc and argv are shifted after this function */
	g_option_context_free(context);
}

static auto
add_client_header(GQueue *opts, const char *hn, const char *hv) -> void
{
	g_assert(hn != nullptr);
	g_assert(hv != nullptr);
	auto *nhdr = g_new(rspamd_http_client_header, 1);
	nhdr->name = g_strdup(hn);
	nhdr->value = g_strdup(hv);
	g_queue_push_tail(opts, (void *) nhdr);
}

static auto
add_client_header(GQueue *opts, std::string_view hn, std::string_view hv) -> void
{
	auto *nhdr = g_new(rspamd_http_client_header, 1);
	nhdr->name = g_new(char, hn.size() + 1);
	rspamd_strlcpy(nhdr->name, hn.data(), hn.size() + 1);
	nhdr->value = g_new(char, hv.size() + 1);
	rspamd_strlcpy(nhdr->value, hv.data(), hv.size() + 1);
	g_queue_push_tail(opts, (void *) nhdr);
}

static auto
rspamd_string_tolower(const char *inp) -> std::string
{
	std::string s{inp};
	std::transform(std::begin(s), std::end(s), std::begin(s),
		[](unsigned char c) { return std::tolower(c); });
	return s;
}

static auto
rspamd_action_from_str_rspamc(const char *data) -> std::optional<int>
{
	static constexpr const auto str_map = frozen::make_unordered_map<frozen::string, int>({
		{"reject",          METRIC_ACTION_REJECT},
		{"greylist",        METRIC_ACTION_GREYLIST},
		{"add_header",      METRIC_ACTION_ADD_HEADER},
		{"add header",      METRIC_ACTION_ADD_HEADER},
		{"rewrite_subject", METRIC_ACTION_REWRITE_SUBJECT},
		{"rewrite subject", METRIC_ACTION_REWRITE_SUBJECT},
		{"soft_reject",     METRIC_ACTION_SOFT_REJECT},
		{"soft reject",     METRIC_ACTION_SOFT_REJECT},
		{"no_action",       METRIC_ACTION_NOACTION},
		{"no action",       METRIC_ACTION_NOACTION},
	});

	auto st_lower = rspamd_string_tolower(data);
	return rspamd::find_map(str_map, std::string_view{st_lower});
}

/*
 * Check rspamc command from string (used for arguments parsing)
 */
static auto
check_rspamc_command(const char *cmd) -> std::optional<rspamc_command>
{
	static constexpr const auto str_map = frozen::make_unordered_map<frozen::string, int>({
		{"symbols",       RSPAMC_COMMAND_SYMBOLS},
		{"check",         RSPAMC_COMMAND_SYMBOLS},
		{"report",        RSPAMC_COMMAND_SYMBOLS},
		{"learn_spam",    RSPAMC_COMMAND_LEARN_SPAM},
		{"learn_ham",     RSPAMC_COMMAND_LEARN_HAM},
		{"fuzzy_add",     RSPAMC_COMMAND_FUZZY_ADD},
		{"fuzzy_del",     RSPAMC_COMMAND_FUZZY_DEL},
		{"fuzzy_delhash", RSPAMC_COMMAND_FUZZY_DELHASH},
		{"stat",          RSPAMC_COMMAND_STAT},
		{"stat_reset",    RSPAMC_COMMAND_STAT_RESET},
		{"counters",      RSPAMC_COMMAND_COUNTERS},
		{"uptime",        RSPAMC_COMMAND_UPTIME},
	});

	std::string cmd_lc = rspamd_string_tolower(cmd);
	auto ct = rspamd::find_map(str_map, std::string_view{cmd_lc});

	auto elt_it = std::find_if(rspamc_commands.begin(), rspamc_commands.end(), [&](const auto &item) {
		return item.cmd == ct;
	});

	if (elt_it != std::end(rspamc_commands)) {
		return *elt_it;
	}

	return std::nullopt;
}

static void
print_commands_list()
{
	guint cmd_len = 0;

	fmt::print(stdout, "Rspamc commands summary:\n");

	for (const auto &cmd: rspamc_commands) {
		auto clen = strlen(cmd.name);

		if (clen > cmd_len) {
			cmd_len = clen;
		}
	}

	for (const auto &cmd: rspamc_commands) {
		fmt::print(stdout,
			"  {:>{}} ({:7}{:1})\t{}\n",
			cmd.name,
			cmd_len,
			cmd.is_controller ? "control" : "normal",
			cmd.is_privileged ? "*" : "",
			cmd.description);
	}

	fmt::print(stdout,
		"\n* is for privileged commands that may need password (see -P option)\n");
	fmt::print(stdout,
		"control commands use port 11334 while normal use 11333 by default (see -h option)\n");
}

static void
add_options(GQueue *opts)
{
	std::string flagbuf;

	if (ip != nullptr) {
		rspamd_inet_addr_t *addr = nullptr;

		if (!rspamd_parse_inet_address(&addr, ip, strlen(ip),
			RSPAMD_INET_ADDRESS_PARSE_DEFAULT)) {
			/* Try to resolve */
			struct addrinfo hints, *res, *cur;
			int r;

			memset(&hints, 0, sizeof(hints));
			hints.ai_socktype = SOCK_STREAM; /* Type of the socket */
#ifdef AI_IDN
			hints.ai_flags = AI_NUMERICSERV|AI_IDN;
#else
			hints.ai_flags = AI_NUMERICSERV;
#endif
			hints.ai_family = AF_UNSPEC;

			if ((r = getaddrinfo(ip, "25", &hints, &res)) == 0) {

				cur = res;
				while (cur) {
					addr = rspamd_inet_address_from_sa(cur->ai_addr,
						cur->ai_addrlen);

					if (addr != nullptr) {
						ip = g_strdup(rspamd_inet_address_to_string(addr));
						rspamd_inet_address_free(addr);
						break;
					}

					cur = cur->ai_next;
				}

				freeaddrinfo(res);
			}
			else {
				fmt::print(stderr, "address resolution for {} failed: {}\n",
					ip,
					gai_strerror(r));
			}
		}
		else {
			rspamd_inet_address_free(addr);
		}

		add_client_header(opts, "Ip", ip);
	}

	if (from != nullptr) {
		add_client_header(opts, "From", from);
	}

	if (user != nullptr) {
		add_client_header(opts, "User", user);
	}

	if (rcpts != nullptr) {
		for (auto *rcpt = rcpts; *rcpt != nullptr; rcpt++) {
			add_client_header(opts, "Rcpt", *rcpt);
		}
	}

	if (deliver_to != nullptr) {
		add_client_header(opts, "Deliver-To", deliver_to);
	}

	if (helo != nullptr) {
		add_client_header(opts, "Helo", helo);
	}

	if (hostname != nullptr) {
		add_client_header(opts, "Hostname", hostname);
	}

	if (password != nullptr) {
		add_client_header(opts, "Password", password);
	}

	if (pass_all) {
		flagbuf += "pass_all,";
	}

	if (raw) {
		add_client_header(opts, "Raw", "yes");
	}

	if (classifier) {
		add_client_header(opts, "Classifier", classifier);
	}

	if (weight != 0) {
		auto nstr = fmt::format("{}", weight);
		add_client_header(opts, "Weight", nstr.c_str());
	}

	if (fuzzy_symbol != nullptr) {
		add_client_header(opts, "Symbol", fuzzy_symbol);
	}

	if (flag != 0) {
		auto nstr = fmt::format("{}", flag);
		add_client_header(opts, "Flag", nstr.c_str());
	}

	if (extended_urls) {
		add_client_header(opts, "URL-Format", "extended");
	}

	if (profile) {
		flagbuf += "profile,";
	}

	flagbuf += "body_block,";

	if (skip_images) {
		add_client_header(opts, "Skip-Images", "true");
	}

	if (skip_attachments) {
		add_client_header(opts, "Skip-Attachments", "true");
	}

	auto hdr = http_headers;

	while (hdr != nullptr && *hdr != nullptr) {
		std::string_view hdr_view{*hdr};

		auto delim_pos = std::find_if(std::begin(hdr_view), std::end(hdr_view), [](auto c) {
			return c == ':' || c == '=';
		});
		if (delim_pos == std::end(hdr_view)) {
			/* Just a header name with no value */
			add_client_header(opts, *hdr, "");
		}
		else {
			add_client_header(opts,
				hdr_view.substr(0, std::distance(std::begin(hdr_view), delim_pos)),
				hdr_view.substr(std::distance(std::begin(hdr_view), delim_pos) + 1));
		}

		hdr++;
	}

	if (!flagbuf.empty()) {
		if (flagbuf.back() == ',') {
			flagbuf.pop_back();
		}

		add_client_header(opts, "Flags", flagbuf.c_str());
	}
}

static void
rspamc_symbol_human_output(FILE *out, const ucl_object_t *obj)
{
	auto first = true;
	auto score = 0.0;
	const char *desc = nullptr;

	const auto *key = ucl_object_key(obj);
	const auto *val = ucl_object_lookup(obj, "score");
	if (val != nullptr) {
		score = ucl_object_todouble(val);
	}

	val = ucl_object_lookup(obj, "description");
	if (val != nullptr) {
		desc = ucl_object_tostring(val);
	}

	auto line = fmt::format("{:>4.1f} {:<22} ", score, key);
	if (desc != nullptr) {
		line += desc;
	}

	val = ucl_object_lookup(obj, "options");
	if (val != nullptr && ucl_object_type(val) == UCL_ARRAY) {
		ucl_object_iter_t it = nullptr;
		const ucl_object_t *cur;

		line += fmt::format("{}[", desc == nullptr ? "" : " ");

		while ((cur = ucl_object_iterate (val, &it, true)) != nullptr) {
			if (first) {
				line += fmt::format("{}", ucl_object_tostring(cur));
				first = false;
			}
			else {
				line += fmt::format(",{}", ucl_object_tostring(cur));
			}
		}
		line += ']';
	}
	else if (desc == nullptr) {
		line += '\n';
	}

	auto print_indented_line = [&](size_t maxlen, size_t indent) {
		if (maxlen < 1 || maxlen < indent) {
			return;
		}
		for (size_t pos = 0; pos < line.size(); ) {
			auto s = line.substr(pos, pos ? (maxlen-indent) : maxlen);
			if (indent && pos) {
				fmt::print(out, "{:>{}}", " ", indent);
			}
			fmt::print(out, "{}\n", s);
			pos += s.size();
		}
	};

	print_indented_line(78, 28);
}

static void
rspamc_symbol_output(FILE *out, const ucl_object_t *obj)
{
	auto first = true;

	fmt::print(out, "Symbol: {} ", ucl_object_key(obj));
	const auto *val = ucl_object_lookup(obj, "score");

	if (val != nullptr) {
		fmt::print(out, "({:.2f})", ucl_object_todouble(val));
	}
	val = ucl_object_lookup(obj, "options");
	if (val != nullptr && ucl_object_type(val) == UCL_ARRAY) {
		ucl_object_iter_t it = nullptr;
		const ucl_object_t *cur;

		fmt::print(out, "[");

		while ((cur = ucl_object_iterate (val, &it, true)) != nullptr) {
			if (first) {
				fmt::print(out, "{}", ucl_object_tostring(cur));
				first = false;
			}
			else {
				fmt::print(out, ", {}", ucl_object_tostring(cur));
			}
		}
		fmt::print(out, "]");
	}
	fmt::print(out, "\n");
}

static void
rspamc_metric_output(FILE *out, const ucl_object_t *obj)
{
	int got_scores = 0;
	bool is_spam = false, is_skipped = false;
	double score = 0, required_score = 0, greylist_score =0, addheader_score = 0;

	auto print_protocol_string = [&](const char *ucl_name, const char *output_message) {
		auto *elt = ucl_object_lookup(obj, ucl_name);
		if (elt) {
			if (humanreport) {
				fmt::print(out, ",{}={}", output_message, emphasis_argument(ucl_object_tostring(elt)));
			}
			else {
				fmt::print(out, "{}: {}\n", output_message, emphasis_argument(ucl_object_tostring(elt)));
			}
		}
	};

	if (!humanreport) {
		fmt::print(out, "[Metric: default]\n");
	}

	const auto *elt = ucl_object_lookup(obj, "required_score");
	if (elt) {
		required_score = ucl_object_todouble(elt);
		got_scores++;
	}

	elt = ucl_object_lookup(obj, "score");
	if (elt) {
		score = ucl_object_todouble(elt);
		got_scores++;
	}

	/* XXX: greylist_score is not yet in checkv2 */
	elt = ucl_object_lookup(obj, "greylist_score");
	if (elt) {
		greylist_score = ucl_object_todouble(elt);
	}

	/* XXX: addheader_score is not yet in checkv2 */
	elt = ucl_object_lookup(obj, "addheader_score");
	if (elt) {
		addheader_score = ucl_object_todouble(elt);
	}

	if (humanreport) {
		fmt::print(out,
			"{}/{}/{}/{}",
			emphasis_argument(score, 2),
			emphasis_argument(greylist_score, 2),
			emphasis_argument(addheader_score, 2),
			emphasis_argument(required_score, 2));
	}

	elt = ucl_object_lookup(obj, "action");
	if (elt) {
		auto act = rspamd_action_from_str_rspamc(ucl_object_tostring(elt));

		if (act.has_value()) {
			if (!tty) {
				if (humanreport) {
					fmt::print(out, ",action={}:{}", act.value(), ucl_object_tostring(elt));
				}
				else {
					print_protocol_string("action", "Action");
				}
			}
			else {
				/* Colorize action type */
				std::string colorized_action;
				switch (act.value()) {
				case METRIC_ACTION_REJECT:
					colorized_action = fmt::format(fmt::fg(fmt::color::red), "reject");
					break;
				case METRIC_ACTION_NOACTION:
					colorized_action = fmt::format(fmt::fg(fmt::color::green), "no action");
					break;
				case METRIC_ACTION_ADD_HEADER:
				case METRIC_ACTION_REWRITE_SUBJECT:
					colorized_action = fmt::format(fmt::fg(fmt::color::orange), ucl_object_tostring(elt));
					break;
				case METRIC_ACTION_GREYLIST:
				case METRIC_ACTION_SOFT_REJECT:
					colorized_action = fmt::format(fmt::fg(fmt::color::gray), ucl_object_tostring(elt));
					break;
				default:
					colorized_action = fmt::format(fmt::emphasis::bold, ucl_object_tostring(elt));
					break;
				}

				if (humanreport) {
					fmt::print(out, ",action={}:{}", act.value(), colorized_action);
				}
				else {
					fmt::print(out, "Action: {}\n", colorized_action);
				}
			}

			is_spam = act.value() < METRIC_ACTION_GREYLIST ? true : false;
			if (!humanreport) {
				fmt::print(out, "Spam: {}\n", is_spam ?	"true" : "false");
			}
		}
		else {
			if (humanreport) {
				fmt::print(out, ",action={}:{}", METRIC_ACTION_NOACTION, ucl_object_tostring(elt));
			}
			else {
				print_protocol_string("action", "Action");
			}
		}
	}

	if (!humanreport) {
		print_protocol_string("subject", "Subject");
	}

	if (humanreport) {
		/* XXX: why checkv2 does not provide "is_spam"? */
		elt = ucl_object_lookup(obj, "is_spam");
		if (elt) {
			is_spam = ucl_object_toboolean(elt);
		}

		elt = ucl_object_lookup(obj, "is_skipped");
		if (elt) {
			is_skipped = ucl_object_toboolean(elt);
		}

		fmt::print(out, ",spam={},skipped={}\n", is_spam ? 1 : 0, is_skipped ? 1 : 0);
	}
	else if (got_scores == 2) {
		fmt::print(out,
			"Score: {} / {}\n",
			emphasis_argument(score, 2),
			emphasis_argument(required_score, 2));
	}

	if (humanreport) {
		fmt::print(out, "Content analysis details:   ({} points, {} required)\n\n",
			emphasis_argument(score, 2),
			emphasis_argument(required_score, 2));
		fmt::print(out, " pts rule name              description\n");
		fmt::print(out, "---- ---------------------- --------------------------------------------------\n");
	}

	elt = ucl_object_lookup(obj, "symbols");

	if (elt) {
		std::vector<const ucl_object_t *> symbols;
		ucl_object_iter_t it = nullptr;
		const ucl_object_t *cur;

		while ((cur = ucl_object_iterate (elt, &it, true)) != nullptr) {
			symbols.push_back(cur);
		}

		sort_ucl_container_with_default(symbols, "name");

		for (const auto *sym_obj : symbols) {
			humanreport ? rspamc_symbol_human_output(out, sym_obj) : rspamc_symbol_output(out, sym_obj);
		}
	}
	if (humanreport) {
		fmt::print(out, "\n");
	}
}

static void
rspamc_profile_output(FILE *out, const ucl_object_t *obj)
{
	ucl_object_iter_t it = nullptr;
	const ucl_object_t *cur;

	std::vector<const ucl_object_t *> ar;

	while ((cur = ucl_object_iterate (obj, &it, true)) != nullptr) {
		ar.push_back(cur);
	}
	std::stable_sort(std::begin(ar), std::end(ar),
		[](const ucl_object_t *u1, const ucl_object_t *u2) -> int {
			return ucl_object_compare(u1, u2);
		});

	for (const auto *cur_elt : ar) {
		fmt::print(out, "\t{}: {:3} usec\n",
			ucl_object_key(cur_elt), ucl_object_todouble(cur_elt));
	}
}

static void
rspamc_symbols_output(FILE *out, ucl_object_t *obj)
{
	rspamc_metric_output(out, obj);

	auto print_protocol_string = [&](const char *ucl_name, const char *output_message) {
		auto *elt = ucl_object_lookup(obj, ucl_name);
		if (elt) {
			fmt::print(out, "{}: {}\n", output_message, ucl_object_tostring(elt));
		}
	};

	if (!humanreport) {
		print_protocol_string("message-id", "Message-ID");
		print_protocol_string("queue-id", "Queue-ID");
	}

	const auto *elt = ucl_object_lookup(obj, "urls");

	if (elt) {
		char *emitted;

		if (!extended_urls || compact) {
			emitted = (char *)ucl_object_emit(elt, UCL_EMIT_JSON_COMPACT);
		}
		else {
			emitted = (char *)ucl_object_emit(elt, UCL_EMIT_JSON);
		}

		if (humanreport) {
			if (emitted && strcmp(emitted, "[]") != 0) {
				auto folded_line = rspamd_header_value_fold("Domains found: ", sizeof("Domains found: ") - 1,
					emitted, strlen(emitted), 78,
					RSPAMD_TASK_NEWLINES_LF, nullptr);
				fmt::print("Domains found: {}\n", folded_line->str);
				g_string_free(folded_line, true);
			}
		}
		else {
			fmt::print(out, "Urls: {}\n", emitted);
		}
		free(emitted);
	}

	elt = ucl_object_lookup(obj, "emails");

	if (elt) {
		char *emitted;
		if (!extended_urls || compact) {
			emitted = (char *)ucl_object_emit(elt, UCL_EMIT_JSON_COMPACT);
		}
		else {
			emitted = (char *)ucl_object_emit(elt, UCL_EMIT_JSON);
		}

		if (humanreport) {
			if (emitted && strcmp(emitted, "[]") != 0) {
				auto folded_line = rspamd_header_value_fold("Emails found: ", sizeof("Emails found: ") - 1,
					emitted, strlen(emitted), 78,
					RSPAMD_TASK_NEWLINES_LF, nullptr);
				fmt::print("Emails found: {}\n", folded_line->str);
				g_string_free(folded_line, true);
			}
		}
		else {
			fmt::print(out, "Emails: {}\n", emitted);
		}
		free(emitted);
	}

	print_protocol_string("error", "Scan error");
	if (humanreport) {
		return;
	}

	elt = ucl_object_lookup(obj, "messages");
	if (elt && elt->type == UCL_OBJECT) {
		ucl_object_iter_t mit = nullptr;
		const ucl_object_t *cmesg;

		while ((cmesg = ucl_object_iterate (elt, &mit, true)) != nullptr) {
			if (ucl_object_type(cmesg) == UCL_STRING) {
				fmt::print(out, "Message - {}: {}\n",
					ucl_object_key(cmesg), ucl_object_tostring(cmesg));
			} else {
				char *rendered_message;
				rendered_message = (char *)ucl_object_emit(cmesg, UCL_EMIT_JSON_COMPACT);
				fmt::print(out, "Message - {}: {:.60}\n",
					ucl_object_key(cmesg), rendered_message);
				free(rendered_message);
			}
		}
	}

	elt = ucl_object_lookup(obj, "dkim-signature");
	if (elt && elt->type == UCL_STRING) {
		fmt::print(out, "DKIM-Signature: {}\n", ucl_object_tostring(elt));
	}
	else if (elt && elt->type == UCL_ARRAY) {
		ucl_object_iter_t it = nullptr;
		const ucl_object_t *cur;

		while ((cur = ucl_object_iterate (elt, &it, true)) != nullptr) {
			fmt::print(out, "DKIM-Signature: {}\n", ucl_object_tostring(cur));
		}
	}

	elt = ucl_object_lookup(obj, "profile");

	if (elt) {
		fmt::print(out, "Profile data:\n");
		rspamc_profile_output(out, elt);
	}
}

static void
rspamc_uptime_output(FILE *out, ucl_object_t *obj)
{
	int64_t seconds, days, hours, minutes;

	const auto *elt = ucl_object_lookup(obj, "version");
	if (elt != nullptr) {
		fmt::print(out, "Rspamd version: %s\n", ucl_object_tostring(
			elt));
	}

	elt = ucl_object_lookup(obj, "uptime");
	if (elt != nullptr) {
		fmt::print("Uptime: ");
		seconds = ucl_object_toint(elt);
		if (seconds >= 2 * 3600) {
			days = seconds / 86400;
			hours = seconds / 3600 - days * 24;
			minutes = seconds / 60 - hours * 60 - days * 1440;
			fmt::print("{} day{} {} hour{} {} minute{}\n", days,
				days > 1 ? "s" : "", hours, hours > 1 ? "s" : "",
				minutes, minutes > 1 ? "s" : "");
		}
			/* If uptime is less than 1 minute print only seconds */
		else if (seconds / 60 == 0) {
			fmt::print("{} second%s\n", seconds,
				(gint) seconds > 1 ? "s" : "");
		}
			/* Else print the minutes and seconds. */
		else {
			hours = seconds / 3600;
			minutes = seconds / 60 - hours * 60;
			seconds -= hours * 3600 + minutes * 60;
			fmt::print("{} hour {} minute{} {} second{}\n", hours,
				minutes, minutes > 1 ? "s" : "",
				seconds, seconds > 1 ? "s" : "");
		}
	}
}

static void
rspamc_counters_output(FILE *out, ucl_object_t *obj)
{
	if (obj->type != UCL_ARRAY) {
		fmt::print(out, "Bad output\n");
		return;
	}

	std::vector<const ucl_object_t *> counters_vec;
	auto max_len = sizeof("Symbol") - 1;

	{
		ucl_object_iter_t iter = nullptr;
		const ucl_object_t *cur;

		while ((cur = ucl_object_iterate (obj, &iter, true)) != nullptr) {
			const auto *sym = ucl_object_lookup(cur, "symbol");
			if (sym != nullptr) {
				if (sym->len > max_len) {
					max_len = sym->len;
				}
			}
			counters_vec.push_back(cur);
		}
	}

	sort_ucl_container_with_default(counters_vec, "name");

	char dash_buf[82], sym_buf[82];
	const int dashes = 44;

	max_len = MIN (sizeof(dash_buf) - dashes - 1, max_len);
	memset(dash_buf, '-', dashes + max_len);
	dash_buf[dashes + max_len] = '\0';

	fmt::print(out, "Symbols cache\n");

	fmt::print(out, " {} \n", emphasis_argument(dash_buf));
	fmt::print(out,
		"| {:<4} | {:<{}} | {:^7} | {:^13} | {:^7} |\n",
		"Pri",
		"Symbol",
		max_len,
		"Weight",
		"Frequency",
		"Hits");
	fmt::print(out, " {} \n", emphasis_argument(dash_buf));
	fmt::print(out, "| {:<4} | {:<{}} | {:^7} | {:^13} | {:^7} |\n", "",
		"", max_len,
		"", "hits/min", "");

	for (const auto [i, cur] : rspamd::enumerate(counters_vec)) {
		fmt::print(out, " {} \n", dash_buf);
		const auto *sym = ucl_object_lookup(cur, "symbol");
		const auto *weight = ucl_object_lookup(cur, "weight");
		const auto *freq = ucl_object_lookup(cur, "frequency");
		const auto *freq_dev = ucl_object_lookup(cur, "frequency_stddev");
		const auto *nhits = ucl_object_lookup(cur, "hits");

		if (sym && weight && freq && nhits) {
			const char *sym_name;

			if (sym->len > max_len) {
				rspamd_snprintf(sym_buf, sizeof(sym_buf), "%*s...",
					(max_len - 3), ucl_object_tostring(sym));
				sym_name = sym_buf;
			}
			else {
				sym_name = ucl_object_tostring(sym);
			}

			fmt::print(out, "| {:<4} | {:<{}} | {:^7.1f} | {:^6.3f}({:^5.3f}) | {:^7} |\n", i,
				sym_name,
				max_len,
				ucl_object_todouble(weight),
				ucl_object_todouble(freq) * 60.0,
				ucl_object_todouble(freq_dev) * 60.0,
				(std::uintmax_t)ucl_object_toint(nhits));
		}
	}
	fmt::print(out, " {} \n", dash_buf);
}

static void
rspamc_stat_actions(ucl_object_t *obj, std::string &out, std::int64_t scanned)
{
	const ucl_object_t *actions = ucl_object_lookup(obj, "actions"), *cur;
	ucl_object_iter_t iter = nullptr;

	if (scanned > 0) {
		if (actions && ucl_object_type(actions) == UCL_OBJECT) {
			while ((cur = ucl_object_iterate (actions, &iter, true)) != nullptr) {
				auto cnt = ucl_object_toint(cur);
				fmt::format_to(std::back_inserter(out), "Messages with action {}: {}, {:.2f}%\n",
					ucl_object_key(cur), emphasis_argument(cnt),
					((double) cnt / (double) scanned) * 100.);
			}
		}

		auto spam = ucl_object_toint(ucl_object_lookup(obj, "spam_count"));
		auto ham = ucl_object_toint(ucl_object_lookup(obj, "ham_count"));
		fmt::format_to(std::back_inserter(out), "Messages treated as spam: {}, {:.2f}%\n",
			emphasis_argument(spam),
			((double) spam / (double) scanned) * 100.);
		fmt::format_to(std::back_inserter(out), "Messages treated as ham: {}, {:.2f}%\n",
			emphasis_argument(ham),
			((double) ham / (double) scanned) * 100.);
	}
}

static void
rspamc_stat_statfile(const ucl_object_t *obj, std::string &out)
{
	auto version = ucl_object_toint(ucl_object_lookup(obj, "revision"));
	auto size = ucl_object_toint(ucl_object_lookup(obj, "size"));
	auto blocks = ucl_object_toint(ucl_object_lookup(obj, "total"));
	auto used_blocks = ucl_object_toint(ucl_object_lookup(obj, "used"));
	auto label = ucl_object_tostring(ucl_object_lookup(obj, "label"));
	auto symbol = ucl_object_tostring(ucl_object_lookup(obj, "symbol"));
	auto type = ucl_object_tostring(ucl_object_lookup(obj, "type"));
	auto nlanguages = ucl_object_toint(ucl_object_lookup(obj, "languages"));
	auto nusers = ucl_object_toint(ucl_object_lookup(obj, "users"));

	if (label) {
		fmt::format_to(std::back_inserter(out), "Statfile: {} <{}> type: {}; ", symbol,
			label, type);
	}
	else {
		fmt::format_to(std::back_inserter(out), "Statfile: {} type: {}; ", symbol, type);
	}
	fmt::format_to(std::back_inserter(out), "length: {}; free blocks: {}; total blocks: {}; "
											"free: {:.2f}%; learned: {}; users: {}; languages: {}\n",
		size,
		blocks - used_blocks, blocks,
		blocks > 0 ? (blocks - used_blocks) * 100.0 / (double) blocks : 0,
		version,
		nusers, nlanguages);
}

static void
rspamc_stat_output(FILE *out, ucl_object_t *obj)
{
	std::string out_str;

	out_str.reserve(8192);

	auto scanned = ucl_object_toint(ucl_object_lookup(obj, "scanned"));
	fmt::format_to(std::back_inserter(out_str), "Messages scanned: {}\n",
		emphasis_argument(scanned));

	rspamc_stat_actions(obj, out_str, scanned);

	fmt::format_to(std::back_inserter(out_str), "Messages learned: {}\n",
		emphasis_argument(ucl_object_toint(ucl_object_lookup(obj, "learned"))));
	fmt::format_to(std::back_inserter(out_str), "Connections count: {}\n",
		emphasis_argument(ucl_object_toint(ucl_object_lookup(obj, "connections"))));
	fmt::format_to(std::back_inserter(out_str), "Control connections count: {}\n",
		emphasis_argument(ucl_object_toint(ucl_object_lookup(obj, "control_connections"))));

	const auto *avg_time_obj = ucl_object_lookup(obj, "scan_times");

	if (avg_time_obj && ucl_object_type(avg_time_obj) == UCL_ARRAY) {
		ucl_object_iter_t iter = nullptr;
		const ucl_object_t *cur;
		std::vector<float> nums;

		while ((cur = ucl_object_iterate (avg_time_obj, &iter, true)) != nullptr) {
			if (ucl_object_type(cur) == UCL_FLOAT || ucl_object_type(cur) == UCL_INT) {
				nums.push_back(ucl_object_todouble(cur));
			}
		}

		auto cnt = nums.size();

		if (cnt > 0) {
			auto sum = rspamd_sum_floats(nums.data(), &cnt);
			fmt::format_to(std::back_inserter(out_str),
				"Average scan time: {} sec\n",
				emphasis_argument(sum / cnt, 3));
		}
	}

	/* Pools */
	fmt::format_to(std::back_inserter(out_str),  "Pools allocated: {}\n",
		ucl_object_toint(ucl_object_lookup(obj, "pools_allocated")));
	fmt::format_to(std::back_inserter(out_str),  "Pools freed: {}\n",
		ucl_object_toint(ucl_object_lookup(obj, "pools_freed")));
	fmt::format_to(std::back_inserter(out_str),  "Bytes allocated: {}\n",
		ucl_object_toint(ucl_object_lookup(obj, "bytes_allocated")));
	fmt::format_to(std::back_inserter(out_str),  "Memory chunks allocated: {}\n",
		ucl_object_toint(ucl_object_lookup(obj, "chunks_allocated")));
	fmt::format_to(std::back_inserter(out_str),  "Shared chunks allocated: {}\n",
		ucl_object_toint(ucl_object_lookup(obj, "shared_chunks_allocated")));
	fmt::format_to(std::back_inserter(out_str),  "Chunks freed: {}\n",
		ucl_object_toint(ucl_object_lookup(obj, "chunks_freed")));
	fmt::format_to(std::back_inserter(out_str),  "Oversized chunks: {}\n",
		ucl_object_toint(ucl_object_lookup(obj, "chunks_oversized")));
	/* Fuzzy */

	const auto *st = ucl_object_lookup(obj, "fuzzy_hashes");
	if (st) {
		ucl_object_iter_t it = nullptr;
		const ucl_object_t *cur;
		std::uint64_t stored = 0;

		while ((cur = ucl_iterate_object (st, &it, true)) != nullptr) {
			auto num = ucl_object_toint(cur);
			fmt::format_to(std::back_inserter(out_str), "Fuzzy hashes in storage \"{}\": {}\n",
				ucl_object_key(cur),
				num);
			stored += num;
		}

		fmt::format_to(std::back_inserter(out_str), "Fuzzy hashes stored: {}\n",
			stored);
	}

	st = ucl_object_lookup(obj, "fuzzy_checked");
	if (st != nullptr && ucl_object_type(st) == UCL_ARRAY) {
		ucl_object_iter_t iter = nullptr;
		const ucl_object_t *cur;

		out_str += "Fuzzy hashes checked: ";

		while ((cur = ucl_object_iterate (st, &iter, true)) != nullptr) {
			fmt::format_to(std::back_inserter(out_str), "{} ", ucl_object_toint(cur));
		}

		out_str.push_back('\n');
	}

	st = ucl_object_lookup(obj, "fuzzy_found");
	if (st != nullptr && ucl_object_type(st) == UCL_ARRAY) {
		ucl_object_iter_t iter = nullptr;
		const ucl_object_t *cur;

		out_str += "Fuzzy hashes found: ";

		while ((cur = ucl_object_iterate (st, &iter, true)) != nullptr) {
			fmt::format_to(std::back_inserter(out_str), "{} ", ucl_object_toint(cur));
		}

		out_str.push_back('\n');
	}

	st = ucl_object_lookup(obj, "statfiles");
	if (st != nullptr && ucl_object_type(st) == UCL_ARRAY) {
		ucl_object_iter_t iter = nullptr;
		const ucl_object_t *cur;

		while ((cur = ucl_object_iterate (st, &iter, true)) != nullptr) {
			rspamc_stat_statfile(cur, out_str);
		}
	}
	fmt::format_to(std::back_inserter(out_str), "Total learns: {}\n",
		ucl_object_toint(ucl_object_lookup(obj, "total_learns")));

	fmt::print(out, "{}", out_str.c_str());
}

static void
rspamc_output_headers(FILE *out, struct rspamd_http_message *msg)
{
	struct rspamd_http_header *h;

	kh_foreach_value (msg->headers, h, {
		fmt::print(out, "{}: {}\n", std::string_view{h->name.begin, h->name.len},
			std::string_view{h->value.begin, h->value.len});
	});

	fmt::print(out, "\n");
}

static void
rspamc_mime_output(FILE *out, ucl_object_t *result, GString *input,
				   gdouble time, GError *err)
{
	const gchar *action = "no action", *line_end = "\r\n", *p;
	gdouble score = 0.0, required_score = 0.0;
	gboolean is_spam = FALSE;
	auto nl_type = RSPAMD_TASK_NEWLINES_CRLF;

	auto headers_pos = rspamd_string_find_eoh(input, nullptr);

	if (headers_pos == -1) {
		fmt::print(stderr, "cannot find end of headers position");
		return;
	}

	p = input->str + headers_pos;

	if (headers_pos > 1 && *(p - 1) == '\n') {
		if (headers_pos > 2 && *(p - 2) == '\r') {
			line_end = "\r\n";
			nl_type = RSPAMD_TASK_NEWLINES_CRLF;
		}
		else {
			line_end = "\n";
			nl_type = RSPAMD_TASK_NEWLINES_LF;
		}
	}
	else if (headers_pos > 1 && *(p - 1) == '\r') {
		line_end = "\r";
		nl_type = RSPAMD_TASK_NEWLINES_CR;
	}

	std::string added_headers;

	if (result) {
		const auto *res = ucl_object_lookup(result, "action");

		if (res) {
			action = ucl_object_tostring(res);
		}

		res = ucl_object_lookup(result, "score");
		if (res) {
			score = ucl_object_todouble(res);
		}

		res = ucl_object_lookup(result, "required_score");
		if (res) {
			required_score = ucl_object_todouble(res);
		}

		auto act = rspamd_action_from_str_rspamc(action);

		if (act.has_value() && act.value() < METRIC_ACTION_GREYLIST) {
			is_spam = TRUE;
		}

		fmt::format_to(std::back_inserter(added_headers), "X-Spam-Scanner: {}{}",
			"rspamc " RVERSION, line_end);
		fmt::format_to(std::back_inserter(added_headers), "X-Spam-Scan-Time: {:.3}{}",
			time, line_end);

		/*
		 * TODO: add milter_headers support here
		 */
		if (is_spam) {
			fmt::format_to(std::back_inserter(added_headers), "X-Spam: yes{}", line_end);
		}

		fmt::format_to(std::back_inserter(added_headers),"X-Spam-Action: {}{}",
			action, line_end);
		fmt::format_to(std::back_inserter(added_headers), "X-Spam-Score: {:.2f} / {:.2f}{}",
			score, required_score, line_end);

		/* SA style stars header */
		std::string scorebuf;
		auto adjusted_score = std::min(score, 32.0);
		while(adjusted_score > 0) {
			scorebuf.push_back('*');
			adjusted_score -= 1.0;
		}

		fmt::format_to(std::back_inserter(added_headers), "X-Spam-Level: {}{}",
			scorebuf, line_end);

		/* Short description of all symbols */
		std::string symbuf;
		const ucl_object_t *cur;
		ucl_object_iter_t it = nullptr;
		const auto *syms = ucl_object_lookup(result, "symbols");

		while (syms && (cur = ucl_object_iterate (syms, &it, true)) != nullptr) {
			if (ucl_object_type(cur) == UCL_OBJECT) {
				fmt::format_to(std::back_inserter(symbuf), "{},", ucl_object_key(cur));
			}
		}
		/* Trim the last comma */
		if (symbuf.back() == ',') {
			symbuf.pop_back();
		}

		auto *folded_symbuf = rspamd_header_value_fold("X-Spam-Symbols", strlen("X-Spam-Symbols"),
			symbuf.data(), symbuf.size(),
			0, nl_type, ",");
		fmt::format_to(std::back_inserter(added_headers), "X-Spam-Symbols: {}{}",
			folded_symbuf->str, line_end);

		g_string_free(folded_symbuf, TRUE);

		res = ucl_object_lookup(result, "dkim-signature");
		if (res && res->type == UCL_STRING) {
			fmt::format_to(std::back_inserter(added_headers), "DKIM-Signature: {}{}",
				ucl_object_tostring(res), line_end);
		}
		else if (res && res->type == UCL_ARRAY) {
			it = nullptr;
			while ((cur = ucl_object_iterate (res, &it, true)) != nullptr) {
				fmt::format_to(std::back_inserter(added_headers), "DKIM-Signature: {}{}",
					ucl_object_tostring(cur), line_end);
			}
		}

		if (json || ucl_reply || compact) {
			unsigned char *json_header;
			/* We also append json data as a specific header */
			if (json) {
				json_header = ucl_object_emit(result,
					compact ? UCL_EMIT_JSON_COMPACT : UCL_EMIT_JSON);
			}
			else {
				json_header = ucl_object_emit(result,
					compact ? UCL_EMIT_JSON_COMPACT : UCL_EMIT_CONFIG);
			}

			auto *json_header_encoded = rspamd_encode_base64_fold(json_header,
				strlen((char *)json_header), 60, nullptr, nl_type);
			free(json_header);
			fmt::format_to(std::back_inserter(added_headers),
				"X-Spam-Result: {}{}",
				json_header_encoded, line_end);
			g_free(json_header_encoded);
		}

		ucl_object_unref(result);
	}
	else {
		fmt::format_to(std::back_inserter(added_headers), "X-Spam-Scanner: {}{}",
			"rspamc " RVERSION, line_end);
		fmt::format_to(std::back_inserter(added_headers), "X-Spam-Scan-Time: {:.3f}{}",
			time, line_end);
		fmt::format_to(std::back_inserter(added_headers), "X-Spam-Error: {}{}",
			err->message, line_end);
	}

	/* Write message */
	/* Original headers */
	fmt::print(out, "{}", std::string_view{input->str, (std::size_t)headers_pos});
	/* Added headers */
	fmt::print(out, "{}", added_headers);
	/* Message body */
	fmt::print(out, "{}", input->str + headers_pos);
}

static void
rspamc_client_execute_cmd(const struct rspamc_command &cmd, ucl_object_t *result,
						  GString *input, gdouble time, GError *err)
{
	gchar **eargv;
	gint eargc, infd, outfd, errfd;
	GError *exec_err = nullptr;
	GPid cld;

	if (!g_shell_parse_argv(execute, &eargc, &eargv, &err)) {
		fmt::print(stderr, "Cannot execute {}: {}", execute, err->message);
		g_error_free(err);

		return;
	}

	if (!g_spawn_async_with_pipes(nullptr, eargv, nullptr,
		static_cast<GSpawnFlags>(G_SPAWN_SEARCH_PATH | G_SPAWN_DO_NOT_REAP_CHILD), nullptr, nullptr, &cld,
		&infd, &outfd, &errfd, &exec_err)) {

		fmt::print(stderr, "Cannot execute {}: {}", execute, exec_err->message);
		g_error_free(exec_err);

		exit(EXIT_FAILURE);
	}
	else {
		children.push_back(cld);
		auto *out = fdopen(infd, "w");

		if (cmd.cmd == RSPAMC_COMMAND_SYMBOLS && mime_output && input) {
			rspamc_mime_output(out, result, input, time, err);
		}
		else if (result) {
			if (ucl_reply || cmd.command_output_func == nullptr) {
				char *ucl_out;

				if (json) {
					ucl_out = (char *)ucl_object_emit(result,
						compact ? UCL_EMIT_JSON_COMPACT : UCL_EMIT_JSON);
				}
				else {
					ucl_out = (char *)ucl_object_emit(result,
						compact ? UCL_EMIT_JSON_COMPACT : UCL_EMIT_CONFIG);
				}
				fmt::print(out, "{}", ucl_out);
				free(ucl_out);
			}
			else {
				cmd.command_output_func(out, result);
			}

			ucl_object_unref(result);
		}
		else {
			fmt::print(out, "{}\n", err->message);
		}

		fflush(out);
		fclose(out);
	}

	g_strfreev(eargv);
}

static void
rspamc_client_cb(struct rspamd_client_connection *conn,
				 struct rspamd_http_message *msg,
				 const char *name, ucl_object_t *result, GString *input,
				 gpointer ud, gdouble start_time, gdouble send_time,
				 const char *body, gsize bodylen,
				 GError *err)
{
	struct rspamc_callback_data *cbdata = (struct rspamc_callback_data *) ud;
	FILE *out = stdout;
	gdouble finish = rspamd_get_ticks(FALSE), diff;

	auto &cmd = cbdata->cmd;

	if (send_time > 0) {
		diff = finish - send_time;
	}
	else {
		diff = finish - start_time;
	}

	if (execute) {
		/* Pass all to the external command */
		rspamc_client_execute_cmd(cmd, result, input, diff, err);
	}
	else {

		if (cmd.cmd == RSPAMC_COMMAND_SYMBOLS && mime_output && input) {
			if (body) {
				GString tmp;

				tmp.str = (char *) body;
				tmp.len = bodylen;
				rspamc_mime_output(out, result, &tmp, diff, err);
			}
			else {
				rspamc_mime_output(out, result, input, diff, err);
			}
		}
		else {
			if (cmd.need_input && !json) {
				if (!compact && !humanreport) {
					fmt::print(out, "Results for file: {} ({:.3} seconds)\n",
						emphasis_argument(cbdata->filename), diff);
				}
			}
			else {
				if (!compact && !json && !humanreport) {
					fmt::print(out, "Results for command: {} ({:.3} seconds)\n",
						emphasis_argument(cmd.name), diff);
				}
			}

			if (result != nullptr) {
				if (headers && msg != nullptr) {
					rspamc_output_headers(out, msg);
				}
				if (ucl_reply || cmd.command_output_func == nullptr) {
					if (cmd.need_input) {
						ucl_object_insert_key(result,
							ucl_object_fromstring(cbdata->filename.c_str()),
							"filename", 0,
							false);
					}

					ucl_object_insert_key(result,
						ucl_object_fromdouble(diff),
						"scan_time", 0,
						false);

					char *ucl_out;

					if (json) {
						ucl_out = (char *)ucl_object_emit(result,
							compact ? UCL_EMIT_JSON_COMPACT : UCL_EMIT_JSON);
					}
					else {
						ucl_out = (char *)ucl_object_emit(result,
							compact ? UCL_EMIT_JSON_COMPACT : UCL_EMIT_CONFIG);
					}

					fmt::print(out, "{}", ucl_out);
					free(ucl_out);
				}
				else {
					cmd.command_output_func(out, result);
				}

				if (body) {
					fmt::print(out, "\nNew body:\n{}\n",
						std::string_view{body, bodylen});
				}

				ucl_object_unref(result);
			}
			else if (err != nullptr) {
				fmt::print(out, "{}\n", err->message);

				if (json && msg != nullptr) {
					gsize rawlen;

					auto *raw_body = rspamd_http_message_get_body(msg, &rawlen);

					if (raw_body) {
						/* We can also output the resulting json */
						fmt::print(out, "{}\n", std::string_view{raw_body, (std::size_t)(rawlen - bodylen)});
					}
				}
			}
			fmt::print(out, "\n");
		}

		fflush(out);
	}

	rspamd_client_destroy(conn);
	delete cbdata;

	if (err) {
		retcode = EXIT_FAILURE;
	}
}

static void
rspamc_process_input(struct ev_loop *ev_base, const struct rspamc_command &cmd,
					 FILE *in, const std::string &name, GQueue *attrs)
{
	struct rspamd_client_connection *conn;
	const char *p;
	guint16 port;
	GError *err = nullptr;
	std::string hostbuf;

	if (connect_str[0] == '[') {
		p = strrchr(connect_str, ']');

		if (p != nullptr) {
			hostbuf.assign(connect_str + 1, (std::size_t)(p - connect_str - 1));
			p++;
		}
		else {
			p = connect_str;
		}
	}
	else {
		p = connect_str;
	}

	p = strrchr(p, ':');

	if (hostbuf.empty()) {
		if (p != nullptr) {
			hostbuf.assign(connect_str, (std::size_t)(p - connect_str));
		}
		else {
			hostbuf.assign(connect_str);
		}
	}

	if (p != nullptr) {
		port = strtoul(p + 1, nullptr, 10);
	}
	else {
		/*
		 * If we connect to localhost, 127.0.0.1 or ::1, then try controller
		 * port first
		 */

		if (hostbuf == "localhost" ||
			hostbuf == "127.0.0.1"||
			hostbuf == "::1" ||
			hostbuf == "[::1]") {
			port = DEFAULT_CONTROL_PORT;
		}
		else {
			port = cmd.is_controller ? DEFAULT_CONTROL_PORT : DEFAULT_PORT;
		}

	}

	conn = rspamd_client_init(http_ctx, ev_base, hostbuf.c_str(), port, timeout, pubkey);

	if (conn != nullptr) {
		auto *cbdata = new rspamc_callback_data;
		cbdata->cmd = cmd;
		cbdata->filename = name;

		if (cmd.need_input) {
			rspamd_client_command(conn, cmd.path, attrs, in, rspamc_client_cb,
				cbdata, compressed, dictionary, cbdata->filename.c_str(), &err);
		}
		else {
			rspamd_client_command(conn,
				cmd.path,
				attrs,
				nullptr,
				rspamc_client_cb,
				cbdata,
				compressed,
				dictionary,
				cbdata->filename.c_str(),
				&err);
		}
	}
	else {
		fmt::print(stderr, "cannot connect to {}: {}\n", connect_str,
			strerror(errno));
		exit(EXIT_FAILURE);
	}
}

static gsize
rspamd_dirent_size(DIR *dirp)
{
	goffset name_max;
	gsize name_end;

#if defined(HAVE_FPATHCONF) && defined(HAVE_DIRFD) \
 && defined(_PC_NAME_MAX)
	name_max = fpathconf(dirfd(dirp), _PC_NAME_MAX);


# if defined(NAME_MAX)
	if (name_max == -1) {
		name_max = (NAME_MAX > 255) ? NAME_MAX : 255;
	}
# else
	if (name_max == -1) {
		return (size_t)(-1);
	}
# endif
#else
	# if defined(NAME_MAX)
	name_max = (NAME_MAX > 255) ? NAME_MAX : 255;
# else
#   error "buffer size for readdir_r cannot be determined"
# endif
#endif

	name_end = G_STRUCT_OFFSET (struct dirent, d_name) + name_max + 1;

	return (name_end > sizeof(struct dirent) ? name_end : sizeof(struct dirent));
}

static void
rspamc_process_dir(struct ev_loop *ev_base, const struct rspamc_command &cmd,
				   const std::string &name, GQueue *attrs)
{
	static auto cur_req = 0;
	auto *d = opendir(name.c_str());

	if (d != nullptr) {
		struct dirent *pentry;
		std::string fpath;

		fpath.reserve(PATH_MAX);

		while ((pentry = readdir(d)) != nullptr) {

			if (pentry->d_name[0] == '.') {
				continue;
			}

			fpath.clear();
			fmt::format_to(std::back_inserter(fpath), "{}{}{}",
				name, G_DIR_SEPARATOR,
				pentry->d_name);

			/* Check exclude */
			auto **ex = exclude_compiled;
			auto skip = false;
			while (ex != nullptr && *ex != nullptr) {
#if GLIB_MAJOR_VERSION >= 2 && GLIB_MINOR_VERSION >= 70
				if (g_pattern_spec_match(*ex, fpath.size(), fpath.c_str(), nullptr)) {
#else
					if (g_pattern_match(*ex, fpath.size(), fpath.c_str(), nullptr)) {
#endif
					skip = true;
					break;
				}

				ex++;
			}

			if (skip) {
				continue;
			}

			auto is_reg = false;
			auto is_dir = false;
			struct stat st;

#if (defined(_DIRENT_HAVE_D_TYPE) || defined(__APPLE__)) && defined(DT_UNKNOWN)
			if (pentry->d_type == DT_UNKNOWN) {
				/* Fallback to lstat */
				if (lstat(fpath.c_str(), &st) == -1) {
					fmt::print(stderr, "cannot stat file {}: {}\n",
						fpath, strerror(errno));
					continue;
				}

				is_dir = S_ISDIR(st.st_mode);
				is_reg = S_ISREG(st.st_mode);
			}
			else {
				if (pentry->d_type == DT_REG) {
					is_reg = true;
				}
				else if (pentry->d_type == DT_DIR) {
					is_dir = true;
				}
			}
#else
			if (lstat(fpath.c_str(), &st) == -1) {
				fmt::print(stderr, "cannot stat file {}: {}\n",
						fpath, strerror (errno));
				continue;
			}

			is_dir = S_ISDIR(st.st_mode);
			is_reg = S_ISREG(st.st_mode);
#endif
			if (is_dir) {
				rspamc_process_dir(ev_base, cmd, fpath, attrs);
				continue;
			}
			else if (is_reg) {
				auto *in = fopen(fpath.c_str(), "r");
				if (in == nullptr) {
					fmt::print(stderr, "cannot open file {}: {}\n",
						fpath, strerror(errno));
					continue;
				}

				rspamc_process_input(ev_base, cmd, in, fpath, attrs);
				cur_req++;
				fclose(in);

				if (cur_req >= max_requests) {
					cur_req = 0;
					/* Wait for completion */
					ev_loop(ev_base, 0);
				}
			}
		}
	}
	else {
		fmt::print(stderr, "cannot open directory {}: {}\n", name, strerror(errno));
		exit(EXIT_FAILURE);
	}

	closedir(d);
	ev_loop(ev_base, 0);
}


static void
rspamc_kwattr_free(gpointer p)
{
	struct rspamd_http_client_header *h = (struct rspamd_http_client_header *) p;

	g_free(h->value);
	g_free(h->name);
	g_free(h);
}

int
main(int argc, char **argv, char **env)
{
	auto *kwattrs = g_queue_new();

	read_cmd_line(&argc, &argv);
	tty = isatty(STDOUT_FILENO);

	if (print_commands) {
		print_commands_list();
		exit(EXIT_SUCCESS);
	}

	/* Deal with exclude patterns */
	auto **exclude_pattern = exclude_patterns;
	auto npatterns = 0;

	while (exclude_pattern && *exclude_pattern) {
		exclude_pattern++;
		npatterns++;
	}

	if (npatterns > 0) {
		exclude_compiled = g_new0(GPatternSpec *, (npatterns + 1));

		for (auto i = 0; i < npatterns; i++) {
			exclude_compiled[i] = g_pattern_spec_new(exclude_patterns[i]);

			if (exclude_compiled[i] == nullptr) {
				fmt::print(stderr, "Invalid glob pattern: {}\n",
					exclude_patterns[i]);
				exit(EXIT_FAILURE);
			}
		}
	}

	auto *libs = rspamd_init_libs();
	auto *event_loop = ev_loop_new(EVBACKEND_ALL);

	struct rspamd_http_context_cfg http_config;
	memset(&http_config, 0, sizeof(http_config));
	http_config.kp_cache_size_client = 32;
	http_config.kp_cache_size_server = 0;
	http_config.user_agent = user_agent;
	http_ctx = rspamd_http_context_create_config(&http_config,
		event_loop, nullptr);

	/* Ignore sigpipe */
	struct sigaction sigpipe_act;
	sigemptyset (&sigpipe_act.sa_mask);
	sigaddset (&sigpipe_act.sa_mask, SIGPIPE);
	sigpipe_act.sa_handler = SIG_IGN;
	sigpipe_act.sa_flags = 0;
	sigaction(SIGPIPE, &sigpipe_act, nullptr);

	/* Now read other args from argc and argv */
	FILE *in = nullptr;
	std::optional<rspamc_command> maybe_cmd;
	auto start_argc = 0;

	if (argc == 1) {
		start_argc = argc;
		in = stdin;
		maybe_cmd = check_rspamc_command("symbols");
	}
	else if (argc == 2) {
		/* One argument is whether command or filename */
		maybe_cmd = check_rspamc_command(argv[1]);

		if (maybe_cmd.has_value()) {
			start_argc = argc;
			in = stdin;
		}
		else {
			maybe_cmd = check_rspamc_command("symbols"); /* Symbols command */
			start_argc = 1;
		}
	}
	else {
		maybe_cmd = check_rspamc_command(argv[1]);
		if (maybe_cmd.has_value()) {
			auto &cmd = maybe_cmd.value();
			/* In case of command read arguments starting from 2 */
			if (cmd.cmd == RSPAMC_COMMAND_ADD_SYMBOL || cmd.cmd == RSPAMC_COMMAND_ADD_ACTION) {
				if (argc < 4 || argc > 5) {
					fmt::print(stderr, "invalid arguments\n");
					exit(EXIT_FAILURE);
				}
				if (argc == 5) {
					add_client_header(kwattrs, "metric", argv[2]);
					add_client_header(kwattrs, "name", argv[3]);
					add_client_header(kwattrs, "value", argv[4]);
				}
				else {
					add_client_header(kwattrs, "name", argv[2]);
					add_client_header(kwattrs, "value", argv[3]);
				}
				start_argc = argc;
			}
			else {
				start_argc = 2;
			}
		}
		else {
			maybe_cmd = check_rspamc_command("symbols");
			start_argc = 1;
		}
	}

	if (!maybe_cmd.has_value()) {
		fmt::print(stderr, "invalid command\n");
		exit(EXIT_FAILURE);
	}

	add_options(kwattrs);
	auto cmd = maybe_cmd.value();

	if (start_argc == argc) {
		/* Do command without input or with stdin */
		if (empty_input) {
			rspamc_process_input(event_loop, cmd, nullptr, "empty", kwattrs);
		}
		else {
			rspamc_process_input(event_loop, cmd, in, "stdin", kwattrs);
		}
	}
	else {
		auto cur_req = 0;

		for (auto i = start_argc; i < argc; i++) {
			if (cmd.cmd == RSPAMC_COMMAND_FUZZY_DELHASH) {
				add_client_header(kwattrs, "Hash", argv[i]);
			}
			else {
				struct stat st;

				if (stat(argv[i], &st) == -1) {
					fmt::print(stderr, "cannot stat file {}\n", argv[i]);
					exit(EXIT_FAILURE);
				}
				if (S_ISDIR (st.st_mode)) {
					/* Directories are processed with a separate limit */
					rspamc_process_dir(event_loop, cmd, argv[i], kwattrs);
					cur_req = 0;
				}
				else {
					in = fopen(argv[i], "r");
					if (in == nullptr) {
						fmt::print(stderr, "cannot open file {}\n", argv[i]);
						exit(EXIT_FAILURE);
					}
					rspamc_process_input(event_loop, cmd, in, argv[i], kwattrs);
					cur_req++;
					fclose(in);
				}
				if (cur_req >= max_requests) {
					cur_req = 0;
					/* Wait for completion */
					ev_loop(event_loop, 0);
				}
			}
		}

		if (cmd.cmd == RSPAMC_COMMAND_FUZZY_DELHASH) {
			rspamc_process_input(event_loop, cmd, nullptr, "hashes", kwattrs);
		}
	}

	ev_loop(event_loop, 0);

	g_queue_free_full(kwattrs, rspamc_kwattr_free);

	/* Wait for children processes */
	auto ret = 0;

	for (auto cld : children) {
		auto res = 0;
		if (waitpid(cld, &res, 0) == -1) {
			fmt::print(stderr, "Cannot wait for {}: {}", cld,
				strerror(errno));

			ret = errno;
		}

		if (ret == 0) {
			/* Check return code */
			if (WIFSIGNALED (res)) {
				ret = WTERMSIG (res);
			}
			else if (WIFEXITED (res)) {
				ret = WEXITSTATUS (res);
			}
		}
	}

	for (auto i = 0; i < npatterns; i++) {
		g_pattern_spec_free(exclude_compiled[i]);
	}
	g_free(exclude_compiled);

	rspamd_deinit_libs(libs);

	/* Mix retcode (return from Rspamd side) and ret (return from subprocess) */
	return ret | retcode;
}
