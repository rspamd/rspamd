#include "config.h"
#include "rspamadm.h"
#include "lua/lua_common.h"

static char *encrypted_header = NULL;
static char *key = NULL;
static char *nonce = NULL;

static void rspamadm_decrypt_header(int argc, char **argv,
                                    const struct rspamadm_command *cmd);
static const char *rspamadm_decrypt_header_help(gboolean full_help,
                                                const struct rspamadm_command *cmd);

struct rspamadm_command decrypt_header_command = {
        .name = "decryptheader",
        .flags = 0,
        .help = rspamadm_decrypt_header_help,
        .run = rspamadm_decrypt_header,
        .lua_subrs = NULL,
};

static GOptionEntry entries[] = {
        {"encheader", 'h', 0, G_OPTION_ARG_STRING, &encrypted_header,
                "Encrypted header to decrypt", NULL},
        {"key", 'k', 0, G_OPTION_ARG_STRING, &key,
                "Key used to encrypt header", NULL},
        {"nonce", 'n', 0, G_OPTION_ARG_STRING, &nonce,
                "Nonce used to encrypt header", NULL},
        {NULL, 0, 0, G_OPTION_ARG_NONE, NULL, NULL, NULL}};

static const char *
rspamadm_decrypt_header_help(gboolean full_help, const struct rspamadm_command *cmd)
{
    const char *help_str;

    if (full_help) {
        help_str = "Decrypt provided encrypted header with provided key and nonce\n\n"
                   "Usage: rspamadm decryptheader -h <header> -k <key> -n <nonce>\n"
                   "Where options are:\n\n"
                   "-h: encrypted header\n"
                   "-k: key used to encrypt header\n"
                   "-n: nonce used to encrypt header\n";
    }
    else {
        help_str = "Decrypt provided encrypted header with provided key and nonce";
    }

    return help_str;
}

static void
rspamadm_decrypt_header(int argc, char **argv, const struct rspamadm_command *cmd) {
    GOptionContext *context;
    GError *error = NULL;
    ucl_object_t *obj;

    context = g_option_context_new(
            "decryptheader - decrypts provided encrypted header with provided key and nonce");
    g_option_context_set_summary(context,
                                 "Summary:\n  Rspamd administration utility version " RVERSION
                                 "\n  Release id: " RID);
    g_option_context_add_main_entries(context, entries, NULL);
    g_option_context_set_ignore_unknown_options(context, TRUE);

    if (!g_option_context_parse(context, &argc, &argv, &error)) {
        rspamd_fprintf(stderr, "option parsing failed: %s\n", error->message);
        g_error_free(error);
        g_option_context_free(context);
        exit(EXIT_FAILURE);
    }

    g_option_context_free(context);

    if (!encrypted_header) {
        rspamd_fprintf(stderr, "encrypted header is missing\n");
        exit(EXIT_FAILURE);
    }
    if (!key) {
        rspamd_fprintf(stderr, "key is missing\n");
        exit(EXIT_FAILURE);
    }
    if (!nonce) {
        rspamd_fprintf(stderr, "nonce is missing\n");
        exit(EXIT_FAILURE);
    }

    obj = ucl_object_typed_new(UCL_OBJECT);
    ucl_object_insert_key(obj, ucl_object_fromstring(encrypted_header),
                          "encrypted_header", 0, false);
    ucl_object_insert_key(obj, ucl_object_fromstring(key),
                          "key", 0, false);
    ucl_object_insert_key(obj, ucl_object_fromstring(nonce),
                          "nonce", 0, false);

    rspamadm_execute_lua_ucl_subr(argc,
                                  argv,
                                  obj,
                                  "maybe_decrypt_header",
                                  TRUE);
}
