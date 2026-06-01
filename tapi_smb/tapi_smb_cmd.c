/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Interpretica Unipessoal Lda */
/** @file
 * @brief SMB TAPI: running a tool, and reading what it printed
 *
 * The three backends answer in three shapes - lines of text from the
 * Samba tools, key=value from @c smbutil, JSON from PowerShell - so the
 * readers live here next to the runner. The one thing they share is
 * that a failure is an NT status somewhere in the text, not an exit
 * code, and tapi_smb_nt_status() is what reads it.
 */

#define TE_LGR_USER "TAPI SMB"

#include "te_config.h"

#include <stdarg.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "logger_api.h"
#include "te_alloc.h"
#include "te_str.h"
#include "te_string.h"
#include "te_vector.h"

#include "tapi_devtool_run.h"
#include "tapi_smb_internal.h"

/** Arguments of a command, as a plain vector of strings. */
typedef struct smb_cmd_opt {
    size_t n_args;
    const char **args;
} smb_cmd_opt;

static const tapi_job_opt_bind smb_cmd_binds[] = TAPI_JOB_OPT_SET(
    TAPI_JOB_OPT_ARRAY_PTR(smb_cmd_opt, n_args, args,
        TAPI_JOB_OPT_CONTENT(TAPI_JOB_OPT_STRING, NULL, false))
);

/* See description in tapi_smb_internal.h */
void
tapi_smb_arg(te_vec *args, const char *fmt, ...)
{
    te_string built = TE_STRING_INIT;
    char *arg;
    va_list ap;

    va_start(ap, fmt);
    te_string_append_va(&built, fmt, ap);
    va_end(ap);

    arg = built.ptr != NULL ? built.ptr : TE_STRDUP("");
    TE_VEC_APPEND(args, arg);
}

/** Run @p program with @p args and @p env, and wait for it. */
static te_errno
smb_cmd(tapi_job_factory_t *factory, const char *name, const char *program,
        const te_vec *args, const char **env, int timeout_ms,
        te_string *out, te_string *err, int *exit_code)
{
    smb_cmd_opt opt = {
        .n_args = te_vec_size(args),
        .args = te_vec_size(args) == 0 ? NULL :
                (const char **)te_vec_get((te_vec *)args, 0),
    };
    tapi_devtool_output output;
    tapi_devtool_run run = TAPI_DEVTOOL_RUN_INIT;
    te_errno rc;

    rc = tapi_devtool_run_init_env(&run, factory, name, program,
                                   smb_cmd_binds, &opt, NULL, env);
    if (rc != 0)
        return rc;

    rc = tapi_devtool_run_start(&run);
    if (rc == 0)
        rc = tapi_devtool_run_wait(&run, timeout_ms);

    if (rc != 0)
    {
        tapi_devtool_run_fini(&run);
        return rc;
    }

    tapi_devtool_run_get_output(&run, &output);

    if (out != NULL && output.out != NULL)
        te_string_append(out, "%s", output.out);
    if (err != NULL && output.err != NULL)
        te_string_append(err, "%s", output.err);

    if (exit_code != NULL)
    {
        *exit_code = output.status.type == TAPI_JOB_STATUS_EXITED ?
                     output.status.value : -1;
    }

    return tapi_devtool_run_fini(&run);
}

/* See description in tapi_smb_internal.h */
te_errno
tapi_smb_sh(tapi_job_factory_t *factory, const char *program,
            const te_vec *args, const char *password, int timeout_ms,
            te_string *out, te_string *err, int *exit_code)
{
    te_vec sh_args = TE_VEC_INIT(char *);
    te_string command = TE_STRING_INIT;
    te_string passwd_env = TE_STRING_INIT;
    /* PATH, LC_ALL, an optional PASSWD, and a NULL terminator. */
    const char *env[4] = { NULL, NULL, NULL, NULL };
    char * const *arg;
    size_t n_env = 0;
    te_errno rc;

    /*
     * The tool is run behind /bin/sh -c '"$0" "$@"' so that $0 is the
     * program and "$@" its arguments, untouched by the shell. The
     * environment - PATH with the sbin dirs, LC_ALL=C, and PASSWD when
     * there is a password - is given as the job's whole environment
     * with tapi_devtool_run_init_env(), not exported by the shell,
     * because a password exported in a shell line would still be a
     * word on that line.
     */
    env[n_env++] = "PATH=/usr/bin:/bin:/usr/sbin:/sbin:/usr/local/bin:"
                   "/usr/local/sbin";
    env[n_env++] = "LC_ALL=C";
    if (password != NULL)
    {
        te_string_append(&passwd_env, "PASSWD=%s", password);
        env[n_env++] = te_string_value(&passwd_env);
    }
    /* env[n_env] stays NULL: the array has room for the terminator. */

    tapi_smb_arg(&sh_args, "-c");
    tapi_smb_arg(&sh_args, "exec \"$0\" \"$@\"");
    tapi_smb_arg(&sh_args, "%s", program);
    if (args != NULL)
    {
        TE_VEC_FOREACH((te_vec *)args, arg)
            tapi_smb_arg(&sh_args, "%s", *arg);
    }

    rc = smb_cmd(factory, program, "/bin/sh", &sh_args, env, timeout_ms,
                 out, err, exit_code);

    te_vec_deep_free(&sh_args);
    te_string_free(&command);
    te_string_free(&passwd_env);

    return rc;
}

/**
 * Encode a UTF-8 script as PowerShell's -EncodedCommand wants it:
 * UTF-16LE, then base64.
 */
static void
smb_ps_encode(const char *script, te_string *encoded)
{
    const unsigned char *pos = (const unsigned char *)script;
    uint8_t *units = TE_ALLOC(4 * strlen(script) + 4);
    size_t n = 0;

    while (*pos != '\0')
    {
        uint32_t cp;
        unsigned int extra;

        if (*pos < 0x80)
        {
            cp = *pos;
            extra = 0;
        }
        else if ((*pos & 0xe0) == 0xc0)
        {
            cp = *pos & 0x1f;
            extra = 1;
        }
        else if ((*pos & 0xf0) == 0xe0)
        {
            cp = *pos & 0x0f;
            extra = 2;
        }
        else
        {
            cp = *pos & 0x07;
            extra = 3;
        }
        pos++;

        for (; extra > 0 && (*pos & 0xc0) == 0x80; extra--, pos++)
            cp = (cp << 6) | (*pos & 0x3f);

        if (cp >= 0x10000)
        {
            uint32_t v = cp - 0x10000;
            uint16_t hi = 0xd800 | (v >> 10);
            uint16_t lo = 0xdc00 | (v & 0x3ff);

            units[n++] = hi & 0xff;
            units[n++] = hi >> 8;
            units[n++] = lo & 0xff;
            units[n++] = lo >> 8;
        }
        else
        {
            units[n++] = cp & 0xff;
            units[n++] = (cp >> 8) & 0xff;
        }
    }

    te_string_encode_base64(encoded, n, units, false);
    free(units);
}

/* See description in tapi_smb_internal.h */
te_errno
tapi_smb_powershell(tapi_job_factory_t *factory, const char *script,
                    int timeout_ms, te_string *out, te_string *err,
                    int *exit_code)
{
    te_vec args = TE_VEC_INIT(char *);
    te_string own_err = TE_STRING_INIT;
    te_string encoded = TE_STRING_INIT;
    te_errno rc;

    smb_ps_encode(script, &encoded);
    tapi_smb_arg(&args, "-NoProfile");
    tapi_smb_arg(&args, "-NonInteractive");
    tapi_smb_arg(&args, "-EncodedCommand");
    tapi_smb_arg(&args, "%s", te_string_value(&encoded));
    te_string_free(&encoded);

    rc = smb_cmd(factory, "powershell", "powershell", &args, NULL,
                 timeout_ms, out, &own_err, exit_code);

    if (rc == 0 && own_err.len != 0)
        RING("PowerShell wrote to stderr: %s", te_string_value(&own_err));
    if (err != NULL)
        te_string_append(err, "%s", te_string_value(&own_err));

    te_vec_deep_free(&args);
    te_string_free(&own_err);

    return rc;
}

/* See description in tapi_smb_internal.h */
void
tapi_smb_ps_quote(te_string *script, const char *value)
{
    const unsigned char *pos = (const unsigned char *)value;

    te_string_append(script, "'");
    for (; pos != NULL && *pos != '\0'; pos++)
    {
        if (*pos == '\'')
        {
            te_string_append(script, "''");
        }
        else if (pos[0] == 0xe2 && pos[1] == 0x80 &&
                 pos[2] >= 0x98 && pos[2] <= 0x9b)
        {
            te_string_append(script, "%.3s%.3s", pos, pos);
            pos += 2;
        }
        else
        {
            te_string_append(script, "%c", *pos);
        }
    }
    te_string_append(script, "'");
}

/** Find @c "key" in a flat JSON object and return what follows the colon. */
static const char *
smb_json_value(const char *object, const char *key)
{
    te_string quoted = TE_STRING_INIT;
    const char *found;

    te_string_append(&quoted, "\"%s\"", key);
    found = strstr(object, quoted.ptr);
    te_string_free(&quoted);

    if (found == NULL)
        return NULL;

    found = strchr(found, ':');
    if (found == NULL)
        return NULL;

    found++;
    while (*found == ' ' || *found == '\t' || *found == '\n' ||
           *found == '\r')
    {
        found++;
    }

    return found;
}

/** Read one JSON string at its opening quote, unescaping it. */
static const char *
smb_json_read_str(const char *pos, te_string *dest)
{
    if (*pos != '"')
        return NULL;

    for (pos++; *pos != '\0' && *pos != '"'; pos++)
    {
        if (*pos != '\\')
        {
            te_string_append(dest, "%c", *pos);
            continue;
        }

        pos++;
        switch (*pos)
        {
            case 'n':
                te_string_append(dest, "\n");
                break;
            case 't':
                te_string_append(dest, "\t");
                break;
            case 'r':
                break;
            case 'u':
            {
                unsigned int code = 0;
                int i;

                for (i = 1; i <= 4 && pos[i] != '\0'; i++)
                {
                    char c = pos[i];

                    code <<= 4;
                    if (c >= '0' && c <= '9')
                        code |= c - '0';
                    else if (c >= 'a' && c <= 'f')
                        code |= c - 'a' + 10;
                    else if (c >= 'A' && c <= 'F')
                        code |= c - 'A' + 10;
                }
                pos += i - 1;
                te_string_append(dest, "%c",
                                 code < 0x80 ? (char)code : '?');
                break;
            }
            case '\0':
                return NULL;
            default:
                te_string_append(dest, "%c", *pos);
                break;
        }
    }

    return *pos == '"' ? pos + 1 : NULL;
}

/* See description in tapi_smb_internal.h */
bool
tapi_smb_json_str(const char *object, const char *key, te_string *dest)
{
    const char *value = smb_json_value(object, key);

    if (value == NULL || *value != '"')
        return false;

    return smb_json_read_str(value, dest) != NULL;
}

/* See description in tapi_smb_internal.h */
bool
tapi_smb_json_bool(const char *object, const char *key, bool *value)
{
    const char *found = smb_json_value(object, key);

    if (found == NULL)
        return false;

    if (strncmp(found, "true", 4) == 0)
        *value = true;
    else if (strncmp(found, "false", 5) == 0)
        *value = false;
    else
        return false;

    return true;
}

/* See description in tapi_smb_internal.h */
bool
tapi_smb_json_int(const char *object, const char *key, long *value)
{
    const char *found = smb_json_value(object, key);

    if (found == NULL)
        return false;

    return te_strtol_silent(found, 10, value) == 0;
}

/* See description in tapi_smb_internal.h */
const char *
tapi_smb_json_next(const char *array, const char *prev, te_string *object)
{
    const char *start = prev != NULL ? prev : array;
    unsigned int depth = 0;
    bool in_str = false;
    const char *pos;
    const char *open = NULL;

    for (pos = start; *pos != '\0'; pos++)
    {
        if (in_str)
        {
            if (*pos == '\\' && pos[1] != '\0')
                pos++;
            else if (*pos == '"')
                in_str = false;
            continue;
        }

        if (*pos == '"')
        {
            in_str = true;
        }
        else if (*pos == '{')
        {
            if (depth == 0)
                open = pos;
            depth++;
        }
        else if (*pos == '}')
        {
            if (depth == 0)
                continue;

            depth--;
            if (depth == 0 && open != NULL)
            {
                te_string_append(object, "%.*s", (int)(pos - open + 1),
                                 open);
                return pos + 1;
            }
        }
    }

    return NULL;
}

/** One NT status name and the TE code it maps to. */
typedef struct smb_status_map {
    const char *name;
    te_errno rc;
} smb_status_map;

/* See description in tapi_smb_internal.h */
te_errno
tapi_smb_nt_status(const char *text, te_string *status)
{
    static const smb_status_map map[] = {
        { "NT_STATUS_LOGON_FAILURE", TE_EACCES },
        { "NT_STATUS_ACCESS_DENIED", TE_EACCES },
        { "NT_STATUS_ACCOUNT_DISABLED", TE_EACCES },
        { "NT_STATUS_ACCOUNT_LOCKED_OUT", TE_EACCES },
        { "NT_STATUS_PASSWORD_EXPIRED", TE_EACCES },
        { "NT_STATUS_BAD_NETWORK_NAME", TE_ENOENT },
        { "NT_STATUS_OBJECT_NAME_NOT_FOUND", TE_ENOENT },
        { "NT_STATUS_OBJECT_PATH_NOT_FOUND", TE_ENOENT },
        { "NT_STATUS_NO_SUCH_FILE", TE_ENOENT },
        { "NT_STATUS_SHARING_VIOLATION", TE_EBUSY },
        { "NT_STATUS_FILE_IS_A_DIRECTORY", TE_EISDIR },
        { "NT_STATUS_NOT_A_DIRECTORY", TE_ENOTDIR },
        { "NT_STATUS_DIRECTORY_NOT_EMPTY", TE_ENOTEMPTY },
        { "NT_STATUS_OBJECT_NAME_COLLISION", TE_EEXIST },
        { "NT_STATUS_DISK_FULL", TE_ENOSPC },
        { "NT_STATUS_CONNECTION_REFUSED", TE_ECONNREFUSED },
        { "NT_STATUS_CONNECTION_RESET", TE_ECONNRESET },
        { "NT_STATUS_IO_TIMEOUT", TE_ETIMEDOUT },
        { "NT_STATUS_HOST_UNREACHABLE", TE_EHOSTUNREACH },
        { "NT_STATUS_NETWORK_UNREACHABLE", TE_ENETUNREACH },
        { "NT_STATUS_INVALID_PARAMETER", TE_EINVAL },
        { "NT_STATUS_NOT_SUPPORTED", TE_EOPNOTSUPP },
        { "NT_STATUS_INVALID_NETWORK_RESPONSE", TE_EPROTO },
    };
    const char *found = strstr(text, "NT_STATUS_");
    size_t i;

    if (found == NULL)
        return 0;

    if (status != NULL)
        te_string_append(status, "%.*s", (int)strcspn(found, " \t\r\n.,"),
                         found);

    for (i = 0; i < TE_ARRAY_LEN(map); i++)
    {
        if (strncmp(found, map[i].name, strlen(map[i].name)) == 0)
            return TE_RC(TE_TAPI, map[i].rc);
    }

    /* A status this table does not name is still a failure. */
    return TE_RC(TE_TAPI, TE_EFAIL);
}

/* See description in tapi_smb_internal.h */
const char *
tapi_smb_factory_ta(tapi_job_factory_t *factory)
{
    const char *ta = tapi_job_factory_ta(factory);

    if (ta == NULL)
        ERROR("Cannot determine the agent behind the job factory");

    return ta;
}
