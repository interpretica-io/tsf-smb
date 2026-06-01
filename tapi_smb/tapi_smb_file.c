/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Interpretica Unipessoal Lda */
/** @file
 * @brief Files on an SMB share
 *
 * Samba drives smbclient with one @c -c command at a time, so that a
 * failure is the command's own; even so the output is read for an NT
 * status, because some commands - @c rmdir of a missing directory,
 * measured on Samba 4.17 - print the status and still exit 0. macOS
 * and Windows work through a mount: the share is mounted, the file
 * operation is an ordinary filesystem one, and the mount is taken down
 * again.
 */

#define TE_LGR_USER "TAPI SMB"

#include "te_config.h"

#include <ctype.h>
#include <stdlib.h>
#include <string.h>

#include "logger_api.h"
#include "te_alloc.h"
#include "te_str.h"
#include "te_string.h"
#include "te_vector.h"
#include "tapi_cfg_base.h"
#include "tapi_file.h"
#include "rcf_api.h"

#include "tapi_smb.h"
#include "tapi_smb_file.h"
#include "tapi_smb_internal.h"

/** What one smbclient/mount operation is. */
typedef enum smb_op {
    SMB_OP_PUT,
    SMB_OP_GET,
    SMB_OP_LS,
    SMB_OP_MKDIR,
    SMB_OP_RMDIR,
    SMB_OP_UNLINK,
    SMB_OP_EXISTS,
} smb_op;

/** Append a path to a string with backslashes, for a mount path. */
static void
smb_backslashes(te_string *dest, const char *path)
{
    for (; *path != '\0'; path++)
        te_string_append(dest, "%c", *path == '/' ? '\\' : *path);
}

/** Run one smbclient command and read the result for an NT status. */
static te_errno
smb_samba_cmd(tapi_job_factory_t *factory, const tapi_smb_target *target,
              const char *share, const char *command, int timeout_ms,
              te_string *out)
{
    te_vec args = TE_VEC_INIT(char *);
    te_string unc = TE_STRING_INIT;
    te_string own = TE_STRING_INIT;
    int code = 0;
    te_errno rc;

    tapi_smb_unc(target, &unc);
    te_string_append(&unc, "%s", share);

    tapi_smb_arg(&args, "%s", unc.ptr);
    tapi_smb_client_args(target, &args);
    tapi_smb_arg(&args, "-c");
    tapi_smb_arg(&args, "%s", command);

    rc = tapi_smb_sh(factory, "smbclient", &args, target->password,
                     timeout_ms, &own, &own, &code);
    if (rc == 0)
    {
        /*
         * The status text is authoritative, not the exit code: a
         * connection that failed shows the NT status here whatever it
         * exits, and a command that succeeded shows none.
         */
        rc = tapi_smb_nt_status(te_string_value(&own), NULL);
        if (rc == 0 && code != 0 && code != TAPI_SMB_EXIT_NOT_FOUND)
        {
            /* Failed without an NT status: a local or usage error. */
            ERROR("smbclient failed (exit %d): %s", code,
                  te_string_value(&own));
            rc = TE_RC(TE_TAPI, TE_EFAIL);
        }
        else if (code == TAPI_SMB_EXIT_NOT_FOUND)
        {
            rc = TE_RC(TE_TAPI, TE_ENOSYS);
        }
    }

    if (out != NULL)
        te_string_append(out, "%s", te_string_value(&own));

    te_vec_deep_free(&args);
    te_string_free(&unc);
    te_string_free(&own);

    return rc;
}

/** Parse one line of smbclient ls into an entry. */
static bool
smb_parse_ls_line(const char *line, tapi_smb_dirent *entry)
{
    char name[512];
    char attr[32];
    long size = -1;
    const char *p = line;
    size_t i = 0;

    while (*p == ' ' || *p == '\t')
        p++;

    /* Name up to the run of spaces before the attribute column. */
    while (*p != '\0' && !(p[0] == ' ' && p[1] == ' ') && i < sizeof(name) - 1)
        name[i++] = *p++;
    name[i] = '\0';

    if (name[0] == '\0' || strcmp(name, ".") == 0 || strcmp(name, "..") == 0)
        return false;

    while (*p == ' ')
        p++;
    /* The attribute letters, e.g. "D", "A", "AHS", or "N". */
    i = 0;
    while (isalpha((unsigned char)*p) && i < sizeof(attr) - 1)
        attr[i++] = *p++;
    attr[i] = '\0';

    while (*p == ' ')
        p++;
    if (isdigit((unsigned char)*p))
        size = strtol(p, NULL, 10);

    entry->name = TE_STRDUP(name);
    entry->is_dir = strchr(attr, 'D') != NULL;
    entry->size = entry->is_dir ? -1 : size;

    return true;
}

/** List a directory with Samba. */
static te_errno
smb_samba_ls(tapi_job_factory_t *factory, const tapi_smb_target *target,
             const char *share, const char *path, int timeout_ms,
             te_vec *entries)
{
    te_string command = TE_STRING_INIT;
    te_string out = TE_STRING_INIT;
    const char *line;
    te_errno rc;

    te_string_append(&command, "ls ");
    if (path != NULL && *path != '\0')
    {
        smb_backslashes(&command, path);
        te_string_append(&command, "\\*");
    }
    else
    {
        te_string_append(&command, "\\*");
    }

    rc = smb_samba_cmd(factory, target, share, command.ptr, timeout_ms,
                       &out);
    if (rc != 0)
        goto out;

    for (line = te_string_value(&out); line != NULL && *line != '\0'; )
    {
        tapi_smb_dirent entry;
        const char *nl = strchr(line, '\n');
        size_t len = nl != NULL ? (size_t)(nl - line) : strlen(line);
        char buf[600];

        if (len < sizeof(buf))
        {
            te_strlcpy(buf, line, len + 1);
            /*
             * The footer is "\t\t<n> blocks of size ..."; checked on
             * the copied line, not on @c line, which runs to the end
             * of the output and would match the footer for every entry
             * above it.
             */
            if (strstr(buf, "blocks of size") == NULL &&
                smb_parse_ls_line(buf, &entry))
            {
                TE_VEC_APPEND(entries, entry);
            }
        }

        line = nl != NULL ? nl + 1 : NULL;
    }

out:
    te_string_free(&command);
    te_string_free(&out);

    return rc;
}

/**
 * Build the shell line that mounts a share, runs @p body against the
 * mount point (named @c $M), and unmounts - for macOS. @p body is a
 * shell fragment using @c $M.
 */
static void
smb_macos_mount_sh(const tapi_smb_target *target, const char *share,
                   const char *body, te_string *sh)
{
    te_string_append(sh, "M=/tmp/tsf_smb_$$; mkdir -p \"$M\"; ");
    te_string_append(sh, "mount_smbfs %s //",
                     target->user == NULL ? "-N" : "");
    if (target->user != NULL && *target->user != '\0')
        te_string_append(sh, "%s@", target->user);
    te_string_append(sh, "%s/%s \"$M\" || { rmdir \"$M\"; exit 70; }; ",
                     target->server, share);
    te_string_append(sh, "( %s ); r=$?; ", body);
    te_string_append(sh, "umount \"$M\" 2>/dev/null; "
                     "rmdir \"$M\" 2>/dev/null; exit $r");
}

/** Run a mount-based shell body on a macOS agent. */
static te_errno
smb_macos_run(tapi_job_factory_t *factory, const tapi_smb_target *target,
              const char *share, const char *body, int timeout_ms,
              te_string *out)
{
    te_vec args = TE_VEC_INIT(char *);
    te_string sh = TE_STRING_INIT;
    te_string own = TE_STRING_INIT;
    int code = 0;
    te_errno rc;

    smb_macos_mount_sh(target, share, body, &sh);
    tapi_smb_arg(&args, "-c");
    tapi_smb_arg(&args, "%s", sh.ptr);

    rc = tapi_smb_sh(factory, "/bin/sh", &args, target->password,
                     timeout_ms, &own, &own, &code);
    if (rc == 0)
    {
        if (code == 70)
            rc = TE_RC(TE_TAPI, TE_EACCES);
        else if (code != 0)
            rc = TE_RC(TE_TAPI, TE_EFAIL);
    }
    if (out != NULL)
        te_string_append(out, "%s", te_string_value(&own));
    if (rc != 0 && code != 70)
        ERROR("Mounted operation on %s failed: %s", share,
              te_string_value(&own));

    te_vec_deep_free(&args);
    te_string_free(&sh);
    te_string_free(&own);

    return rc;
}

/** Quote a path as a single-quoted shell word. */
static void
smb_sh_quote(te_string *dest, const char *value)
{
    te_string_append(dest, "'");
    for (; *value != '\0'; value++)
    {
        if (*value == '\'')
            te_string_append(dest, "'\\''");
        else
            te_string_append(dest, "%c", *value);
    }
    te_string_append(dest, "'");
}

/**
 * Quote a local path for an smbclient @c -c command.
 *
 * The @c -c string is smbclient's own to parse, not the shell's, and
 * its tokenizer takes a double-quoted word - measured on Samba 4.17, a
 * single-quoted path came through with the quotes still on it and
 * "does not exist". So the local path is wrapped in double quotes,
 * which also lets it hold a space.
 */
static void
smb_client_quote(te_string *dest, const char *value)
{
    te_string_append(dest, "\"%s\"", value);
}

/**
 * Build the PowerShell that maps a share to a PSDrive @c X, runs
 * @p body (using @c $root as the share root), and unmaps.
 */
static void
smb_windows_map_ps(const tapi_smb_target *target, const char *share,
                   const char *body, te_string *ps)
{
    te_string_append(ps, "$s = ");
    tapi_smb_ps_quote(ps, target->server);
    te_string_append(ps, "; $sh = ");
    tapi_smb_ps_quote(ps, share);
    te_string_append(ps, "; $root = \"\\\\$s\\$sh\"; ");
    te_string_append(ps, "$u = ");
    tapi_smb_ps_quote(ps, target->user != NULL ? target->user : "");
    te_string_append(ps, "; $p = ");
    tapi_smb_ps_quote(ps, target->password != NULL ? target->password : "");
    te_string_append(ps,
        "; try { if ($u) { $sec = ConvertTo-SecureString $p -AsPlainText "
        "-Force; $cred = New-Object PSCredential($u, $sec); "
        "New-SmbMapping -RemotePath $root -Credential $cred "
        "-ErrorAction Stop | Out-Null } else { New-SmbMapping "
        "-RemotePath $root -ErrorAction Stop | Out-Null } } "
        "catch { 'SMBERR ' + $_.Exception.Message; exit 70 }; "
        "try { ");
    te_string_append(ps, "%s", body);
    te_string_append(ps,
        " } finally { Remove-SmbMapping -RemotePath $root -Force "
        "-ErrorAction SilentlyContinue | Out-Null }");
}

/** Run a mapping-based PowerShell body on a Windows agent. */
static te_errno
smb_windows_run(tapi_job_factory_t *factory, const tapi_smb_target *target,
                const char *share, const char *body, int timeout_ms,
                te_string *out)
{
    te_string ps = TE_STRING_INIT;
    te_string own = TE_STRING_INIT;
    int code = 0;
    te_errno rc;

    smb_windows_map_ps(target, share, body, &ps);
    rc = tapi_smb_powershell(factory, ps.ptr, timeout_ms, &own, &own,
                             &code);
    if (rc == 0)
    {
        const char *text = te_string_value(&own);

        if (strstr(text, "SMBERR") != NULL)
        {
            rc = strstr(text, "denied") != NULL ||
                 strstr(text, "password") != NULL ?
                 TE_RC(TE_TAPI, TE_EACCES) : TE_RC(TE_TAPI, TE_EFAIL);
        }
        else if (strstr(text, "SMBFAIL") != NULL)
        {
            rc = strstr(text, "DirectoryNotEmpty") != NULL ?
                 TE_RC(TE_TAPI, TE_ENOTEMPTY) :
                 strstr(text, "NotFound") != NULL ?
                 TE_RC(TE_TAPI, TE_ENOENT) : TE_RC(TE_TAPI, TE_EFAIL);
        }
    }
    if (out != NULL)
        te_string_append(out, "%s", te_string_value(&own));

    te_string_free(&ps);
    te_string_free(&own);

    return rc;
}

/** The whole path on a mounted share, as one string with a separator. */
static void
smb_mount_path(te_string *dest, const char *var, const char *remote,
               char sep)
{
    te_string_append(dest, "%s", var);
    if (remote != NULL && *remote != '\0')
    {
        te_string_append(dest, "%c", sep);
        for (; *remote != '\0'; remote++)
        {
            char c = *remote;

            if (c == '/' || c == '\\')
                c = sep;
            te_string_append(dest, "%c", c);
        }
    }
}

/** One file operation, dispatched by backend. */
static te_errno
smb_do(tapi_job_factory_t *factory, tapi_smb_backend backend,
       const tapi_smb_target *target, const char *share, smb_op op,
       const char *remote, const char *local, int timeout_ms,
       te_string *out)
{
    te_string frag = TE_STRING_INIT;
    te_string body = TE_STRING_INIT;
    te_errno rc;

    switch (backend)
    {
        case TAPI_SMB_SAMBA:
            switch (op)
            {
                case SMB_OP_PUT:
                    te_string_append(&frag, "put ");
                    smb_client_quote(&frag, local);
                    te_string_append(&frag, " ");
                    smb_backslashes(&frag, remote);
                    break;
                case SMB_OP_GET:
                    te_string_append(&frag, "get ");
                    smb_backslashes(&frag, remote);
                    te_string_append(&frag, " ");
                    smb_client_quote(&frag, local);
                    break;
                case SMB_OP_MKDIR:
                    te_string_append(&frag, "mkdir ");
                    smb_backslashes(&frag, remote);
                    break;
                case SMB_OP_RMDIR:
                    te_string_append(&frag, "rmdir ");
                    smb_backslashes(&frag, remote);
                    break;
                case SMB_OP_UNLINK:
                    te_string_append(&frag, "rm ");
                    smb_backslashes(&frag, remote);
                    break;
                case SMB_OP_EXISTS:
                    te_string_append(&frag, "allinfo ");
                    smb_backslashes(&frag, remote);
                    break;
                default:
                    rc = TE_RC(TE_TAPI, TE_EINVAL);
                    goto out;
            }
            rc = smb_samba_cmd(factory, target, share, frag.ptr, timeout_ms,
                               out);
            break;

        case TAPI_SMB_MACOS:
            switch (op)
            {
                case SMB_OP_PUT:
                    te_string_append(&body, "cp ");
                    smb_sh_quote(&body, local);
                    te_string_append(&body, " ");
                    smb_mount_path(&body, "\"$M\"", remote, '/');
                    break;
                case SMB_OP_GET:
                    te_string_append(&body, "cp ");
                    smb_mount_path(&body, "\"$M\"", remote, '/');
                    te_string_append(&body, " ");
                    smb_sh_quote(&body, local);
                    break;
                case SMB_OP_MKDIR:
                    te_string_append(&body, "mkdir ");
                    smb_mount_path(&body, "\"$M\"", remote, '/');
                    break;
                case SMB_OP_RMDIR:
                    te_string_append(&body, "rmdir ");
                    smb_mount_path(&body, "\"$M\"", remote, '/');
                    break;
                case SMB_OP_UNLINK:
                    te_string_append(&body, "rm -f ");
                    smb_mount_path(&body, "\"$M\"", remote, '/');
                    break;
                case SMB_OP_EXISTS:
                    te_string_append(&body, "test -e ");
                    smb_mount_path(&body, "\"$M\"", remote, '/');
                    break;
                default:
                    rc = TE_RC(TE_TAPI, TE_EINVAL);
                    goto out;
            }
            rc = smb_macos_run(factory, target, share, body.ptr, timeout_ms,
                               out);
            break;

        case TAPI_SMB_WINDOWS:
            switch (op)
            {
                case SMB_OP_PUT:
                    te_string_append(&body, "Copy-Item -LiteralPath ");
                    tapi_smb_ps_quote(&body, local);
                    te_string_append(&body, " -Destination ");
                    smb_mount_path(&frag, "$root", remote, '\\');
                    tapi_smb_ps_quote(&body, frag.ptr);
                    te_string_append(&body, " -Force -ErrorAction Stop");
                    break;
                case SMB_OP_GET:
                    te_string_append(&body, "Copy-Item -LiteralPath ");
                    smb_mount_path(&frag, "$root", remote, '\\');
                    tapi_smb_ps_quote(&body, frag.ptr);
                    te_string_append(&body, " -Destination ");
                    tapi_smb_ps_quote(&body, local);
                    te_string_append(&body, " -Force -ErrorAction Stop");
                    break;
                case SMB_OP_MKDIR:
                    te_string_append(&body, "New-Item -ItemType Directory "
                                     "-Path ");
                    smb_mount_path(&frag, "$root", remote, '\\');
                    tapi_smb_ps_quote(&body, frag.ptr);
                    te_string_append(&body, " -ErrorAction Stop | Out-Null");
                    break;
                case SMB_OP_RMDIR:
                    smb_mount_path(&frag, "$root", remote, '\\');
                    te_string_append(&body,
                        "if ((Get-ChildItem -LiteralPath ");
                    tapi_smb_ps_quote(&body, frag.ptr);
                    te_string_append(&body,
                        " -Force | Measure-Object).Count -gt 0) "
                        "{ 'SMBFAIL DirectoryNotEmpty'; exit 71 }; "
                        "Remove-Item -LiteralPath ");
                    tapi_smb_ps_quote(&body, frag.ptr);
                    te_string_append(&body, " -ErrorAction Stop");
                    break;
                case SMB_OP_UNLINK:
                    te_string_append(&body, "Remove-Item -LiteralPath ");
                    smb_mount_path(&frag, "$root", remote, '\\');
                    tapi_smb_ps_quote(&body, frag.ptr);
                    te_string_append(&body, " -Force -ErrorAction Stop");
                    break;
                case SMB_OP_EXISTS:
                    te_string_append(&body, "if (Test-Path -LiteralPath ");
                    smb_mount_path(&frag, "$root", remote, '\\');
                    tapi_smb_ps_quote(&body, frag.ptr);
                    te_string_append(&body,
                        ") { 'EXISTS yes' } else { 'EXISTS no' }");
                    break;
                default:
                    rc = TE_RC(TE_TAPI, TE_EINVAL);
                    goto out;
            }
            rc = smb_windows_run(factory, target, share, body.ptr,
                                 timeout_ms, out);
            break;

        default:
            rc = TE_RC(TE_TAPI, TE_EINVAL);
            break;
    }

out:
    te_string_free(&frag);
    te_string_free(&body);

    return rc;
}

/** Resolve, check the target, and dispatch one operation. */
static te_errno
smb_file_op(tapi_job_factory_t *factory, tapi_smb_backend backend,
            const tapi_smb_target *target, const char *share, smb_op op,
            const char *remote, const char *local, int timeout_ms,
            te_string *out)
{
    te_errno rc;

    rc = tapi_smb_resolve(factory, timeout_ms, &backend);
    if (rc != 0)
        return rc;
    if (target == NULL || target->server == NULL || share == NULL)
    {
        ERROR("An SMB file operation needs a server and a share");
        return TE_RC(TE_TAPI, TE_EINVAL);
    }

    return smb_do(factory, backend, target, share, op, remote, local,
                  timeout_ms, out);
}

/* See description in tapi_smb_file.h */
te_errno
tapi_smb_put(tapi_job_factory_t *factory, tapi_smb_backend backend,
             const tapi_smb_target *target, const char *share,
             const char *remote, const char *local, int timeout_ms)
{
    return smb_file_op(factory, backend, target, share, SMB_OP_PUT, remote,
                       local, timeout_ms, NULL);
}

/* See description in tapi_smb_file.h */
te_errno
tapi_smb_get(tapi_job_factory_t *factory, tapi_smb_backend backend,
             const tapi_smb_target *target, const char *share,
             const char *remote, const char *local, int timeout_ms)
{
    return smb_file_op(factory, backend, target, share, SMB_OP_GET, remote,
                       local, timeout_ms, NULL);
}

/** A temporary path on the agent, keeping @p suffix. */
static te_errno
smb_ta_tmp(tapi_job_factory_t *factory, const char *suffix, te_string *path)
{
    const char *ta = tapi_smb_factory_ta(factory);
    char *tmp_dir;

    if (ta == NULL)
        return TE_RC(TE_TAPI, TE_EINVAL);

    tmp_dir = tapi_cfg_base_get_ta_dir(ta, TAPI_CFG_BASE_TA_DIR_TMP);
    if (tmp_dir == NULL)
        return TE_RC(TE_TAPI, TE_EFAIL);

    tapi_file_make_custom_pathname(path, tmp_dir, suffix);
    free(tmp_dir);

    return 0;
}

/* See description in tapi_smb_file.h */
te_errno
tapi_smb_put_from_engine(tapi_job_factory_t *factory,
                         tapi_smb_backend backend,
                         const tapi_smb_target *target, const char *share,
                         const char *remote, const char *engine_path,
                         int timeout_ms)
{
    const char *ta = tapi_smb_factory_ta(factory);
    te_string local = TE_STRING_INIT;
    te_errno rc;

    if (ta == NULL)
        return TE_RC(TE_TAPI, TE_EINVAL);

    rc = smb_ta_tmp(factory, ".upload", &local);
    if (rc == 0)
        rc = rcf_ta_put_file(ta, 0, engine_path, local.ptr);
    if (rc != 0)
    {
        ERROR("Failed to put %s on TA %s: %r", engine_path, ta, rc);
        te_string_free(&local);
        return rc;
    }

    rc = tapi_smb_put(factory, backend, target, share, remote, local.ptr,
                      timeout_ms);

    tapi_file_ta_unlink_fmt(ta, "%s", local.ptr);
    te_string_free(&local);

    return rc;
}

/* See description in tapi_smb_file.h */
te_errno
tapi_smb_get_to_engine(tapi_job_factory_t *factory, tapi_smb_backend backend,
                       const tapi_smb_target *target, const char *share,
                       const char *remote, const char *engine_path,
                       int timeout_ms)
{
    const char *ta = tapi_smb_factory_ta(factory);
    te_string local = TE_STRING_INIT;
    te_errno rc;

    if (ta == NULL)
        return TE_RC(TE_TAPI, TE_EINVAL);

    rc = smb_ta_tmp(factory, ".download", &local);
    if (rc == 0)
        rc = tapi_smb_get(factory, backend, target, share, remote,
                          local.ptr, timeout_ms);
    if (rc == 0)
        rc = rcf_ta_get_file(ta, 0, local.ptr, engine_path);
    if (rc != 0 && TE_RC_GET_ERROR(rc) != TE_ENOENT)
        ERROR("Failed to get %s to the engine: %r", remote, rc);

    tapi_file_ta_unlink_fmt(ta, "%s", local.ptr);
    te_string_free(&local);

    return rc;
}

/* See description in tapi_smb_file.h */
te_errno
tapi_smb_write(tapi_job_factory_t *factory, tapi_smb_backend backend,
               const tapi_smb_target *target, const char *share,
               const char *remote, const void *content, size_t len,
               int timeout_ms)
{
    const char *ta = tapi_smb_factory_ta(factory);
    te_string local = TE_STRING_INIT;
    te_errno rc;

    if (ta == NULL)
        return TE_RC(TE_TAPI, TE_EINVAL);

    rc = smb_ta_tmp(factory, ".content", &local);
    if (rc == 0)
    {
        rc = tapi_file_create_ta(ta, local.ptr, "%.*s", (int)len,
                                 (const char *)content);
    }
    if (rc == 0)
    {
        rc = tapi_smb_put(factory, backend, target, share, remote,
                          local.ptr, timeout_ms);
    }

    tapi_file_ta_unlink_fmt(ta, "%s", local.ptr);
    te_string_free(&local);

    return rc;
}

/* See description in tapi_smb_file.h */
te_errno
tapi_smb_read(tapi_job_factory_t *factory, tapi_smb_backend backend,
              const tapi_smb_target *target, const char *share,
              const char *remote, int timeout_ms, te_string *content)
{
    const char *ta = tapi_smb_factory_ta(factory);
    te_string local = TE_STRING_INIT;
    char *buf = NULL;
    te_errno rc;

    if (ta == NULL)
        return TE_RC(TE_TAPI, TE_EINVAL);

    rc = smb_ta_tmp(factory, ".content", &local);
    if (rc == 0)
    {
        rc = tapi_smb_get(factory, backend, target, share, remote,
                          local.ptr, timeout_ms);
    }
    if (rc == 0)
        rc = tapi_file_read_ta(ta, local.ptr, &buf);
    if (rc == 0)
    {
        te_string_append(content, "%s", buf);
        free(buf);
    }

    tapi_file_ta_unlink_fmt(ta, "%s", local.ptr);
    te_string_free(&local);

    return rc;
}

/* See description in tapi_smb_file.h */
te_errno
tapi_smb_ls(tapi_job_factory_t *factory, tapi_smb_backend backend,
            const tapi_smb_target *target, const char *share,
            const char *path, int timeout_ms, te_vec *entries)
{
    te_string out = TE_STRING_INIT;
    te_errno rc;

    rc = tapi_smb_resolve(factory, timeout_ms, &backend);
    if (rc != 0)
        return rc;

    switch (backend)
    {
        case TAPI_SMB_SAMBA:
            rc = smb_samba_ls(factory, target, share, path, timeout_ms,
                              entries);
            break;

        case TAPI_SMB_MACOS:
        {
            te_string body = TE_STRING_INIT;
            const char *line;

            /* One entry per line: "name/" for a directory. */
            te_string_append(&body, "cd ");
            smb_mount_path(&body, "\"$M\"", path, '/');
            te_string_append(&body,
                " 2>/dev/null && for e in * .*; do [ \"$e\" = . ] || "
                "[ \"$e\" = .. ] || [ ! -e \"$e\" ] || { if [ -d \"$e\" ]; "
                "then echo \"D $e\"; else echo \"F $(wc -c < \"$e\") $e\"; "
                "fi; }; done");
            rc = smb_macos_run(factory, target, share, body.ptr, timeout_ms,
                               &out);
            for (line = te_string_value(&out);
                 rc == 0 && line != NULL && *line != '\0'; )
            {
                tapi_smb_dirent entry;
                char kind;
                long size = -1;
                char name[512] = "";

                if (line[0] == 'D' && sscanf(line, "D %511[^\n]", name) == 1)
                {
                    entry.name = TE_STRDUP(name);
                    entry.is_dir = true;
                    entry.size = -1;
                    TE_VEC_APPEND(entries, entry);
                }
                else if (sscanf(line, "%c %ld %511[^\n]", &kind, &size,
                                name) == 3)
                {
                    entry.name = TE_STRDUP(name);
                    entry.is_dir = false;
                    entry.size = size;
                    TE_VEC_APPEND(entries, entry);
                }

                line = strchr(line, '\n');
                if (line != NULL)
                    line++;
            }
            te_string_free(&body);
            break;
        }

        case TAPI_SMB_WINDOWS:
        {
            te_string body = TE_STRING_INIT;
            te_string object = TE_STRING_INIT;
            const char *pos = NULL;
            te_string frag = TE_STRING_INIT;

            smb_mount_path(&frag, "$root", path, '\\');
            te_string_append(&body, "$d = ");
            tapi_smb_ps_quote(&body, frag.ptr);
            te_string_append(&body,
                "; ConvertTo-Json -Compress -InputObject @(Get-ChildItem "
                "-LiteralPath $d -Force | ForEach-Object { "
                "[pscustomobject]@{ Name = $_.Name;"
                " Dir = $_.PSIsContainer;"
                " Size = [long]($_.Length) } })");
            rc = smb_windows_run(factory, target, share, body.ptr,
                                 timeout_ms, &out);
            while (rc == 0 &&
                   (pos = tapi_smb_json_next(te_string_value(&out), pos,
                                             &object)) != NULL)
            {
                tapi_smb_dirent entry;
                te_string name = TE_STRING_INIT;
                long size = -1;

                if (tapi_smb_json_str(object.ptr, "Name", &name) &&
                    name.len != 0)
                {
                    entry.name = TE_STRDUP(name.ptr);
                    entry.is_dir = false;
                    tapi_smb_json_bool(object.ptr, "Dir", &entry.is_dir);
                    tapi_smb_json_int(object.ptr, "Size", &size);
                    entry.size = entry.is_dir ? -1 : size;
                    TE_VEC_APPEND(entries, entry);
                }
                te_string_free(&name);
                te_string_reset(&object);
            }
            te_string_free(&body);
            te_string_free(&object);
            te_string_free(&frag);
            break;
        }

        default:
            rc = TE_RC(TE_TAPI, TE_EINVAL);
            break;
    }

    te_string_free(&out);

    return rc;
}

/* See description in tapi_smb_file.h */
bool
tapi_smb_exists(tapi_job_factory_t *factory, tapi_smb_backend backend,
                const tapi_smb_target *target, const char *share,
                const char *remote, int timeout_ms)
{
    te_string out = TE_STRING_INIT;
    te_errno rc;
    bool exists;

    rc = smb_file_op(factory, backend, target, share, SMB_OP_EXISTS, remote,
                     NULL, timeout_ms, &out);

    /*
     * Samba and macOS say so by rc; Windows prints EXISTS yes/no with
     * rc 0 either way.
     */
    exists = rc == 0 && strstr(te_string_value(&out), "EXISTS no") == NULL;

    te_string_free(&out);

    return exists;
}

/* See description in tapi_smb_file.h */
te_errno
tapi_smb_mkdir(tapi_job_factory_t *factory, tapi_smb_backend backend,
               const tapi_smb_target *target, const char *share,
               const char *remote, int timeout_ms)
{
    return smb_file_op(factory, backend, target, share, SMB_OP_MKDIR, remote,
                       NULL, timeout_ms, NULL);
}

/* See description in tapi_smb_file.h */
te_errno
tapi_smb_rmdir(tapi_job_factory_t *factory, tapi_smb_backend backend,
               const tapi_smb_target *target, const char *share,
               const char *remote, int timeout_ms)
{
    return smb_file_op(factory, backend, target, share, SMB_OP_RMDIR, remote,
                       NULL, timeout_ms, NULL);
}

/* See description in tapi_smb_file.h */
te_errno
tapi_smb_unlink(tapi_job_factory_t *factory, tapi_smb_backend backend,
                const tapi_smb_target *target, const char *share,
                const char *remote, int timeout_ms)
{
    return smb_file_op(factory, backend, target, share, SMB_OP_UNLINK, remote,
                       NULL, timeout_ms, NULL);
}

/* See description in tapi_smb.h */
bool
tapi_smb_unix_extensions(tapi_job_factory_t *factory, tapi_smb_backend backend,
                         const tapi_smb_target *target, const char *share,
                         int timeout_ms)
{
    te_string out = TE_STRING_INIT;
    te_errno rc;
    bool yes;

    rc = tapi_smb_resolve(factory, timeout_ms, &backend);
    if (rc != 0)
        return false;
    if (target == NULL || target->server == NULL || share == NULL)
        return false;
    if (!tapi_smb_supports(backend, TAPI_SMB_FEAT_POSIX))
        return false;

    /*
     * The "posix" command asks smbclient to negotiate the CIFS UNIX
     * extensions and prints the server's answer: "Server supports CIFS
     * extensions ..." when they are there, "Server doesn't support
     * UNIX CIFS extensions" when they are not. The verdict is the text,
     * not the exit code.
     */
    rc = smb_samba_cmd(factory, target, share, "posix", timeout_ms, &out);
    yes = rc == 0 &&
          strstr(te_string_value(&out), "supports CIFS extensions") != NULL &&
          strstr(te_string_value(&out), "doesn't support") == NULL;

    te_string_free(&out);

    return yes;
}

/* See description in tapi_smb_file.h */
te_errno
tapi_smb_symlink(tapi_job_factory_t *factory, tapi_smb_backend backend,
                 const tapi_smb_target *target, const char *share,
                 const char *linkname, const char *points_to, int timeout_ms)
{
    te_string command = TE_STRING_INIT;
    te_errno rc;

    rc = tapi_smb_resolve(factory, timeout_ms, &backend);
    if (rc != 0)
        return rc;
    if (target == NULL || target->server == NULL || share == NULL ||
        linkname == NULL || points_to == NULL)
    {
        ERROR("An SMB symlink needs a server, a share, a name and a target");
        return TE_RC(TE_TAPI, TE_EINVAL);
    }
    if (!tapi_smb_supports(backend, TAPI_SMB_FEAT_POSIX))
    {
        ERROR("%s has no POSIX/CIFS UNIX extensions to make a symlink with",
              tapi_smb_backend2str(backend));
        return TE_RC(TE_TAPI, TE_EOPNOTSUPP);
    }

    /*
     * smbclient's posix "symlink <target> <newname>": the first word
     * is what the link points to, the second is the link. Both are
     * POSIX paths with forward slashes, so - unlike the ordinary file
     * commands - they are not turned into backslashes. They are
     * double-quoted for smbclient's own tokenizer, which is what reads
     * a -c command.
     */
    te_string_append(&command, "posix; symlink ");
    smb_client_quote(&command, points_to);
    te_string_append(&command, " ");
    smb_client_quote(&command, linkname);

    rc = smb_samba_cmd(factory, target, share, command.ptr, timeout_ms, NULL);

    te_string_free(&command);

    return rc;
}

/* See description in tapi_smb_internal.h */
te_errno
tapi_smb_posix_unlink(tapi_job_factory_t *factory, tapi_smb_backend backend,
                      const tapi_smb_target *target, const char *share,
                      const char *name, int timeout_ms)
{
    te_string command = TE_STRING_INIT;
    te_errno rc;

    rc = tapi_smb_resolve(factory, timeout_ms, &backend);
    if (rc != 0)
        return rc;
    if (target == NULL || target->server == NULL || share == NULL ||
        name == NULL)
    {
        return TE_RC(TE_TAPI, TE_EINVAL);
    }
    if (!tapi_smb_supports(backend, TAPI_SMB_FEAT_POSIX))
        return TE_RC(TE_TAPI, TE_EOPNOTSUPP);

    /*
     * posix_unlink removes the name itself, following nothing - so a
     * symlink node goes and the file it points to is left. This is why
     * the chain's cleanup uses it and not the ordinary rm.
     */
    te_string_append(&command, "posix; posix_unlink ");
    smb_client_quote(&command, name);

    rc = smb_samba_cmd(factory, target, share, command.ptr, timeout_ms, NULL);

    te_string_free(&command);

    return rc;
}

/** Read a getfacl permission triple ("rwx", "r--", ...) as three bits. */
static long
smb_perm_triple(const char *p)
{
    long v = 0;

    if (p[0] == 'r')
        v |= 4;
    if (p[1] == 'w')
        v |= 2;
    /* x, or the set-id/sticky letters that stand in the execute slot. */
    if (p[2] == 'x' || p[2] == 's' || p[2] == 'S' || p[2] == 't' ||
        p[2] == 'T')
    {
        v |= 1;
    }

    return v;
}

/** Read the number after a getfacl "# owner:"/"# group:" label. */
static bool
smb_getfacl_num(const char *text, const char *label, long *value)
{
    const char *found = strstr(text, label);

    if (found == NULL)
        return false;

    found += strlen(label);
    while (*found == ' ' || *found == '\t')
        found++;

    return te_strtol_silent(found, 10, value) == 0;
}

/* See description in tapi_smb_file.h */
te_errno
tapi_smb_stat(tapi_job_factory_t *factory, tapi_smb_backend backend,
              const tapi_smb_target *target, const char *share,
              const char *remote, int timeout_ms, tapi_smb_stat_info *info)
{
    te_string command = TE_STRING_INIT;
    te_string out = TE_STRING_INIT;
    const char *text;
    const char *owner_perm;
    const char *group_perm;
    const char *other_perm;
    te_errno rc;

    if (info == NULL)
        return TE_RC(TE_TAPI, TE_EINVAL);

    info->uid = -1;
    info->gid = -1;
    info->mode = -1;
    info->size = -1;
    info->is_dir = false;
    info->is_symlink = false;

    rc = tapi_smb_resolve(factory, timeout_ms, &backend);
    if (rc != 0)
        return rc;
    if (target == NULL || target->server == NULL || share == NULL ||
        remote == NULL)
    {
        ERROR("An SMB stat needs a server, a share and a path");
        return TE_RC(TE_TAPI, TE_EINVAL);
    }
    if (!tapi_smb_supports(backend, TAPI_SMB_FEAT_POSIX))
    {
        ERROR("%s has no POSIX/CIFS UNIX extensions to stat with",
              tapi_smb_backend2str(backend));
        return TE_RC(TE_TAPI, TE_EOPNOTSUPP);
    }

    /*
     * getfacl over the UNIX extensions prints the numeric owner and
     * group and a base ACL - the u/g/o permission triples - which is
     * the owner and the mode this reads. It is a stable, machine-shaped
     * output across Samba versions, where "stat" has varied. It follows
     * a symlink to its target, which is what a wide-links check wants:
     * getfacl of the link that escaped the share reads the file it
     * reached.
     */
    te_string_append(&command, "posix; getfacl ");
    smb_client_quote(&command, remote);

    rc = smb_samba_cmd(factory, target, share, command.ptr, timeout_ms, &out);
    if (rc != 0)
        goto out;

    text = te_string_value(&out);
    smb_getfacl_num(text, "# owner:", &info->uid);
    smb_getfacl_num(text, "# group:", &info->gid);

    owner_perm = strstr(text, "user::");
    group_perm = strstr(text, "group::");
    other_perm = strstr(text, "other::");
    if (owner_perm != NULL && group_perm != NULL && other_perm != NULL)
    {
        info->mode = (smb_perm_triple(owner_perm + strlen("user::")) << 6) |
                     (smb_perm_triple(group_perm + strlen("group::")) << 3) |
                     smb_perm_triple(other_perm + strlen("other::"));
    }

    if (info->uid == -1 && info->mode == -1)
    {
        ERROR("getfacl gave no owner or mode this could read: %s", text);
        rc = TE_RC(TE_TAPI, TE_EPROTO);
    }

out:
    te_string_free(&command);
    te_string_free(&out);

    return rc;
}

/* See description in tapi_smb_file.h */
void
tapi_smb_dirents_free(te_vec *entries)
{
    tapi_smb_dirent *entry;

    TE_VEC_FOREACH(entries, entry)
        free(entry->name);
    te_vec_free(entries);
}
