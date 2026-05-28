/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (C) 2026 Interpretica Unipessoal Lda */
/** @file
 * @brief SMB from a test: backends, targets, listing shares
 *
 * One function per operation and a switch over the backend inside it.
 * The three systems share the idea of a share and very little of the
 * way to reach one.
 */

#define TE_LGR_USER "TAPI SMB"

#include "te_config.h"

#include <stdlib.h>
#include <string.h>

#include "logger_api.h"
#include "te_alloc.h"
#include "te_str.h"
#include "te_string.h"
#include "te_vector.h"

#include "tapi_smb.h"
#include "tapi_smb_internal.h"

/* See description in tapi_smb.h */
const char *
tapi_smb_backend2str(tapi_smb_backend backend)
{
    switch (backend)
    {
        case TAPI_SMB_SAMBA:
            return "samba";
        case TAPI_SMB_MACOS:
            return "macos";
        case TAPI_SMB_WINDOWS:
            return "windows";
        default:
            return "auto";
    }
}

/* See description in tapi_smb.h */
const char *
tapi_smb_dialect2str(tapi_smb_dialect dialect)
{
    switch (dialect)
    {
        case TAPI_SMB_DIALECT_NT1:
            return "SMB1";
        case TAPI_SMB_DIALECT_SMB2_02:
            return "SMB2.0.2";
        case TAPI_SMB_DIALECT_SMB2_10:
            return "SMB2.1";
        case TAPI_SMB_DIALECT_SMB3_00:
            return "SMB3.0";
        case TAPI_SMB_DIALECT_SMB3_02:
            return "SMB3.0.2";
        case TAPI_SMB_DIALECT_SMB3_11:
            return "SMB3.1.1";
        default:
            return "any";
    }
}

/* See description in tapi_smb_internal.h */
const char *
tapi_smb_dialect2samba(tapi_smb_dialect dialect)
{
    switch (dialect)
    {
        case TAPI_SMB_DIALECT_NT1:
            return "NT1";
        case TAPI_SMB_DIALECT_SMB2_02:
            return "SMB2_02";
        case TAPI_SMB_DIALECT_SMB2_10:
            return "SMB2_10";
        case TAPI_SMB_DIALECT_SMB3_00:
            return "SMB3_00";
        case TAPI_SMB_DIALECT_SMB3_02:
            return "SMB3_02";
        case TAPI_SMB_DIALECT_SMB3_11:
            return "SMB3_11";
        default:
            return NULL;
    }
}

/* See description in tapi_smb_internal.h */
tapi_smb_dialect
tapi_smb_str2dialect(const char *text)
{
    static const struct {
        const char *name;
        tapi_smb_dialect dialect;
    } names[] = {
        /* Longest and most specific first, so a prefix does not win. */
        { "SMB3_11", TAPI_SMB_DIALECT_SMB3_11 },
        { "SMB3.1.1", TAPI_SMB_DIALECT_SMB3_11 },
        { "3.1.1", TAPI_SMB_DIALECT_SMB3_11 },
        { "311", TAPI_SMB_DIALECT_SMB3_11 },
        { "SMB3_02", TAPI_SMB_DIALECT_SMB3_02 },
        { "SMB3.0.2", TAPI_SMB_DIALECT_SMB3_02 },
        { "3.0.2", TAPI_SMB_DIALECT_SMB3_02 },
        { "302", TAPI_SMB_DIALECT_SMB3_02 },
        { "SMB3_10", TAPI_SMB_DIALECT_SMB3_11 },
        { "SMB3_00", TAPI_SMB_DIALECT_SMB3_00 },
        { "SMB3.0", TAPI_SMB_DIALECT_SMB3_00 },
        { "SMB3", TAPI_SMB_DIALECT_SMB3_00 },
        { "300", TAPI_SMB_DIALECT_SMB3_00 },
        { "SMB2_10", TAPI_SMB_DIALECT_SMB2_10 },
        { "SMB2.1", TAPI_SMB_DIALECT_SMB2_10 },
        { "2.1", TAPI_SMB_DIALECT_SMB2_10 },
        { "210", TAPI_SMB_DIALECT_SMB2_10 },
        { "SMB2_02", TAPI_SMB_DIALECT_SMB2_02 },
        { "SMB2.0.2", TAPI_SMB_DIALECT_SMB2_02 },
        { "SMB2.002", TAPI_SMB_DIALECT_SMB2_02 },
        { "SMB2", TAPI_SMB_DIALECT_SMB2_02 },
        { "202", TAPI_SMB_DIALECT_SMB2_02 },
        { "NT LM 0.12", TAPI_SMB_DIALECT_NT1 },
        { "NT1", TAPI_SMB_DIALECT_NT1 },
        { "SMB1", TAPI_SMB_DIALECT_NT1 },
    };
    size_t i;

    if (text == NULL)
        return TAPI_SMB_DIALECT_ANY;

    while (*text == ' ' || *text == '[')
        text++;

    for (i = 0; i < TE_ARRAY_LEN(names); i++)
    {
        if (strncmp(text, names[i].name, strlen(names[i].name)) == 0)
            return names[i].dialect;
    }

    return TAPI_SMB_DIALECT_ANY;
}

/* See description in tapi_smb.h */
unsigned int
tapi_smb_features(tapi_smb_backend backend)
{
    switch (backend)
    {
        case TAPI_SMB_SAMBA:
            return TAPI_SMB_FEAT_LIST | TAPI_SMB_FEAT_FILES |
                   TAPI_SMB_FEAT_DIALECT | TAPI_SMB_FEAT_SIGNING |
                   TAPI_SMB_FEAT_ENCRYPT | TAPI_SMB_FEAT_NEGOTIATED |
                   TAPI_SMB_FEAT_SERVE;

        case TAPI_SMB_MACOS:
            /*
             * No dialect or signing per connection: macOS keeps those
             * in nsmb.conf, which is the whole machine's, and this
             * library does not rewrite a machine-wide file behind a
             * test. No serving: macOS shares through System Preferences
             * and a launchd service, not a command a test drives.
             */
            return TAPI_SMB_FEAT_LIST | TAPI_SMB_FEAT_FILES |
                   TAPI_SMB_FEAT_ENCRYPT | TAPI_SMB_FEAT_NEGOTIATED;

        case TAPI_SMB_WINDOWS:
            return TAPI_SMB_FEAT_LIST | TAPI_SMB_FEAT_FILES |
                   TAPI_SMB_FEAT_DIALECT | TAPI_SMB_FEAT_SIGNING |
                   TAPI_SMB_FEAT_ENCRYPT | TAPI_SMB_FEAT_NEGOTIATED |
                   TAPI_SMB_FEAT_SERVE;

        default:
            return 0;
    }
}

/* See description in tapi_smb.h */
bool
tapi_smb_supports(tapi_smb_backend backend, unsigned int feature)
{
    return (tapi_smb_features(backend) & feature) == feature;
}

/** Refuse a target that asks for what the backend cannot force. */
static te_errno
smb_target_check(tapi_smb_backend backend, const tapi_smb_target *target)
{
    if (target == NULL || target->server == NULL)
    {
        ERROR("An SMB target needs a server");
        return TE_RC(TE_TAPI, TE_EINVAL);
    }

    if ((target->min_dialect != TAPI_SMB_DIALECT_ANY ||
         target->max_dialect != TAPI_SMB_DIALECT_ANY) &&
        !tapi_smb_supports(backend, TAPI_SMB_FEAT_DIALECT))
    {
        ERROR("%s cannot choose the dialect per connection",
              tapi_smb_backend2str(backend));
        return TE_RC(TE_TAPI, TE_EOPNOTSUPP);
    }

    if (target->require_signing &&
        !tapi_smb_supports(backend, TAPI_SMB_FEAT_SIGNING))
    {
        ERROR("%s cannot require signing per connection",
              tapi_smb_backend2str(backend));
        return TE_RC(TE_TAPI, TE_EOPNOTSUPP);
    }

    return 0;
}

/* See description in tapi_smb_internal.h */
void
tapi_smb_unc(const tapi_smb_target *target, te_string *unc)
{
    te_string_append(unc, "//%s/", target->server);
}

/* See description in tapi_smb_internal.h */
te_errno
tapi_smb_client_args(const tapi_smb_target *target, te_vec *args)
{
    if (target->user == NULL)
    {
        /* A null session: no user, no password prompt. */
        tapi_smb_arg(args, "-N");
    }
    else
    {
        tapi_smb_arg(args, "-U");
        tapi_smb_arg(args, "%s", target->user);
        /* The password travels in PASSWD; -U carries only the name. */
    }

    if (target->domain != NULL)
    {
        tapi_smb_arg(args, "-W");
        tapi_smb_arg(args, "%s", target->domain);
    }

    if (target->port != 0)
    {
        tapi_smb_arg(args, "-p");
        tapi_smb_arg(args, "%u", target->port);
    }

    if (target->max_dialect != TAPI_SMB_DIALECT_ANY)
    {
        tapi_smb_arg(args, "-m");
        tapi_smb_arg(args, "%s",
                     tapi_smb_dialect2samba(target->max_dialect));
    }
    if (target->min_dialect != TAPI_SMB_DIALECT_ANY)
    {
        tapi_smb_arg(args, "--option=client min protocol=%s",
                     tapi_smb_dialect2samba(target->min_dialect));
    }

    if (target->require_signing)
        tapi_smb_arg(args, "--option=client signing=mandatory");
    if (target->require_encryption)
        tapi_smb_arg(args, "--client-protection=encrypt");

    return 0;
}

/** Is smbclient there? */
static bool
smb_samba_probe(tapi_job_factory_t *factory, int timeout_ms)
{
    te_vec args = TE_VEC_INIT(char *);
    te_string out = TE_STRING_INIT;
    int code = 0;
    te_errno rc;

    tapi_smb_arg(&args, "--version");
    rc = tapi_smb_sh(factory, "smbclient", &args, NULL, timeout_ms, &out,
                     NULL, &code);

    te_vec_deep_free(&args);
    te_string_free(&out);

    return rc == 0 && code != TAPI_SMB_EXIT_NOT_FOUND && code >= 0;
}

/** Is macOS smbutil there (and not the Samba one on a Linux box)? */
static bool
smb_macos_probe(tapi_job_factory_t *factory, int timeout_ms)
{
    te_vec args = TE_VEC_INIT(char *);
    te_string out = TE_STRING_INIT;
    int code = 0;
    te_errno rc;

    /*
     * mount_smbfs is the one that is macOS and only macOS: Samba's
     * client tools do not include it, and its usage line names the
     * program. smbutil alone would also match a stray script.
     */
    tapi_smb_arg(&args, "-h");
    rc = tapi_smb_sh(factory, "mount_smbfs", &args, NULL, timeout_ms, &out,
                     NULL, &code);

    te_vec_deep_free(&args);
    te_string_free(&out);

    return rc == 0 && code != TAPI_SMB_EXIT_NOT_FOUND;
}

/** Is the Windows SMB client cmdlet there? */
static bool
smb_windows_probe(tapi_job_factory_t *factory, int timeout_ms)
{
    te_string out = TE_STRING_INIT;
    int code = 0;
    te_errno rc;

    rc = tapi_smb_powershell(factory,
            "if (Get-Command Get-SmbConnection -ErrorAction "
            "SilentlyContinue) { 'SMB yes' } else { 'SMB no' }",
            timeout_ms, &out, NULL, &code);

    te_string_free(&out);

    return rc == 0 && strstr(te_string_value(&out), "SMB yes") != NULL;
}

/* See description in tapi_smb.h */
te_errno
tapi_smb_detect(tapi_job_factory_t *factory, int timeout_ms,
                tapi_smb_backend *backend)
{
    /*
     * macOS first, because a Mac has smbclient too (Apple ships a
     * cut-down one) but the mount path is the one that works there;
     * mount_smbfs is what tells a Mac from a Samba host.
     */
    if (smb_macos_probe(factory, timeout_ms))
    {
        *backend = TAPI_SMB_MACOS;
        return 0;
    }
    if (smb_samba_probe(factory, timeout_ms))
    {
        *backend = TAPI_SMB_SAMBA;
        return 0;
    }
    if (smb_windows_probe(factory, timeout_ms))
    {
        *backend = TAPI_SMB_WINDOWS;
        return 0;
    }

    return TE_RC(TE_TAPI, TE_ENOENT);
}

/* See description in tapi_smb_internal.h */
te_errno
tapi_smb_resolve(tapi_job_factory_t *factory, int timeout_ms,
                 tapi_smb_backend *backend)
{
    te_errno rc;

    if (*backend != TAPI_SMB_AUTO)
        return 0;

    rc = tapi_smb_detect(factory, timeout_ms, backend);
    if (rc != 0)
        ERROR("There is no SMB client on the agent");

    return rc;
}

/* See description in tapi_smb.h */
bool
tapi_smb_available(tapi_job_factory_t *factory, tapi_smb_backend backend,
                   int timeout_ms)
{
    switch (backend)
    {
        case TAPI_SMB_AUTO:
        {
            tapi_smb_backend found;

            return tapi_smb_detect(factory, timeout_ms, &found) == 0;
        }
        case TAPI_SMB_SAMBA:
            return smb_samba_probe(factory, timeout_ms);
        case TAPI_SMB_MACOS:
            return smb_macos_probe(factory, timeout_ms);
        case TAPI_SMB_WINDOWS:
            return smb_windows_probe(factory, timeout_ms);
        default:
            return false;
    }
}

/** Add a share to the vector. */
static void
smb_share_add(te_vec *shares, const char *name, const char *comment,
              bool is_disk)
{
    tapi_smb_share_info info;

    info.name = TE_STRDUP(name);
    info.comment = comment != NULL && *comment != '\0' ?
                   TE_STRDUP(comment) : NULL;
    info.is_disk = is_disk;
    TE_VEC_APPEND(shares, info);
}

/** List shares with Samba's smbclient -L -g. */
static te_errno
smb_samba_list(tapi_job_factory_t *factory, const tapi_smb_target *target,
               int timeout_ms, te_vec *shares)
{
    te_vec args = TE_VEC_INIT(char *);
    te_string out = TE_STRING_INIT;
    te_string err = TE_STRING_INIT;
    te_string unc = TE_STRING_INIT;
    const char *line;
    int code = 0;
    te_errno rc;

    tapi_smb_arg(&args, "-L");
    tapi_smb_arg(&args, "%s", target->server);
    /* -g: "Disk|name|comment", one per line, easy to read. */
    tapi_smb_arg(&args, "-g");
    tapi_smb_client_args(target, &args);

    rc = tapi_smb_sh(factory, "smbclient", &args, target->password,
                     timeout_ms, &out, &err, &code);
    te_string_free(&unc);
    if (rc != 0)
        goto out;

    if (code != 0)
    {
        te_string both = TE_STRING_INIT;

        te_string_append(&both, "%s%s", te_string_value(&out),
                         te_string_value(&err));
        rc = tapi_smb_nt_status(both.ptr, NULL);
        te_string_free(&both);
        if (rc == 0)
            rc = TE_RC(TE_TAPI, TE_EFAIL);
        ERROR("Listing %s failed: %s%s", target->server,
              te_string_value(&out), te_string_value(&err));
        goto out;
    }

    for (line = te_string_value(&out); line != NULL && *line != '\0'; )
    {
        char type[32];
        char name[256];
        const char *bar2;
        const char *comment = "";

        if (sscanf(line, "%31[^|]|%255[^|\n]", type, name) == 2)
        {
            bar2 = strchr(line, '|');
            bar2 = bar2 != NULL ? strchr(bar2 + 1, '|') : NULL;
            if (bar2 != NULL)
            {
                static char buf[256];

                te_strlcpy(buf, bar2 + 1, sizeof(buf));
                buf[strcspn(buf, "\r\n")] = '\0';
                comment = buf;
            }
            smb_share_add(shares, name, comment,
                          strcasecmp(type, "Disk") == 0);
        }

        line = strchr(line, '\n');
        if (line != NULL)
            line++;
    }

out:
    te_vec_deep_free(&args);
    te_string_free(&out);
    te_string_free(&err);

    return rc;
}

/** List shares with macOS smbutil view. */
static te_errno
smb_macos_list(tapi_job_factory_t *factory, const tapi_smb_target *target,
               int timeout_ms, te_vec *shares)
{
    te_vec args = TE_VEC_INIT(char *);
    te_string out = TE_STRING_INIT;
    te_string url = TE_STRING_INIT;
    const char *line;
    bool in_table = false;
    int code = 0;
    te_errno rc;

    /*
     * smbutil view //user@host, with the password in the environment
     * the same way smbclient takes it. An anonymous target is -N and
     * a bare //host.
     */
    te_string_append(&url, "//");
    if (target->user != NULL && *target->user != '\0')
        te_string_append(&url, "%s@", target->user);
    te_string_append(&url, "%s", target->server);

    if (target->user == NULL)
        tapi_smb_arg(&args, "-N");
    tapi_smb_arg(&args, "view");
    tapi_smb_arg(&args, "%s", url.ptr);

    rc = tapi_smb_sh(factory, "smbutil", &args, target->password,
                     timeout_ms, &out, &out, &code);
    if (rc != 0)
        goto out;

    if (code != 0)
    {
        const char *text = te_string_value(&out);

        ERROR("smbutil view %s failed: %s", target->server, text);
        rc = strstr(text, "Authentication error") != NULL ||
             strstr(text, "Permission denied") != NULL ?
             TE_RC(TE_TAPI, TE_EACCES) : TE_RC(TE_TAPI, TE_EFAIL);
        goto out;
    }

    /*
     * A header line "Share ... Type ... Comments", then a rule of
     * dashes, then one share per line "name    Type    comment", then
     * a blank line and "N shares listed".
     */
    for (line = te_string_value(&out); line != NULL && *line != '\0'; )
    {
        size_t len = strcspn(line, "\r\n");

        if (!in_table)
        {
            if (len > 0 && strspn(line, "-") == len)
                in_table = true;
        }
        else if (len == 0 || strstr(line, "shares listed") == line ||
                 strstr(line, " shares listed") != NULL)
        {
            break;
        }
        else
        {
            char name[256] = "";
            char type[32] = "";

            if (sscanf(line, "%255s %31s", name, type) >= 1)
            {
                smb_share_add(shares, name, NULL,
                              strcasecmp(type, "Disk") == 0);
            }
        }

        line = strchr(line, '\n');
        if (line != NULL)
            line++;
    }

out:
    te_vec_deep_free(&args);
    te_string_free(&out);
    te_string_free(&url);

    return rc;
}

/** List shares with Windows Get-SmbShare over a mapping, or net view. */
static te_errno
smb_windows_list(tapi_job_factory_t *factory, const tapi_smb_target *target,
                 int timeout_ms, te_vec *shares)
{
    te_string script = TE_STRING_INIT;
    te_string out = TE_STRING_INIT;
    te_string object = TE_STRING_INIT;
    const char *pos = NULL;
    int code = 0;
    te_errno rc;

    /*
     * net view lists a remote server's shares without mounting them.
     * PowerShell parses its columns and writes flat JSON so the reader
     * here is the same as everywhere else.
     */
    te_string_append(&script, "$s = ");
    tapi_smb_ps_quote(&script, target->server);
    te_string_append(&script,
        "; $lines = net view \"\\\\$s\" /all 2>$null; "
        "$out = @(); foreach ($l in $lines) { "
        "if ($l -match '^(\\S.*?)\\s{2,}(Disk|Print|IPC)\\s*(.*)$') { "
        "$out += [pscustomobject]@{ Name = $matches[1].Trim();"
        " Type = $matches[2]; Comment = $matches[3].Trim() } } }; "
        "if ($LASTEXITCODE -ne 0 -and $out.Count -eq 0) { 'NETVIEWFAIL' } "
        "else { ConvertTo-Json -Compress -InputObject @($out) }");

    rc = tapi_smb_powershell(factory, script.ptr, timeout_ms, &out, NULL,
                             &code);
    if (rc == 0 && strstr(te_string_value(&out), "NETVIEWFAIL") != NULL)
    {
        ERROR("net view %s failed", target->server);
        rc = TE_RC(TE_TAPI, TE_EFAIL);
    }

    while (rc == 0 &&
           (pos = tapi_smb_json_next(te_string_value(&out), pos,
                                     &object)) != NULL)
    {
        te_string name = TE_STRING_INIT;
        te_string type = TE_STRING_INIT;
        te_string comment = TE_STRING_INIT;

        tapi_smb_json_str(object.ptr, "Name", &name);
        tapi_smb_json_str(object.ptr, "Type", &type);
        tapi_smb_json_str(object.ptr, "Comment", &comment);
        if (name.len != 0)
        {
            smb_share_add(shares, name.ptr, comment.ptr,
                          strcasecmp(te_string_value(&type), "Disk") == 0);
        }
        te_string_free(&name);
        te_string_free(&type);
        te_string_free(&comment);
        te_string_reset(&object);
    }

    te_string_free(&script);
    te_string_free(&out);
    te_string_free(&object);

    return rc;
}

/* See description in tapi_smb.h */
te_errno
tapi_smb_list(tapi_job_factory_t *factory, tapi_smb_backend backend,
              const tapi_smb_target *target, int timeout_ms, te_vec *shares)
{
    te_errno rc;

    rc = tapi_smb_resolve(factory, timeout_ms, &backend);
    if (rc != 0)
        return rc;

    rc = smb_target_check(backend, target);
    if (rc != 0)
        return rc;

    switch (backend)
    {
        case TAPI_SMB_SAMBA:
            return smb_samba_list(factory, target, timeout_ms, shares);
        case TAPI_SMB_MACOS:
            return smb_macos_list(factory, target, timeout_ms, shares);
        case TAPI_SMB_WINDOWS:
            return smb_windows_list(factory, target, timeout_ms, shares);
        default:
            return TE_RC(TE_TAPI, TE_EINVAL);
    }
}

/** Read the negotiated dialect out of smbclient -d4. */
static tapi_smb_dialect
smb_samba_negotiated(const char *text)
{
    const char *found = strstr(text, "negotiated dialect[");

    if (found == NULL)
        return TAPI_SMB_DIALECT_ANY;

    return tapi_smb_str2dialect(found + strlen("negotiated dialect["));
}

/** Connection info with Samba. */
static te_errno
smb_samba_connect_info(tapi_job_factory_t *factory,
                       const tapi_smb_target *target, const char *share,
                       int timeout_ms, tapi_smb_conn_info *info)
{
    te_vec args = TE_VEC_INIT(char *);
    te_string out = TE_STRING_INIT;
    te_string unc = TE_STRING_INIT;
    int code = 0;
    te_errno rc;

    tapi_smb_unc(target, &unc);
    te_string_append(&unc, "%s", share);

    tapi_smb_arg(&args, "%s", unc.ptr);
    /* -d4 is where "negotiated dialect[...]" appears on stderr. */
    tapi_smb_arg(&args, "-d4");
    tapi_smb_arg(&args, "--debug-stdout");
    tapi_smb_client_args(target, &args);
    tapi_smb_arg(&args, "-c");
    tapi_smb_arg(&args, "quit");

    rc = tapi_smb_sh(factory, "smbclient", &args, target->password,
                     timeout_ms, &out, &out, &code);
    if (rc != 0)
        goto out;

    if (code != 0)
    {
        rc = tapi_smb_nt_status(te_string_value(&out), NULL);
        if (rc == 0)
            rc = TE_RC(TE_TAPI, TE_EFAIL);
        goto out;
    }

    info->dialect = smb_samba_negotiated(te_string_value(&out));
    /*
     * Samba's client signs and encrypts when the server asks and the
     * connection allowed it; what it actually did is not printed
     * plainly, so signing and encryption in force are left to the
     * negotiate probe of the audit, and only the dialect is taken
     * here. The requirement the caller set is reflected: a connection
     * asked to encrypt that succeeded is encrypted.
     */
    info->encrypted = target->require_encryption;
    info->signed_conn = target->require_signing;
    info->server = TE_STRDUP(target->server);

out:
    te_vec_deep_free(&args);
    te_string_free(&out);
    te_string_free(&unc);

    return rc;
}

/** Connection info with macOS: mount, statshares, unmount. */
static te_errno
smb_macos_connect_info(tapi_job_factory_t *factory,
                       const tapi_smb_target *target, const char *share,
                       int timeout_ms, tapi_smb_conn_info *info)
{
    const char *ta = tapi_smb_factory_ta(factory);
    te_vec args = TE_VEC_INIT(char *);
    te_string out = TE_STRING_INIT;
    te_string url = TE_STRING_INIT;
    te_string mnt = TE_STRING_INIT;
    const char *line;
    int code = 0;
    te_errno rc;

    if (ta == NULL)
        return TE_RC(TE_TAPI, TE_EINVAL);

    te_string_append(&mnt, "/tmp/tsf_smb_%u", (unsigned int)rand());

    te_string_append(&url, "//");
    if (target->user != NULL && *target->user != '\0')
        te_string_append(&url, "%s@", target->user);
    te_string_append(&url, "%s/%s", target->server, share);

    tapi_smb_arg(&args, "-c");
    te_string_append(&mnt, "");
    {
        te_string sh = TE_STRING_INIT;

        te_string_append(&sh,
            "mkdir -p %s && mount_smbfs %s %s %s && "
            "smbutil statshares -m %s; r=$?; "
            "umount %s 2>/dev/null; rmdir %s 2>/dev/null; exit $r",
            mnt.ptr, target->user == NULL ? "-N" : "", url.ptr, mnt.ptr,
            mnt.ptr, mnt.ptr, mnt.ptr);
        tapi_smb_arg(&args, "%s", sh.ptr);
        te_string_free(&sh);
    }

    rc = tapi_smb_sh(factory, "/bin/sh", &args, target->password,
                     timeout_ms, &out, &out, &code);
    if (rc != 0)
        goto out;

    if (code != 0)
    {
        const char *text = te_string_value(&out);

        ERROR("Mounting %s failed: %s", url.ptr, text);
        rc = strstr(text, "Authentication error") != NULL ?
             TE_RC(TE_TAPI, TE_EACCES) :
             strstr(text, "No such file") != NULL ?
             TE_RC(TE_TAPI, TE_ENOENT) : TE_RC(TE_TAPI, TE_EFAIL);
        goto out;
    }

    info->server = TE_STRDUP(target->server);
    for (line = te_string_value(&out); line != NULL && *line != '\0'; )
    {
        if (strstr(line, "SMB_VERSION") != NULL)
        {
            const char *v = strstr(line, "SMB_");

            v = strchr(v + 4, ' ');
            if (v != NULL)
                info->dialect = tapi_smb_str2dialect(v + strspn(v, " \t"));
        }
        else if (strstr(line, "SMB_CURR_SIGN_ALGORITHM") != NULL)
        {
            info->signed_conn = strstr(line, "OFF") == NULL;
        }
        else if (strstr(line, "SMB_CURR_ENCRYPT_ALGORITHM") != NULL)
        {
            info->encrypted = strstr(line, "OFF") == NULL;
        }

        line = strchr(line, '\n');
        if (line != NULL)
            line++;
    }

out:
    te_vec_deep_free(&args);
    te_string_free(&out);
    te_string_free(&url);
    te_string_free(&mnt);

    return rc;
}

/** Connection info with Windows Get-SmbConnection. */
static te_errno
smb_windows_connect_info(tapi_job_factory_t *factory,
                         const tapi_smb_target *target, const char *share,
                         int timeout_ms, tapi_smb_conn_info *info)
{
    te_string script = TE_STRING_INIT;
    te_string out = TE_STRING_INIT;
    te_string object = TE_STRING_INIT;
    const char *pos;
    int code = 0;
    te_errno rc;

    te_string_append(&script, "$s = ");
    tapi_smb_ps_quote(&script, target->server);
    te_string_append(&script, "; $sh = ");
    tapi_smb_ps_quote(&script, share);
    te_string_append(&script, "; $u = ");
    tapi_smb_ps_quote(&script,
                      target->user != NULL ? target->user : "");
    te_string_append(&script, "; $p = ");
    tapi_smb_ps_quote(&script,
                      target->password != NULL ? target->password : "");
    te_string_append(&script,
        "; $unc = \"\\\\$s\\$sh\"; try { "
        "if ($u) { $sec = ConvertTo-SecureString $p -AsPlainText -Force; "
        "$cred = New-Object PSCredential($u, $sec); "
        "New-SmbMapping -RemotePath $unc -Credential $cred "
        "-ErrorAction Stop | Out-Null } "
        "else { New-SmbMapping -RemotePath $unc -ErrorAction Stop "
        "| Out-Null } "
        "$c = Get-SmbConnection -ServerName $s | Select-Object -First 1; "
        "$o = [pscustomobject]@{ Dialect = [string]$c.Dialect;"
        " Signed = [bool]$c.Signed; Encrypted = [bool]$c.Encrypted;"
        " Server = [string]$c.ServerName }; "
        "Remove-SmbMapping -RemotePath $unc -Force -ErrorAction "
        "SilentlyContinue | Out-Null; ConvertTo-Json -Compress $o } "
        "catch { 'SMBERR ' + $_.Exception.Message }");

    rc = tapi_smb_powershell(factory, script.ptr, timeout_ms, &out, NULL,
                             &code);
    if (rc != 0)
        goto out;

    if (strstr(te_string_value(&out), "SMBERR") != NULL ||
        strchr(te_string_value(&out), '{') == NULL)
    {
        const char *text = te_string_value(&out);

        ERROR("Connecting to \\\\%s\\%s failed: %s", target->server, share,
              text);
        rc = strstr(text, "denied") != NULL || strstr(text, "password") !=
             NULL ? TE_RC(TE_TAPI, TE_EACCES) : TE_RC(TE_TAPI, TE_EFAIL);
        goto out;
    }

    pos = te_string_value(&out);
    tapi_smb_json_str(pos, "Dialect", &object);
    info->dialect = tapi_smb_str2dialect(te_string_value(&object));
    tapi_smb_json_bool(pos, "Signed", &info->signed_conn);
    tapi_smb_json_bool(pos, "Encrypted", &info->encrypted);
    te_string_reset(&object);
    if (tapi_smb_json_str(pos, "Server", &object) && object.len != 0)
        info->server = TE_STRDUP(object.ptr);

out:
    te_string_free(&script);
    te_string_free(&out);
    te_string_free(&object);

    return rc;
}

/* See description in tapi_smb.h */
te_errno
tapi_smb_connect_info(tapi_job_factory_t *factory, tapi_smb_backend backend,
                      const tapi_smb_target *target, const char *share,
                      int timeout_ms, tapi_smb_conn_info *info)
{
    te_errno rc;

    memset(info, 0, sizeof(*info));

    rc = tapi_smb_resolve(factory, timeout_ms, &backend);
    if (rc != 0)
        return rc;
    rc = smb_target_check(backend, target);
    if (rc != 0)
        return rc;

    switch (backend)
    {
        case TAPI_SMB_SAMBA:
            rc = smb_samba_connect_info(factory, target, share, timeout_ms,
                                        info);
            break;
        case TAPI_SMB_MACOS:
            rc = smb_macos_connect_info(factory, target, share, timeout_ms,
                                        info);
            break;
        case TAPI_SMB_WINDOWS:
            rc = smb_windows_connect_info(factory, target, share, timeout_ms,
                                          info);
            break;
        default:
            rc = TE_RC(TE_TAPI, TE_EINVAL);
            break;
    }

    if (rc != 0)
        tapi_smb_conn_info_free(info);

    return rc;
}

/* See description in tapi_smb.h */
bool
tapi_smb_can_connect(tapi_job_factory_t *factory, tapi_smb_backend backend,
                     const tapi_smb_target *target, const char *share,
                     int timeout_ms, te_string *status)
{
    tapi_smb_conn_info info;
    te_errno rc;

    rc = tapi_smb_connect_info(factory, backend, target, share, timeout_ms,
                               &info);
    if (rc == 0)
    {
        if (status != NULL)
            te_string_append(status, "NT_STATUS_OK");
        tapi_smb_conn_info_free(&info);
        return true;
    }

    if (status != NULL)
        te_string_append(status, "%s", te_rc_err2str(TE_RC_GET_ERROR(rc)));

    return false;
}

/* See description in tapi_smb.h */
void
tapi_smb_conn_info_log(const tapi_smb_conn_info *info)
{
    RING("SMB connection to %s: %s, %s, %s",
         info->server != NULL ? info->server : "?",
         tapi_smb_dialect2str(info->dialect),
         info->signed_conn ? "signed" : "not signed",
         info->encrypted ? "encrypted" : "not encrypted");
}

/* See description in tapi_smb.h */
void
tapi_smb_conn_info_free(tapi_smb_conn_info *info)
{
    free(info->server);
    free(info->detail);
    memset(info, 0, sizeof(*info));
}

/* See description in tapi_smb.h */
void
tapi_smb_shares_free(te_vec *shares)
{
    tapi_smb_share_info *info;

    TE_VEC_FOREACH(shares, info)
    {
        free(info->name);
        free(info->comment);
    }
    te_vec_free(shares);
}
