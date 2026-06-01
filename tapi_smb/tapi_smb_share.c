/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Interpretica Unipessoal Lda */
/** @file
 * @brief Shares served by the agent
 *
 * On Samba, @c net @c usershare: a share an ordinary user in the
 * @c sambashare group adds without touching smb.conf. Its ACL is
 * written as a SID, not a name - measured on Samba 4.17, @c "Everyone"
 * was refused with "cannot convert name Everyone to a SID" for a
 * non-root user, while the well-known SID @c S-1-1-0 was taken - so
 * that is what is used. A guest share needs the server's
 * @c "usershare allow guests", and @c net says so plainly when it is
 * off, which becomes @c TE_EPERM rather than a share that is not what
 * was asked for.
 */

#define TE_LGR_USER "TAPI SMB"

#include "te_config.h"

#include <stdlib.h>
#include <string.h>

#include "logger_api.h"
#include "te_str.h"
#include "te_string.h"
#include "te_vector.h"

#include "tapi_smb.h"
#include "tapi_smb_share.h"
#include "tapi_smb_internal.h"

/** The well-known SID for Everyone. */
#define SMB_SID_EVERYONE "S-1-1-0"

/** Serve a share with net usershare. */
static te_errno
smb_samba_serve(tapi_job_factory_t *factory, const tapi_smb_served *share,
                int timeout_ms)
{
    te_vec args = TE_VEC_INIT(char *);
    te_string out = TE_STRING_INIT;
    int code = 0;
    te_errno rc;

    tapi_smb_arg(&args, "usershare");
    tapi_smb_arg(&args, "add");
    tapi_smb_arg(&args, "%s", share->name);
    tapi_smb_arg(&args, "%s", share->path);
    tapi_smb_arg(&args, "%s", share->comment != NULL ? share->comment : "");
    tapi_smb_arg(&args, "%s:%s", SMB_SID_EVERYONE,
                 share->writable ? "F" : "R");
    tapi_smb_arg(&args, "guest_ok=%s", share->guest_ok ? "y" : "n");

    rc = tapi_smb_sh(factory, "net", &args, NULL, timeout_ms, &out, &out,
                     &code);
    if (rc == 0 && code != 0)
    {
        const char *text = te_string_value(&out);

        ERROR("net usershare add failed (exit %d): %s", code, text);
        if (strstr(text, "usershare allow guests") != NULL ||
            strstr(text, "not have permission") != NULL ||
            strstr(text, "Permission denied") != NULL)
        {
            rc = TE_RC(TE_TAPI, TE_EPERM);
        }
        else
        {
            rc = TE_RC(TE_TAPI, TE_EFAIL);
        }
    }

    te_vec_deep_free(&args);
    te_string_free(&out);

    return rc;
}

/** Serve a share with New-SmbShare. */
static te_errno
smb_windows_serve(tapi_job_factory_t *factory, const tapi_smb_served *share,
                  int timeout_ms)
{
    te_string script = TE_STRING_INIT;
    te_string out = TE_STRING_INIT;
    int code = 0;
    te_errno rc;

    te_string_append(&script, "$ErrorActionPreference='Stop'; try { "
                     "New-SmbShare -Name ");
    tapi_smb_ps_quote(&script, share->name);
    te_string_append(&script, " -Path ");
    tapi_smb_ps_quote(&script, share->path);
    if (share->comment != NULL)
    {
        te_string_append(&script, " -Description ");
        tapi_smb_ps_quote(&script, share->comment);
    }
    /* Everyone gets the level the caller asked for. */
    te_string_append(&script,
                     share->writable ? " -FullAccess 'Everyone'" :
                     " -ReadAccess 'Everyone'");
    te_string_append(&script,
        " | Out-Null; 'OK' } catch { 'SMBERR ' + $_.Exception.Message }");

    rc = tapi_smb_powershell(factory, script.ptr, timeout_ms, &out, NULL,
                             &code);
    if (rc == 0 && strstr(te_string_value(&out), "OK") == NULL)
    {
        const char *text = te_string_value(&out);

        ERROR("New-SmbShare failed: %s", text);
        rc = strstr(text, "denied") != NULL ?
             TE_RC(TE_TAPI, TE_EPERM) : TE_RC(TE_TAPI, TE_EFAIL);
    }

    te_string_free(&script);
    te_string_free(&out);

    return rc;
}

/* See description in tapi_smb_share.h */
te_errno
tapi_smb_serve(tapi_job_factory_t *factory, tapi_smb_backend backend,
               const tapi_smb_served *share, int timeout_ms)
{
    te_errno rc;

    if (share == NULL || share->name == NULL || share->path == NULL)
    {
        ERROR("A served share needs a name and a path");
        return TE_RC(TE_TAPI, TE_EINVAL);
    }

    rc = tapi_smb_resolve(factory, timeout_ms, &backend);
    if (rc != 0)
        return rc;

    switch (backend)
    {
        case TAPI_SMB_SAMBA:
            rc = smb_samba_serve(factory, share, timeout_ms);
            break;
        case TAPI_SMB_WINDOWS:
            rc = smb_windows_serve(factory, share, timeout_ms);
            break;
        default:
            ERROR("%s cannot serve a share",
                  tapi_smb_backend2str(backend));
            return TE_RC(TE_TAPI, TE_EOPNOTSUPP);
    }

    if (rc == 0)
        RING("Serving %s from %s", share->name, share->path);

    return rc;
}

/* See description in tapi_smb_share.h */
te_errno
tapi_smb_unserve(tapi_job_factory_t *factory, tapi_smb_backend backend,
                 const char *name, int timeout_ms)
{
    te_vec args = TE_VEC_INIT(char *);
    te_string script = TE_STRING_INIT;
    te_string out = TE_STRING_INIT;
    int code = 0;
    te_errno rc;

    rc = tapi_smb_resolve(factory, timeout_ms, &backend);
    if (rc != 0)
        return rc;

    switch (backend)
    {
        case TAPI_SMB_SAMBA:
            tapi_smb_arg(&args, "usershare");
            tapi_smb_arg(&args, "delete");
            tapi_smb_arg(&args, "%s", name);
            rc = tapi_smb_sh(factory, "net", &args, NULL, timeout_ms, &out,
                             &out, &code);
            if (rc == 0 && code != 0)
            {
                rc = strstr(te_string_value(&out), "No such") != NULL ||
                     strstr(te_string_value(&out), "unable to remove") !=
                     NULL ? TE_RC(TE_TAPI, TE_ENOENT) :
                     TE_RC(TE_TAPI, TE_EFAIL);
            }
            break;

        case TAPI_SMB_WINDOWS:
            te_string_append(&script, "try { Remove-SmbShare -Name ");
            tapi_smb_ps_quote(&script, name);
            te_string_append(&script,
                " -Force -ErrorAction Stop | Out-Null; 'OK' } "
                "catch { 'SMBERR ' + $_.Exception.Message }");
            rc = tapi_smb_powershell(factory, script.ptr, timeout_ms, &out,
                                     NULL, &code);
            if (rc == 0 && strstr(te_string_value(&out), "OK") == NULL)
            {
                rc = strstr(te_string_value(&out), "NotFound") != NULL ?
                     TE_RC(TE_TAPI, TE_ENOENT) : TE_RC(TE_TAPI, TE_EFAIL);
            }
            break;

        default:
            rc = TE_RC(TE_TAPI, TE_EOPNOTSUPP);
            break;
    }

    if (rc == 0)
        RING("Stopped serving %s", name);

    te_vec_deep_free(&args);
    te_string_free(&script);
    te_string_free(&out);

    return rc;
}

/* See description in tapi_smb_share.h */
bool
tapi_smb_can_serve(tapi_job_factory_t *factory, tapi_smb_backend backend,
                   int timeout_ms)
{
    te_vec args = TE_VEC_INIT(char *);
    te_string out = TE_STRING_INIT;
    int code = 0;
    te_errno rc;
    bool can = false;

    rc = tapi_smb_resolve(factory, timeout_ms, &backend);
    if (rc != 0)
        return false;

    switch (backend)
    {
        case TAPI_SMB_SAMBA:
            /*
             * "net usershare list" exits 0 for a user who may serve
             * and non-zero ("You do not have permission to create a
             * usershare") for one who may not.
             */
            tapi_smb_arg(&args, "usershare");
            tapi_smb_arg(&args, "list");
            rc = tapi_smb_sh(factory, "net", &args, NULL, timeout_ms, &out,
                             &out, &code);
            can = rc == 0 && code == 0;
            break;

        case TAPI_SMB_WINDOWS:
            rc = tapi_smb_powershell(factory,
                    "if (Get-Command New-SmbShare -ErrorAction "
                    "SilentlyContinue) { 'yes' }",
                    timeout_ms, &out, NULL, &code);
            can = rc == 0 && strstr(te_string_value(&out), "yes") != NULL;
            break;

        default:
            break;
    }

    te_vec_deep_free(&args);
    te_string_free(&out);

    return can;
}
