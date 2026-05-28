/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (C) 2026 Interpretica Unipessoal Lda */
/** @file
 * @brief Shares served by the agent
 *
 * @defgroup tapi_smb_share Serving a share
 * @ingroup tapi_smb
 * @{
 *
 * The other direction: a share served from the agent, so that one
 * agent serves and another - or the same one - connects. A test of an
 * SMB client under test points it at a share this puts up; a test of
 * the client half of this library connects to a share it served
 * itself.
 *
 * On Samba the share is a @c net @c usershare, which an ordinary user
 * in the @c sambashare group may add and remove without editing
 * @c smb.conf or restarting anything. On Windows it is a
 * @c New-SmbShare. macOS does not serve from a command a test can
 * drive, so there is no macOS backend here.
 *
 * @code
 * tapi_smb_served share = TAPI_SMB_SERVED_INIT;
 *
 * share.name = "tsfshare";
 * share.path = "/srv/tsf";
 * share.writable = true;
 * CHECK_RC(tapi_smb_serve(factory, TAPI_SMB_AUTO, &share, 30000));
 * ... connect to //localhost/tsfshare ...
 * tapi_smb_unserve(factory, TAPI_SMB_AUTO, "tsfshare", 30000);
 * @endcode
 */

#ifndef __TSF_TAPI_SMB_SHARE_H__
#define __TSF_TAPI_SMB_SHARE_H__

#include "te_defs.h"
#include "te_errno.h"
#include "tapi_job.h"

#include "tapi_smb.h"

#ifdef __cplusplus
extern "C" {
#endif

/** A share to serve from the agent. */
typedef struct tapi_smb_served {
    /** Share name. */
    const char *name;
    /** Directory on the agent to export. It must already exist. */
    const char *path;
    /** Comment, or @c NULL. */
    const char *comment;
    /** Let clients write, not only read. */
    bool writable;
    /**
     * Let a guest (unauthenticated) client in. On Samba this needs the
     * server's @c "usershare allow guests = yes", which is not the
     * default; tapi_smb_serve() reports @c TE_EPERM when the server
     * forbids it rather than serving an authenticated share that looks
     * like a guest one.
     */
    bool guest_ok;
} tapi_smb_served;

/** Initializer for #tapi_smb_served. */
#define TAPI_SMB_SERVED_INIT { .name = NULL }

/**
 * Serve a share from the agent.
 *
 * @note This changes the agent, and needs the right to: membership of
 *       @c sambashare (or root) on Samba, an administrator on Windows.
 *       Remove it in a cleanup section that runs even when the test
 *       failed.
 *
 * @param factory       Job factory.
 * @param backend       Backend, or @ref TAPI_SMB_AUTO.
 * @param share         What to serve.
 * @param timeout_ms    Timeout, ms.
 *
 * @return Status code.
 * @retval TE_EPERM         The agent's user may not, or a guest share
 *                          was asked for where the server forbids it.
 * @retval TE_EOPNOTSUPP    macOS cannot serve from a command.
 */
extern te_errno tapi_smb_serve(tapi_job_factory_t *factory,
                               tapi_smb_backend backend,
                               const tapi_smb_served *share, int timeout_ms);

/**
 * Stop serving a share.
 *
 * @param factory       Job factory.
 * @param backend       Backend, or @ref TAPI_SMB_AUTO.
 * @param name          Share name.
 * @param timeout_ms    Timeout, ms.
 *
 * @return Status code.
 * @retval TE_ENOENT        There was no such share.
 */
extern te_errno tapi_smb_unserve(tapi_job_factory_t *factory,
                                 tapi_smb_backend backend, const char *name,
                                 int timeout_ms);

/**
 * Can the agent serve a share at all?
 *
 * On Samba this is not a given: @c net @c usershare works only for a
 * user the server lets create shares, and a bare image may not have
 * the @c sambashare group or the @c usershares directory. Asked so a
 * test can skip rather than fail.
 *
 * @param factory       Job factory.
 * @param backend       Backend, or @ref TAPI_SMB_AUTO.
 * @param timeout_ms    Timeout, ms.
 *
 * @return @c true when a share can be served.
 */
extern bool tapi_smb_can_serve(tapi_job_factory_t *factory,
                               tapi_smb_backend backend, int timeout_ms);

#ifdef __cplusplus
} /* extern "C" */
#endif
#endif /* !__TSF_TAPI_SMB_SHARE_H__ */

/**@} <!-- END tapi_smb_share --> */
