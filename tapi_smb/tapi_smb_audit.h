/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (C) 2026 Interpretica Unipessoal Lda */
/** @file
 * @brief What an SMB server is worth
 *
 * @defgroup tapi_smb_audit SMB security posture
 * @ingroup tapi_smb
 * @{
 *
 * An SMB server read from the outside, the way an attacker on the same
 * network would: what dialects it accepts, whether it insists on
 * signing, whether it will encrypt, and whether it hands a stranger a
 * list of its shares. It is asked over the wire, not read from the
 * server's own configuration, so it works against any SMB server the
 * agent can reach and not only a Samba one - the one thing it needs on
 * the agent is @c python3, because the SMB negotiation is done by a
 * small helper rather than by driving a client whose output does not
 * say what was negotiated.
 *
 * | Finding | Severity | Read from |
 * |---|---|---|
 * | @c smb.smb1-enabled | high | the server accepts an SMB1 negotiate |
 * | @c smb.no-signing-required | medium | it accepts a connection it will not sign |
 * | @c smb.no-encryption | medium | it offers no SMB3 dialect, so nothing is encrypted |
 * | @c smb.anonymous-shares | medium | a null session lists its shares |
 * | @c smb.guest-writable | high | a guest login can write to a share |
 * | @c smb.not-assessed | info | the negotiation could not be done (no python3) |
 *
 * @c smb.smb1-enabled is the one worth knowing about: SMB1 is the
 * protocol WannaCry spread over, it has no real integrity protection,
 * and a modern server has no reason to answer it. It is off by default
 * on a current Samba and Windows, and a server that answers it was
 * turned back on for something that should have been fixed another
 * way.
 *
 * @code
 * tapi_smb_target target = TAPI_SMB_TARGET_INIT;
 * tapi_cybersec_report report;
 *
 * target.server = "fileserver";
 * tapi_cybersec_report_init(&report);
 * CHECK_RC(tapi_smb_audit(factory, TAPI_SMB_AUTO, &target, NULL, 30000,
 *                         &report));
 * tapi_cybersec_report_log(&report);
 * @endcode
 */

#ifndef __TSF_TAPI_SMB_AUDIT_H__
#define __TSF_TAPI_SMB_AUDIT_H__

#include "te_defs.h"
#include "te_errno.h"
#include "tapi_job.h"

#include "tapi_cybersec.h"
#include "tapi_smb.h"

#ifdef __cplusplus
extern "C" {
#endif

/** What the server is expected to be. */
typedef struct tapi_smb_policy {
    /** A null session may list the shares. */
    bool allow_anonymous;
    /** A guest login may reach a share. */
    bool allow_guest;
    /** The server need not encrypt (it is on a trusted segment). */
    bool allow_unencrypted;
    /**
     * A guest share to try writing to, or @c NULL to skip the write
     * check. The @c smb.guest-writable finding needs somewhere to try.
     */
    const char *guest_share;
} tapi_smb_policy;

/** The default: nothing anonymous, nothing for guests, encryption wanted. */
extern const tapi_smb_policy tapi_smb_default_policy;

/**
 * Read a server's posture and add what is wrong to @p report.
 *
 * @param[in]  factory      Job factory.
 * @param[in]  backend      Backend, or @ref TAPI_SMB_AUTO. Only the
 *                          anonymous-list and guest-write checks use a
 *                          client; the negotiation is the helper's, so
 *                          the audit runs even where no full client is.
 * @param[in]  target       The server (its @a server and @a port; the
 *                          credentials are used only for the checks
 *                          that need a login).
 * @param[in]  policy       What is expected, or @c NULL for the
 *                          default.
 * @param[in]  timeout_ms   Timeout, ms.
 * @param[out] report       Report to append findings to.
 *
 * @return Status code of reading the posture, not its verdict.
 * @retval TE_ECONNREFUSED  Nothing answered on the SMB port.
 */
extern te_errno tapi_smb_audit(tapi_job_factory_t *factory,
                               tapi_smb_backend backend,
                               const tapi_smb_target *target,
                               const tapi_smb_policy *policy, int timeout_ms,
                               tapi_cybersec_report *report);

#ifdef __cplusplus
} /* extern "C" */
#endif
#endif /* !__TSF_TAPI_SMB_AUDIT_H__ */

/**@} <!-- END tapi_smb_audit --> */
