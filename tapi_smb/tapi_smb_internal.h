/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Interpretica Unipessoal Lda */
/** @file
 * @brief SMB TAPI: internal helpers
 *
 * Internal to tsf-smb; not installed.
 */

#ifndef __TSF_TAPI_SMB_INTERNAL_H__
#define __TSF_TAPI_SMB_INTERNAL_H__

#include "te_defs.h"
#include "te_errno.h"
#include "te_string.h"
#include "te_vector.h"
#include "tapi_job.h"

#include "tapi_smb.h"

#ifdef __cplusplus
extern "C" {
#endif

/** Exit status of a POSIX shell that could not find the program. */
#define TAPI_SMB_EXIT_NOT_FOUND 127

/** Append one argument to a vector, taking ownership of it. */
extern void tapi_smb_arg(te_vec *args, const char *fmt, ...)
    TE_LIKE_PRINTF(2, 3);

/**
 * Run a tool on a POSIX agent and wait for it.
 *
 * The job gets an environment of its own, and only this: a fixed
 * @c PATH with the @c sbin directories in it, @c LC_ALL=C so that the
 * tools print the English the parsers read, and - when @p password is
 * not @c NULL - @c PASSWD.
 *
 * That last one is why there is an environment at all. @c smbclient
 * reads its password from @c PASSWD, and a variable is visible only to
 * the process's own user and root, where @c -U @c user%password is on
 * the command line and visible to everyone who runs @c ps on the agent.
 * The user name still goes on the command line with @c -U: measured
 * on Samba 4.17, a wrong password with the user in @c USER instead
 * was not refused - the session quietly continued without those
 * credentials - while @c -U with the same wrong password failed with
 * @c NT_STATUS_LOGON_FAILURE, which is the answer a test needs.
 *
 * The program is run through @c /bin/sh because TE starts a job with
 * @c execvpe(), which looks the program up in the agent's @c PATH and
 * not in the job's.
 *
 * @param[in]  factory      Job factory.
 * @param[in]  program      Program name.
 * @param[in]  args         Arguments after @c argv[0].
 * @param[in]  password     Password for @c PASSWD, or @c NULL.
 * @param[in]  timeout_ms   Timeout, ms.
 * @param[out] out          Standard output, or @c NULL.
 * @param[out] err          Standard error, or @c NULL.
 * @param[out] exit_code    Exit status, or @c NULL; @c -1 for a signal
 *                          and @ref TAPI_SMB_EXIT_NOT_FOUND when the
 *                          program is not installed.
 *
 * @return Status code of running the tool, not of the tool.
 */
extern te_errno tapi_smb_sh(tapi_job_factory_t *factory, const char *program,
                            const te_vec *args, const char *password,
                            int timeout_ms, te_string *out, te_string *err,
                            int *exit_code);

/**
 * Run a PowerShell script on a Windows agent, as @c -EncodedCommand.
 *
 * @param[in]  factory      Job factory.
 * @param[in]  script       The script.
 * @param[in]  timeout_ms   Timeout, ms.
 * @param[out] out          Standard output.
 * @param[out] err          Standard error, or @c NULL.
 * @param[out] exit_code    Exit status, or @c NULL.
 *
 * @return Status code.
 */
extern te_errno tapi_smb_powershell(tapi_job_factory_t *factory,
                                    const char *script, int timeout_ms,
                                    te_string *out, te_string *err,
                                    int *exit_code);

/** Append @p value to a PowerShell script as a single-quoted string. */
extern void tapi_smb_ps_quote(te_string *script, const char *value);

/** Pull one JSON string field out of a flat object. */
extern bool tapi_smb_json_str(const char *object, const char *key,
                              te_string *dest);

/** Pull one JSON boolean field out of a flat object. */
extern bool tapi_smb_json_bool(const char *object, const char *key,
                               bool *value);

/** Pull one JSON number field out of a flat object. */
extern bool tapi_smb_json_int(const char *object, const char *key,
                              long *value);

/** Walk the objects of a JSON array, or the one object of an array of one. */
extern const char *tapi_smb_json_next(const char *array, const char *prev,
                                      te_string *object);

/**
 * The status an SMB tool reported, turned into a TE status code.
 *
 * Every tool here reports a failure as the server's own NT status -
 * @c NT_STATUS_LOGON_FAILURE, @c NT_STATUS_BAD_NETWORK_NAME - somewhere
 * in what it printed, and that is what is read: the exit status of
 * @c smbclient belongs to the last command it ran, not to the first
 * that failed.
 *
 * @param text      What the tool printed.
 * @param status    String to append the NT status name to, or @c NULL.
 *
 * @return @c 0 when no NT status was found, the mapped code otherwise.
 */
extern te_errno tapi_smb_nt_status(const char *text, te_string *status);

/**
 * The agent a factory runs on, for putting files there.
 *
 * @return The agent name, or @c NULL with an error logged.
 */
extern const char *tapi_smb_factory_ta(tapi_job_factory_t *factory);

/**
 * Resolve @ref TAPI_SMB_AUTO to what the agent has.
 */
extern te_errno tapi_smb_resolve(tapi_job_factory_t *factory, int timeout_ms,
                                 tapi_smb_backend *backend);

/**
 * POSIX-unlink a name on a share (Samba only).
 *
 * The one deletion that removes a symlink itself rather than what it
 * points to: it is how the access-rights chain takes down the links it
 * planted without touching the out-of-share files they reach - an
 * ordinary delete would follow the link. Not public: the chain's own
 * cleanup uses it, a test drives the share it serves with the ordinary
 * tapi_smb_unlink().
 *
 * @param factory       Job factory.
 * @param backend       Backend (must have @ref TAPI_SMB_FEAT_POSIX).
 * @param target        Server and credentials.
 * @param share         Share name.
 * @param name          Path on the share, forward slashes.
 * @param timeout_ms    Timeout, ms.
 *
 * @return Status code.
 */
extern te_errno tapi_smb_posix_unlink(tapi_job_factory_t *factory,
                                      tapi_smb_backend backend,
                                      const tapi_smb_target *target,
                                      const char *share, const char *name,
                                      int timeout_ms);

/**
 * Append the smbclient arguments that name the server, the user and
 * the connection requirements of @p target.
 *
 * @param[in]  target   Server and credentials.
 * @param[out] args     Arguments to append to.
 *
 * @return Status code.
 * @retval TE_EINVAL    The dialect bounds are not dialects.
 */
extern te_errno tapi_smb_client_args(const tapi_smb_target *target,
                                     te_vec *args);

/** The UNC path of a share: @c //host/share, with the port if not 445. */
extern void tapi_smb_unc(const tapi_smb_target *target, te_string *unc);

/** The smbclient spelling of a dialect, or @c NULL. */
extern const char *tapi_smb_dialect2samba(tapi_smb_dialect dialect);

/**
 * Parse a dialect as any of the tools write it: @c SMB3_11,
 * @c SMB_3.1.1, @c 3.1.1, @c 311.
 */
extern tapi_smb_dialect tapi_smb_str2dialect(const char *text);

#ifdef __cplusplus
} /* extern "C" */
#endif
#endif /* !__TSF_TAPI_SMB_INTERNAL_H__ */
