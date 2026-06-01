/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Interpretica Unipessoal Lda */
/** @file
 * @brief Files on an SMB share
 *
 * @defgroup tapi_smb_file Files on a share
 * @ingroup tapi_smb
 * @{
 *
 * Reading and writing files on a share of a server the agent reaches:
 * put a file there, get one back, list a directory, make and remove
 * directories, remove a file. The path inside the share is always
 * written with forward slashes; each backend turns them into what its
 * tool wants.
 *
 * A file put or got is a file on the agent, named from the agent's
 * temporary directory when the caller does not give a path.
 * tapi_smb_put_from_engine() and tapi_smb_get_to_engine() are the two
 * that cross from the engine to the agent, for a document the test
 * carries with it.
 *
 * @code
 * tapi_smb_target target = TAPI_SMB_TARGET_INIT;
 * te_vec entries = TE_VEC_INIT(tapi_smb_dirent);
 *
 * target.server = "fileserver";
 * target.user = "alice";
 * target.password = "s3cret";
 *
 * CHECK_RC(tapi_smb_put_from_engine(factory, TAPI_SMB_AUTO, &target,
 *                                   "share", "report.pdf",
 *                                   "/local/report.pdf", 30000));
 * CHECK_RC(tapi_smb_ls(factory, TAPI_SMB_AUTO, &target, "share", "",
 *                      30000, &entries));
 * @endcode
 */

#ifndef __TSF_TAPI_SMB_FILE_H__
#define __TSF_TAPI_SMB_FILE_H__

#include "te_defs.h"
#include "te_errno.h"
#include "te_string.h"
#include "te_vector.h"
#include "tapi_job.h"

#include "tapi_smb.h"

#ifdef __cplusplus
extern "C" {
#endif

/** One entry of a directory on a share. */
typedef struct tapi_smb_dirent {
    /** Its name, without the path. */
    char *name;
    /** @c true when it is a directory. */
    bool is_dir;
    /** Size in bytes; @c -1 for a directory or when unknown. */
    long size;
} tapi_smb_dirent;

/**
 * What a POSIX stat of a path on a share said - the owner and the
 * mode, which is what the identity a session runs as and the reach of
 * a symlink are judged from.
 */
typedef struct tapi_smb_stat_info {
    /** Owning user id, or @c -1 when the server did not give it. */
    long uid;
    /** Owning group id, or @c -1 when the server did not give it. */
    long gid;
    /** Permission bits (the low 12), or @c -1 when not given. */
    long mode;
    /** Size in bytes, or @c -1. */
    long size;
    /** @c true when the path is a directory. */
    bool is_dir;
    /** @c true when the path is a symlink. */
    bool is_symlink;
} tapi_smb_stat_info;

/**
 * Put a file that is on the agent onto a share.
 *
 * @param factory       Job factory.
 * @param backend       Backend, or @ref TAPI_SMB_AUTO.
 * @param target        Server and credentials.
 * @param share         Share name.
 * @param remote        Path on the share, forward slashes.
 * @param local         Path on the agent.
 * @param timeout_ms    Timeout, ms.
 *
 * @return Status code.
 * @retval TE_EACCES    The login or the write was refused.
 * @retval TE_ENOENT    There is no such share, or no such path on it.
 */
extern te_errno tapi_smb_put(tapi_job_factory_t *factory,
                             tapi_smb_backend backend,
                             const tapi_smb_target *target,
                             const char *share, const char *remote,
                             const char *local, int timeout_ms);

/**
 * Get a file from a share onto the agent.
 *
 * @param factory       Job factory.
 * @param backend       Backend, or @ref TAPI_SMB_AUTO.
 * @param target        Server and credentials.
 * @param share         Share name.
 * @param remote        Path on the share, forward slashes.
 * @param local         Path on the agent.
 * @param timeout_ms    Timeout, ms.
 *
 * @return Status code.
 */
extern te_errno tapi_smb_get(tapi_job_factory_t *factory,
                             tapi_smb_backend backend,
                             const tapi_smb_target *target,
                             const char *share, const char *remote,
                             const char *local, int timeout_ms);

/**
 * Put a file from the engine onto a share, via the agent.
 *
 * The file is copied to the agent, put on the share, and removed from
 * the agent.
 *
 * @param factory       Job factory.
 * @param backend       Backend, or @ref TAPI_SMB_AUTO.
 * @param target        Server and credentials.
 * @param share         Share name.
 * @param remote        Path on the share.
 * @param engine_path   File on the engine.
 * @param timeout_ms    Timeout, ms.
 *
 * @return Status code.
 */
extern te_errno tapi_smb_put_from_engine(tapi_job_factory_t *factory,
                                         tapi_smb_backend backend,
                                         const tapi_smb_target *target,
                                         const char *share,
                                         const char *remote,
                                         const char *engine_path,
                                         int timeout_ms);

/**
 * Get a file from a share to the engine, via the agent.
 *
 * @param factory       Job factory.
 * @param backend       Backend, or @ref TAPI_SMB_AUTO.
 * @param target        Server and credentials.
 * @param share         Share name.
 * @param remote        Path on the share.
 * @param engine_path   Where to write it on the engine.
 * @param timeout_ms    Timeout, ms.
 *
 * @return Status code.
 */
extern te_errno tapi_smb_get_to_engine(tapi_job_factory_t *factory,
                                       tapi_smb_backend backend,
                                       const tapi_smb_target *target,
                                       const char *share, const char *remote,
                                       const char *engine_path,
                                       int timeout_ms);

/**
 * Write bytes to a file on a share, from a string.
 *
 * @param factory       Job factory.
 * @param backend       Backend, or @ref TAPI_SMB_AUTO.
 * @param target        Server and credentials.
 * @param share         Share name.
 * @param remote        Path on the share.
 * @param content       The bytes.
 * @param len           How many.
 * @param timeout_ms    Timeout, ms.
 *
 * @return Status code.
 */
extern te_errno tapi_smb_write(tapi_job_factory_t *factory,
                               tapi_smb_backend backend,
                               const tapi_smb_target *target,
                               const char *share, const char *remote,
                               const void *content, size_t len,
                               int timeout_ms);

/**
 * Read a whole file from a share into a string.
 *
 * @param[in]  factory      Job factory.
 * @param[in]  backend      Backend, or @ref TAPI_SMB_AUTO.
 * @param[in]  target       Server and credentials.
 * @param[in]  share        Share name.
 * @param[in]  remote       Path on the share.
 * @param[in]  timeout_ms   Timeout, ms.
 * @param[out] content      String to append the file to.
 *
 * @return Status code.
 */
extern te_errno tapi_smb_read(tapi_job_factory_t *factory,
                              tapi_smb_backend backend,
                              const tapi_smb_target *target,
                              const char *share, const char *remote,
                              int timeout_ms, te_string *content);

/**
 * List a directory on a share.
 *
 * @param[in]  factory      Job factory.
 * @param[in]  backend      Backend, or @ref TAPI_SMB_AUTO.
 * @param[in]  target       Server and credentials.
 * @param[in]  share        Share name.
 * @param[in]  path         Directory on the share, @c "" for its root.
 * @param[in]  timeout_ms   Timeout, ms.
 * @param[out] entries      Vector of #tapi_smb_dirent to append to;
 *                          release with tapi_smb_dirents_free(). @c "."
 *                          and @c ".." are left out.
 *
 * @return Status code.
 */
extern te_errno tapi_smb_ls(tapi_job_factory_t *factory,
                            tapi_smb_backend backend,
                            const tapi_smb_target *target, const char *share,
                            const char *path, int timeout_ms,
                            te_vec *entries);

/**
 * Is there a file or directory at this path on a share?
 *
 * @param factory       Job factory.
 * @param backend       Backend, or @ref TAPI_SMB_AUTO.
 * @param target        Server and credentials.
 * @param share         Share name.
 * @param remote        Path on the share.
 * @param timeout_ms    Timeout, ms.
 *
 * @return @c true when it is there.
 */
extern bool tapi_smb_exists(tapi_job_factory_t *factory,
                            tapi_smb_backend backend,
                            const tapi_smb_target *target, const char *share,
                            const char *remote, int timeout_ms);

/**
 * Make a directory on a share.
 *
 * @param factory       Job factory.
 * @param backend       Backend, or @ref TAPI_SMB_AUTO.
 * @param target        Server and credentials.
 * @param share         Share name.
 * @param remote        Path on the share.
 * @param timeout_ms    Timeout, ms.
 *
 * @return Status code.
 */
extern te_errno tapi_smb_mkdir(tapi_job_factory_t *factory,
                               tapi_smb_backend backend,
                               const tapi_smb_target *target,
                               const char *share, const char *remote,
                               int timeout_ms);

/**
 * Remove an empty directory from a share.
 *
 * @param factory       Job factory.
 * @param backend       Backend, or @ref TAPI_SMB_AUTO.
 * @param target        Server and credentials.
 * @param share         Share name.
 * @param remote        Path on the share.
 * @param timeout_ms    Timeout, ms.
 *
 * @return Status code.
 * @retval TE_ENOTEMPTY The directory is not empty.
 */
extern te_errno tapi_smb_rmdir(tapi_job_factory_t *factory,
                               tapi_smb_backend backend,
                               const tapi_smb_target *target,
                               const char *share, const char *remote,
                               int timeout_ms);

/**
 * Remove a file from a share.
 *
 * @param factory       Job factory.
 * @param backend       Backend, or @ref TAPI_SMB_AUTO.
 * @param target        Server and credentials.
 * @param share         Share name.
 * @param remote        Path on the share.
 * @param timeout_ms    Timeout, ms.
 *
 * @return Status code.
 */
extern te_errno tapi_smb_unlink(tapi_job_factory_t *factory,
                                tapi_smb_backend backend,
                                const tapi_smb_target *target,
                                const char *share, const char *remote,
                                int timeout_ms);

/**
 * Create a POSIX symlink inside a share.
 *
 * The link is made through the CIFS UNIX extensions, so it needs a
 * server that exposes them (tapi_smb_unix_extensions()) reached over
 * SMB1, and a backend that has @ref TAPI_SMB_FEAT_POSIX - Samba only.
 * @p points_to is written into the link verbatim and is not resolved
 * here: an absolute path that leaves the share is exactly what a
 * wide-links check wants, and whether the server then follows it out
 * of the share is the thing under test.
 *
 * @param factory       Job factory.
 * @param backend       Backend, or @ref TAPI_SMB_AUTO.
 * @param target        Server and credentials.
 * @param share         Share name.
 * @param linkname      Name of the link to create, relative to the
 *                      share root, forward slashes.
 * @param points_to     What the link points to, as the server's own
 *                      filesystem sees it - may be outside the share.
 * @param timeout_ms    Timeout, ms.
 *
 * @return Status code.
 * @retval TE_EOPNOTSUPP    The backend has no POSIX extensions.
 * @retval TE_EACCES        The server refused the link.
 */
extern te_errno tapi_smb_symlink(tapi_job_factory_t *factory,
                                 tapi_smb_backend backend,
                                 const tapi_smb_target *target,
                                 const char *share, const char *linkname,
                                 const char *points_to, int timeout_ms);

/**
 * POSIX-stat a path on a share: its owner, mode and kind.
 *
 * Read through the CIFS UNIX extensions, so, like tapi_smb_symlink(),
 * Samba over SMB1 only. It is how the identity a session was mapped to
 * is read back - stat a file the session itself created and look at
 * @a uid - and how a symlink that escaped the share is confirmed to
 * reach a privileged, otherwise unreadable file.
 *
 * @param[in]  factory      Job factory.
 * @param[in]  backend      Backend, or @ref TAPI_SMB_AUTO.
 * @param[in]  target       Server and credentials.
 * @param[in]  share        Share name.
 * @param[in]  remote       Path on the share, forward slashes.
 * @param[in]  timeout_ms   Timeout, ms.
 * @param[out] info         What the stat said.
 *
 * @return Status code.
 * @retval TE_EOPNOTSUPP    The backend has no POSIX extensions.
 * @retval TE_ENOENT        There is no such path.
 * @retval TE_EPROTO        The server gave no stat this could read.
 */
extern te_errno tapi_smb_stat(tapi_job_factory_t *factory,
                              tapi_smb_backend backend,
                              const tapi_smb_target *target,
                              const char *share, const char *remote,
                              int timeout_ms, tapi_smb_stat_info *info);

/**
 * Release a vector of directory entries.
 *
 * @param entries       Vector of #tapi_smb_dirent.
 */
extern void tapi_smb_dirents_free(te_vec *entries);

#ifdef __cplusplus
} /* extern "C" */
#endif
#endif /* !__TSF_TAPI_SMB_FILE_H__ */

/**@} <!-- END tapi_smb_file --> */
