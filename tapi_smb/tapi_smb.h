/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Interpretica Unipessoal Lda */
/** @file
 * @brief SMB from a test
 *
 * @defgroup tapi_smb SMB/CIFS (tapi_smb)
 * @{
 *
 * SMB from a Test Agent: reaching a file server over the network,
 * listing its shares, reading and writing files on them, and - the
 * other direction - serving a share from the agent so that one agent
 * serves and another connects. On Linux, macOS and Windows.
 *
 * - @ref tapi_smb - backends, targets, listing shares, dialects;
 * - @ref tapi_smb_file - files on a share: put, get, list, remove,
 *   make and remove directories;
 * - @ref tapi_smb_share - shares served by the agent;
 * - @ref tapi_smb_audit - a server read as a security posture.
 *
 * Everything runs on the agent behind a job factory. The client is
 * the agent, and the server is whatever it can reach - which may be
 * another agent serving a share, so a test of SMB is two factories:
 * one that serves and one that connects.
 *
 * @section tapi_smb_backends Three backends, and no pretence
 *
 * - **@ref TAPI_SMB_SAMBA** - Linux and the BSDs: @c smbclient for the
 *   client, @c net and @c testparm for a server, @c smbcontrol and
 *   @c smbstatus around them. The complete one.
 * - **@ref TAPI_SMB_MACOS** - @c smbutil and @c mount_smbfs. It lists
 *   shares, mounts one and works through the mount, and reads what the
 *   mounted connection negotiated. It cannot ask for a dialect or a
 *   signing requirement per connection: macOS keeps those in
 *   @c nsmb.conf, which is the whole machine's, and this library does
 *   not rewrite a machine-wide file behind a test's back.
 * - **@ref TAPI_SMB_WINDOWS** - PowerShell: the SMB client and share
 *   cmdlets, @c New-SmbMapping for a drive and @c Get-SmbConnection
 *   for what it negotiated.
 *
 * The common core is only what all three genuinely do, and the rest is
 * behind tapi_smb_supports(); an operation a backend cannot do is
 * refused with @c TE_EOPNOTSUPP.
 *
 * | | Samba | macOS | Windows |
 * |---|---|---|---|
 * | list a server's shares | yes | yes | yes |
 * | put, get, list, remove files | yes | yes | yes |
 * | make and remove directories | yes | yes | yes |
 * | choose the dialect range | yes | no | yes |
 * | require signing | yes | no | yes |
 * | require encryption | yes | yes | yes |
 * | what the connection negotiated | yes | yes | yes |
 * | serve a share | yes | no | yes |
 *
 * @code
 * tapi_smb_target target = TAPI_SMB_TARGET_INIT;
 * te_vec shares = TE_VEC_INIT(tapi_smb_share_info);
 *
 * target.server = "fileserver";
 * target.user = "alice";
 * target.password = "s3cret";
 *
 * if (!tapi_smb_available(factory, TAPI_SMB_AUTO, 10000))
 *     TEST_SKIP("There is no SMB client on the agent");
 * CHECK_RC(tapi_smb_list(factory, TAPI_SMB_AUTO, &target, 30000, &shares));
 * @endcode
 */

#ifndef __TSF_TAPI_SMB_H__
#define __TSF_TAPI_SMB_H__

#include "te_defs.h"
#include "te_errno.h"
#include "te_string.h"
#include "te_vector.h"
#include "tapi_job.h"

#ifdef __cplusplus
extern "C" {
#endif

/** Default timeout for one SMB command, ms. */
#define TAPI_SMB_TIMEOUT_MS 30000

/** How the agent's SMB is reached. */
typedef enum tapi_smb_backend {
    /** Ask the agent which of the others it has. */
    TAPI_SMB_AUTO = 0,
    /** Samba tools: Linux, the BSDs. */
    TAPI_SMB_SAMBA,
    /** macOS: @c smbutil and @c mount_smbfs. */
    TAPI_SMB_MACOS,
    /** Windows: PowerShell SMB cmdlets. */
    TAPI_SMB_WINDOWS,
} tapi_smb_backend;

/**
 * An SMB dialect. The values are the wire numbers, so a bound can be
 * compared and the newest of what a server offered can be found.
 */
typedef enum tapi_smb_dialect {
    /** Not set. */
    TAPI_SMB_DIALECT_ANY = 0,
    /** SMB1 / CIFS (NT LM 0.12). The dangerous one. */
    TAPI_SMB_DIALECT_NT1 = 0x0001,
    /** SMB 2.0.2. */
    TAPI_SMB_DIALECT_SMB2_02 = 0x0202,
    /** SMB 2.1. */
    TAPI_SMB_DIALECT_SMB2_10 = 0x0210,
    /** SMB 3.0. */
    TAPI_SMB_DIALECT_SMB3_00 = 0x0300,
    /** SMB 3.0.2. */
    TAPI_SMB_DIALECT_SMB3_02 = 0x0302,
    /** SMB 3.1.1. */
    TAPI_SMB_DIALECT_SMB3_11 = 0x0311,
} tapi_smb_dialect;

/** List a server's shares. */
#define TAPI_SMB_FEAT_LIST      (1u << 0)
/** Read and write files on a share. */
#define TAPI_SMB_FEAT_FILES     (1u << 1)
/** Choose the dialect range per connection. */
#define TAPI_SMB_FEAT_DIALECT   (1u << 2)
/** Require signing per connection. */
#define TAPI_SMB_FEAT_SIGNING   (1u << 3)
/** Require encryption per connection. */
#define TAPI_SMB_FEAT_ENCRYPT   (1u << 4)
/** Read what the connection negotiated. */
#define TAPI_SMB_FEAT_NEGOTIATED (1u << 5)
/** Serve a share from the agent. */
#define TAPI_SMB_FEAT_SERVE     (1u << 6)
/**
 * POSIX / CIFS UNIX extensions on a share: create a symlink in it,
 * read a file's owner and mode. The one thing a wide-links path
 * traversal is built out of, and a Samba-only, SMB1-era feature.
 */
#define TAPI_SMB_FEAT_POSIX     (1u << 7)

/** A server and the credentials to reach it with. */
typedef struct tapi_smb_target {
    /** Server host name or address. */
    const char *server;
    /** TCP port, or @c 0 for 445. */
    unsigned int port;
    /**
     * User name, or @c NULL for an anonymous (null-session) login.
     * The empty string is the guest login where the server maps it.
     */
    const char *user;
    /** Password, or @c NULL. */
    const char *password;
    /** Domain or workgroup, or @c NULL. */
    const char *domain;
    /**
     * Oldest dialect to offer. @ref TAPI_SMB_DIALECT_ANY leaves it to
     * the tool's default, which on a current Samba and Windows is
     * SMB 2.0.2 - SMB1 is off unless it is asked for here.
     */
    tapi_smb_dialect min_dialect;
    /** Newest dialect to offer, or @ref TAPI_SMB_DIALECT_ANY. */
    tapi_smb_dialect max_dialect;
    /** Refuse a connection the server will not sign. */
    bool require_signing;
    /** Refuse a connection the server will not encrypt. */
    bool require_encryption;
} tapi_smb_target;

/** Initializer for #tapi_smb_target. */
#define TAPI_SMB_TARGET_INIT { .server = NULL }

/** A share, as a server lists it. */
typedef struct tapi_smb_share_info {
    /** Share name. */
    char *name;
    /** Comment, or @c NULL. */
    char *comment;
    /**
     * @c true for a disk share, @c false for a printer, IPC or
     * anything else - the things a file test cannot use.
     */
    bool is_disk;
} tapi_smb_share_info;

/** What a connection negotiated. */
typedef struct tapi_smb_conn_info {
    /** The dialect in force. */
    tapi_smb_dialect dialect;
    /** @c true when this connection is signed. */
    bool signed_conn;
    /** @c true when this connection is encrypted. */
    bool encrypted;
    /** The server's name as it gave it, or @c NULL. */
    char *server;
    /** Free text the tool gave; for the log. */
    char *detail;
} tapi_smb_conn_info;

/**
 * Is there an SMB client on the agent?
 *
 * @param factory       Job factory.
 * @param backend       Backend to check, or @ref TAPI_SMB_AUTO.
 * @param timeout_ms    Timeout, ms.
 *
 * @return @c true when the tools are there.
 */
extern bool tapi_smb_available(tapi_job_factory_t *factory,
                               tapi_smb_backend backend, int timeout_ms);

/**
 * Work out which SMB tooling the agent has.
 *
 * @param[in]  factory      Job factory.
 * @param[in]  timeout_ms   Timeout, ms.
 * @param[out] backend      The backend found.
 *
 * @return Status code.
 * @retval TE_ENOENT        Nothing on the agent answers.
 */
extern te_errno tapi_smb_detect(tapi_job_factory_t *factory, int timeout_ms,
                                tapi_smb_backend *backend);

/**
 * What a backend can do.
 *
 * @param backend       Backend.
 *
 * @return A mask of @c TAPI_SMB_FEAT_*.
 */
extern unsigned int tapi_smb_features(tapi_smb_backend backend);

/**
 * Can this backend do this?
 *
 * @param backend       Backend.
 * @param feature       One or more @c TAPI_SMB_FEAT_*.
 *
 * @return @c true when all of @p feature are supported.
 */
extern bool tapi_smb_supports(tapi_smb_backend backend,
                              unsigned int feature);

/**
 * List the shares of a server.
 *
 * @note An anonymous target (@a user @c NULL) lists only what the
 *       server shows a null session, which a server with
 *       @c "restrict anonymous = 2" refuses outright with
 *       @c TE_EACCES - and that refusal is itself what
 *       tapi_smb_audit() checks.
 *
 * @param[in]  factory      Job factory.
 * @param[in]  backend      Backend, or @ref TAPI_SMB_AUTO.
 * @param[in]  target       Server and credentials.
 * @param[in]  timeout_ms   Timeout, ms.
 * @param[out] shares       Vector of #tapi_smb_share_info to append to;
 *                          release with tapi_smb_shares_free().
 *
 * @return Status code.
 * @retval TE_EACCES        The login was refused.
 * @retval TE_EOPNOTSUPP    The target asks for something the backend
 *                          cannot force - a dialect or signing on
 *                          macOS.
 */
extern te_errno tapi_smb_list(tapi_job_factory_t *factory,
                              tapi_smb_backend backend,
                              const tapi_smb_target *target, int timeout_ms,
                              te_vec *shares);

/**
 * Read what a connection to @p share negotiated.
 *
 * The one operation whose whole purpose is the connection rather than
 * a file: it opens one, reads the dialect, signing and encryption in
 * force, and closes it.
 *
 * @param[in]  factory      Job factory.
 * @param[in]  backend      Backend, or @ref TAPI_SMB_AUTO.
 * @param[in]  target       Server and credentials.
 * @param[in]  share        Share name.
 * @param[in]  timeout_ms   Timeout, ms.
 * @param[out] info         What it negotiated; release with
 *                          tapi_smb_conn_info_free().
 *
 * @return Status code.
 */
extern te_errno tapi_smb_connect_info(tapi_job_factory_t *factory,
                                      tapi_smb_backend backend,
                                      const tapi_smb_target *target,
                                      const char *share, int timeout_ms,
                                      tapi_smb_conn_info *info);

/**
 * Can this server be reached with these terms at all?
 *
 * For the yes/no question behind a skip or an assertion: would a
 * connection with @p target's dialect bounds and signing and
 * encryption requirements succeed? It opens one and closes it.
 *
 * @param[in]  factory      Job factory.
 * @param[in]  backend      Backend, or @ref TAPI_SMB_AUTO.
 * @param[in]  target       Server and credentials.
 * @param[in]  share        Share to connect to.
 * @param[in]  timeout_ms   Timeout, ms.
 * @param[out] status       The NT status the server gave, or @c NULL.
 *
 * @return @c true when the connection succeeded.
 */
extern bool tapi_smb_can_connect(tapi_job_factory_t *factory,
                                 tapi_smb_backend backend,
                                 const tapi_smb_target *target,
                                 const char *share, int timeout_ms,
                                 te_string *status);

/**
 * Does the server expose CIFS UNIX extensions on this share?
 *
 * The question a wide-links traversal turns on: a server that
 * advertises the extensions to this session lets a POSIX client
 * create a symlink in the share and, where @c "wide links" is left on,
 * follow it out of the share. It is asked by negotiating the
 * extensions, not read from configuration. Samba only; another
 * backend answers @c false without asking.
 *
 * @note The extensions ride on SMB1, so the answer is @c true only for
 *       a @p target that reaches the server over SMB1 - set
 *       @a min_dialect and @a max_dialect to @ref TAPI_SMB_DIALECT_NT1.
 *
 * @param factory       Job factory.
 * @param backend       Backend, or @ref TAPI_SMB_AUTO.
 * @param target        Server and credentials.
 * @param share         Share to ask on.
 * @param timeout_ms    Timeout, ms.
 *
 * @return @c true when the share exposes the extensions to @p target.
 */
extern bool tapi_smb_unix_extensions(tapi_job_factory_t *factory,
                                     tapi_smb_backend backend,
                                     const tapi_smb_target *target,
                                     const char *share, int timeout_ms);

/**
 * Write connection info into the log.
 *
 * @param info      Connection info.
 */
extern void tapi_smb_conn_info_log(const tapi_smb_conn_info *info);

/**
 * Release connection info.
 *
 * @param info      Connection info.
 */
extern void tapi_smb_conn_info_free(tapi_smb_conn_info *info);

/**
 * Release a vector of shares.
 *
 * @param shares    Vector of #tapi_smb_share_info.
 */
extern void tapi_smb_shares_free(te_vec *shares);

/**
 * Spell out a backend.
 *
 * @param backend   Backend.
 *
 * @return A static string, never @c NULL.
 */
extern const char *tapi_smb_backend2str(tapi_smb_backend backend);

/**
 * Spell out a dialect, as @c "SMB3.1.1" or @c "SMB1".
 *
 * @param dialect   Dialect.
 *
 * @return A static string, never @c NULL.
 */
extern const char *tapi_smb_dialect2str(tapi_smb_dialect dialect);

#ifdef __cplusplus
} /* extern "C" */
#endif
#endif /* !__TSF_TAPI_SMB_H__ */

/**@} <!-- END tapi_smb --> */
