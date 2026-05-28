/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (C) 2026 Interpretica Unipessoal Lda */
/** @file
 * @brief What an SMB server is worth
 *
 * The negotiation is done by a small python3 helper put on the agent,
 * not by driving a client: a client tells you it connected, not what
 * the server would and would not agree to. The helper sends a raw
 * SMB1 and then an SMB2 negotiate for each dialect and prints, per
 * dialect, whether it was accepted and whether signing was required
 * and encryption offered - which is exactly the posture. It was
 * written against Samba 4.17 and its answers checked against
 * @c nmap @c --script @c smb2-security-mode,smb-protocols.
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
#include "tapi_cfg_base.h"
#include "tapi_file.h"

#include "tapi_smb.h"
#include "tapi_smb_file.h"
#include "tapi_smb_audit.h"
#include "tapi_smb_internal.h"

/* See description in tapi_smb_audit.h */
const tapi_smb_policy tapi_smb_default_policy = {
    .allow_anonymous = false,
    .allow_guest = false,
    .allow_unencrypted = false,
    .guest_share = NULL,
};

/**
 * The SMB negotiate helper. One argument, @c host[:port]; it prints
 * one line per probe:
 *
 *   smb1 accepted|refused
 *   smb2 <hex-dialect> accepted signing=required|enabled encryption=yes|no
 *   smb2 <hex-dialect> refused
 *
 * and exits 2 when nothing answered on the port.
 */
static const char smb_negotiate_py[] =
"import os,socket,struct,sys\n"
"host=sys.argv[1]; port=int(sys.argv[2]) if len(sys.argv)>2 else 445\n"
"to=float(sys.argv[3]) if len(sys.argv)>3 else 5.0\n"
"D=[0x0202,0x0210,0x0300,0x0302,0x0311]\n"
"def ex(p):\n"
" try:\n"
"  s=socket.create_connection((host,port),to)\n"
" except OSError as e:\n"
"  sys.stderr.write(str(e)+'\\n'); sys.exit(2)\n"
" try:\n"
"  s.sendall(struct.pack('>I',len(p))+p); h=b''\n"
"  while len(h)<4:\n"
"   c=s.recv(4-len(h))\n"
"   if not c: return None\n"
"   h+=c\n"
"  n=struct.unpack('>I',h)[0]&0xffffff; b=b''\n"
"  while len(b)<n:\n"
"   c=s.recv(n-len(b))\n"
"   if not c: return None\n"
"   b+=c\n"
"  return b\n"
" except OSError: return None\n"
" finally: s.close()\n"
"def smb1():\n"
" d=b'\\x02NT LM 0.12\\x00'\n"
" hd=b'\\xffSMB'+bytes([0x72])+b'\\x00'*4+bytes([0x18])+struct.pack('<H',0xc853)+b'\\x00'*12+struct.pack('<HHHH',0,0xfeff,0,0)\n"
" r=ex(hd+b'\\x00'+struct.pack('<H',len(d))+d)\n"
" if r is None or r[:4]!=b'\\xffSMB' or len(r)<37: return None\n"
" if struct.unpack('<I',r[5:9])[0]!=0 or r[32]==0: return None\n"
" if struct.unpack('<H',r[33:35])[0]==0xffff: return None\n"
" return True\n"
"def smb2(dl):\n"
" body=struct.pack('<HHHHI',36,1,1,0,0x7f)+os.urandom(16)\n"
" ctx=b''\n"
" if dl==0x0311:\n"
"  off=64+36+2; pad=(8-off%8)%8; off+=pad\n"
"  pa=struct.pack('<HHH',1,32,1)+os.urandom(32); c1=struct.pack('<HHI',1,len(pa),0)+pa; c1+=b'\\x00'*((8-len(c1)%8)%8)\n"
"  ci=struct.pack('<HHHHH',4,4,3,2,1); c2=struct.pack('<HHI',2,len(ci),0)+ci\n"
"  body+=struct.pack('<IHH',off,2,0); ctx=b'\\x00'*pad+c1+c2\n"
" else: body+=b'\\x00'*8\n"
" body+=struct.pack('<H',dl)+ctx\n"
" hd=b'\\xfeSMB'+struct.pack('<HHIHHIIQII',64,0,0,0,1,0,0,0,0,0)+struct.pack('<Q',0)+b'\\x00'*16\n"
" r=ex(hd+body)\n"
" if r is None or r[:4]!=b'\\xfeSMB' or len(r)<128: return None\n"
" if struct.unpack('<I',r[8:12])[0]!=0: return None\n"
" rr=r[64:]; sm,rev=struct.unpack('<HH',rr[2:6]); caps=struct.unpack('<I',rr[24:28])[0]\n"
" if rev!=dl: return None\n"
" cip=0\n"
" if dl==0x0311:\n"
"  cnt=struct.unpack('<H',rr[6:8])[0]; p=struct.unpack('<I',rr[60:64])[0]\n"
"  for _ in range(cnt):\n"
"   ct,cl=struct.unpack('<HH',r[p:p+4]); dt=r[p+8:p+8+cl]\n"
"   if ct==2 and cl>=4: cip=struct.unpack('<H',dt[2:4])[0]\n"
"   p+=8+cl; p+=(8-p%8)%8\n"
" return (sm,caps,cip)\n"
"print('smb1 '+('accepted' if smb1() else 'refused'))\n"
"for d in D:\n"
" r=smb2(d)\n"
" if r is None: print('smb2 %04x refused'%d); continue\n"
" sm,caps,cip=r\n"
" print('smb2 %04x accepted signing=%s encryption=%s'%(d,'required' if sm&2 else 'enabled','yes' if (caps&0x40 or cip) else 'no'))\n";

/** What the negotiate helper found. */
typedef struct smb_negotiated {
    /** The server answered on the port at all. */
    bool answered;
    /** SMB1 was accepted. */
    bool smb1;
    /** Some dialect required signing. */
    bool signing_required;
    /** Some dialect was accepted at all. */
    bool any;
    /** Some accepted dialect offered encryption (an SMB3 one). */
    bool encryption;
} smb_negotiated;

/** Put the helper on the agent and run it against @p target. */
static te_errno
smb_negotiate(tapi_job_factory_t *factory, const tapi_smb_target *target,
              int timeout_ms, smb_negotiated *neg)
{
    const char *ta = tapi_smb_factory_ta(factory);
    te_vec args = TE_VEC_INIT(char *);
    te_string path = TE_STRING_INIT;
    te_string out = TE_STRING_INIT;
    te_string err = TE_STRING_INIT;
    char *tmp_dir;
    const char *line;
    int code = 0;
    te_errno rc;

    memset(neg, 0, sizeof(*neg));

    if (ta == NULL)
        return TE_RC(TE_TAPI, TE_EINVAL);

    tmp_dir = tapi_cfg_base_get_ta_dir(ta, TAPI_CFG_BASE_TA_DIR_TMP);
    if (tmp_dir == NULL)
        return TE_RC(TE_TAPI, TE_EFAIL);
    tapi_file_make_custom_pathname(&path, tmp_dir, "-smbneg.py");
    free(tmp_dir);

    rc = tapi_file_create_ta(ta, path.ptr, "%s", smb_negotiate_py);
    if (rc != 0)
    {
        ERROR("Failed to put the SMB negotiate helper on TA %s: %r", ta, rc);
        goto out;
    }

    tapi_smb_arg(&args, "%s", path.ptr);
    tapi_smb_arg(&args, "%s", target->server);
    tapi_smb_arg(&args, "%u", target->port != 0 ? target->port : 445);

    rc = tapi_smb_sh(factory, "python3", &args, NULL, timeout_ms, &out,
                     &err, &code);
    if (rc != 0)
        goto out;

    if (code == TAPI_SMB_EXIT_NOT_FOUND)
    {
        WARN("There is no python3 on TA %s to negotiate with", ta);
        rc = TE_RC(TE_TAPI, TE_ENOENT);
        goto out;
    }
    if (code == 2)
    {
        rc = TE_RC(TE_TAPI, TE_ECONNREFUSED);
        goto out;
    }

    neg->answered = true;
    for (line = te_string_value(&out); line != NULL && *line != '\0'; )
    {
        if (strncmp(line, "smb1 accepted", strlen("smb1 accepted")) == 0)
        {
            neg->smb1 = true;
        }
        else if (strncmp(line, "smb2 ", 5) == 0 &&
                 strstr(line, " accepted") != NULL)
        {
            neg->any = true;
            if (strstr(line, "signing=required") != NULL)
                neg->signing_required = true;
            if (strstr(line, "encryption=yes") != NULL)
                neg->encryption = true;
        }

        line = strchr(line, '\n');
        if (line != NULL)
            line++;
    }

out:
    tapi_file_ta_unlink_fmt(ta, "%s", path.ptr);
    te_vec_deep_free(&args);
    te_string_free(&path);
    te_string_free(&out);
    te_string_free(&err);

    return rc;
}

/* See description in tapi_smb_audit.h */
te_errno
tapi_smb_audit(tapi_job_factory_t *factory, tapi_smb_backend backend,
               const tapi_smb_target *target, const tapi_smb_policy *policy,
               int timeout_ms, tapi_cybersec_report *report)
{
    smb_negotiated neg;
    te_string subject = TE_STRING_INIT;
    te_errno rc;

    if (target == NULL || target->server == NULL)
    {
        ERROR("An SMB audit needs a server");
        return TE_RC(TE_TAPI, TE_EINVAL);
    }
    if (policy == NULL)
        policy = &tapi_smb_default_policy;

    te_string_append(&subject, "%s", target->server);

    rc = smb_negotiate(factory, target, timeout_ms, &neg);
    if (TE_RC_GET_ERROR(rc) == TE_ENOENT)
    {
        tapi_cybersec_report_add(report, TAPI_CYBERSEC_SEV_INFO,
                                 "smb.not-assessed", subject.ptr,
                                 "There is no python3 on the agent, so the "
                                 "server's dialects and signing were not "
                                 "measured");
        rc = 0;
        goto shares;
    }
    if (rc != 0)
    {
        te_string_free(&subject);
        return rc;
    }

    if (neg.smb1)
    {
        tapi_cybersec_report_add(report, TAPI_CYBERSEC_SEV_HIGH,
                                 "smb.smb1-enabled", subject.ptr,
                                 "The server answers an SMB1 negotiate - "
                                 "the protocol WannaCry spread over");
    }

    if (neg.any && !neg.signing_required)
    {
        tapi_cybersec_report_add(report, TAPI_CYBERSEC_SEV_MEDIUM,
                                 "smb.no-signing-required", subject.ptr,
                                 "The server accepts a connection it will "
                                 "not sign, so a man in the middle can alter "
                                 "traffic");
    }

    if (neg.any && !neg.encryption && !policy->allow_unencrypted)
    {
        tapi_cybersec_report_add(report, TAPI_CYBERSEC_SEV_MEDIUM,
                                 "smb.no-encryption", subject.ptr,
                                 "The server offers no encrypted dialect, so "
                                 "files cross the network readable");
    }

shares:
    /*
     * The anonymous-list check needs a client, and is skipped where
     * there is none rather than failing the audit: the negotiation
     * above is the part that always runs.
     */
    if (!policy->allow_anonymous &&
        tapi_smb_available(factory, backend, timeout_ms))
    {
        tapi_smb_target anon = *target;
        te_vec shares = TE_VEC_INIT(tapi_smb_share_info);
        te_errno list_rc;

        anon.user = NULL;
        anon.password = NULL;
        list_rc = tapi_smb_list(factory, backend, &anon, timeout_ms,
                                &shares);
        if (list_rc == 0 && te_vec_size(&shares) != 0)
        {
            tapi_cybersec_report_add(report, TAPI_CYBERSEC_SEV_MEDIUM,
                                     "smb.anonymous-shares", subject.ptr,
                                     "A null session lists the server's "
                                     "shares");
        }
        tapi_smb_shares_free(&shares);
    }

    if (!policy->allow_guest && policy->guest_share != NULL &&
        tapi_smb_supports(backend == TAPI_SMB_AUTO ? TAPI_SMB_SAMBA :
                          backend, TAPI_SMB_FEAT_FILES))
    {
        tapi_smb_target guest = *target;
        te_string remote = TE_STRING_INIT;
        te_errno w;

        /*
         * A guest login is a null session that the server maps to
         * guest (map to guest = Bad User): user NULL, so smbclient is
         * given -N and never asks for a password - which, in a job
         * with no terminal, is what keeps it from stalling.
         */
        guest.user = NULL;
        guest.password = NULL;
        te_string_append(&remote, "tsf_audit_probe.txt");
        w = tapi_smb_write(factory, backend, &guest, policy->guest_share,
                           remote.ptr, "probe", 5, timeout_ms);
        if (w == 0)
        {
            tapi_cybersec_report_add(report, TAPI_CYBERSEC_SEV_HIGH,
                                     "smb.guest-writable",
                                     policy->guest_share,
                                     "A guest login can write to the share");
            /* Clean up what the probe wrote. */
            tapi_smb_unlink(factory, backend, &guest, policy->guest_share,
                            remote.ptr, timeout_ms);
        }
        te_string_free(&remote);
    }

    te_string_free(&subject);

    return rc;
}
