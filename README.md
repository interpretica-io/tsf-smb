# tsf-smb

SMB/CIFS from a test suite, packaged as an external Test Environment
(TE) repository.

Library:

- `tapi_smb` — engine-side, built as a shared library: reaching a file
  server from a Test Agent, the files on its shares, serving a share
  from the agent, and reading a server as a security posture — on
  Linux, macOS and Windows.
  - `tapi_smb` — backends, targets, listing a server's shares, and what
    a connection negotiated;
  - `tapi_smb_file` — files on a share: put, get, list, read, write,
    make and remove directories, remove a file;
  - `tapi_smb_share` — a share served from the agent, so one agent
    serves and another connects;
  - `tapi_smb_audit` — a server read as a security posture, reported
    through tsf-cybersec.

TE has no SMB of its own.

## Usage

Declare the repositories in an external libraries catalog and pass it
to `dispatcher.sh --external=external.yml`:

```yaml
repositories:
  - name: tsf_devtool
    url: https://github.com/interpretica-io/tsf-devtool.git
    ref: <tag>
    libs:
      - tapi_devtool
  - name: tsf_cybersec
    url: https://github.com/interpretica-io/tsf-cybersec.git
    ref: <tag>
    libs:
      - tapi_cybersec
  - name: tsf_smb
    url: https://github.com/interpretica-io/tsf-smb.git
    ref: <tag>
    libs:
      - tapi_smb
```

Bind them in `builder.conf`:

```
TE_EXT_REPO_USE([tsf_devtool], [], [tapi_devtool])
TE_EXT_REPO_USE([tsf_cybersec], [], [tapi_cybersec])
TE_EXT_REPO_USE([tsf_smb], [], [tapi_smb])
```

Then add `tapi_smb` to `te_libs` in the suite's `meson.build`.
Requires TE with `TE_EXT_REPO` support and an **RPC** job factory
(`ta_rpcprovider` on the agent): every call reads what a command
printed, which needs output channels, and only that factory has them.

```c
tapi_smb_target target = TAPI_SMB_TARGET_INIT;
te_vec shares = TE_VEC_INIT(tapi_smb_share_info);

target.server = "fileserver";
target.user = "alice";
target.password = "s3cret";

if (!tapi_smb_available(factory, TAPI_SMB_AUTO, 10000))
    TEST_SKIP("There is no SMB client on the agent");
CHECK_RC(tapi_smb_list(factory, TAPI_SMB_AUTO, &target, 30000, &shares));
```

## The client is the agent, the server is what it can reach

Everything runs on the agent behind a job factory. The client is the
agent; the server is whatever the agent can reach — which may be
another agent serving a share with `tapi_smb_serve()`. So a test of SMB
is two factories, one that serves and one that connects, or, for the
library's own tests, one agent doing both against `localhost`.

## Three backends, and no pretence

| | Samba | macOS | Windows |
|---|---|---|---|
| list a server's shares | yes | yes | yes |
| put, get, list, remove files | yes | yes | yes |
| make and remove directories | yes | yes | yes |
| choose the dialect range | yes | no | yes |
| require signing | yes | no | yes |
| require encryption | yes | yes | yes |
| what the connection negotiated | yes | yes | yes |
| serve a share | yes | no | yes |

- **Samba** — Linux and the BSDs: `smbclient` for the client, `net
  usershare` and `testparm` for a server, one command per operation so
  that a failure is the command's own. The complete one.
- **macOS** — `smbutil view` to list, and `mount_smbfs` to mount a
  share and work through the mount. It **cannot ask for a dialect or a
  signing requirement per connection**: macOS keeps those in
  `nsmb.conf`, which is the whole machine's, and this library does not
  rewrite a machine-wide file behind a test's back. A target that asks
  for either is refused with `TE_EOPNOTSUPP`. macOS does not serve a
  share from a command either.
- **Windows** — PowerShell: `New-SmbMapping` for a drive and the file
  cmdlets over it, `Get-SmbConnection` for what was negotiated,
  `New-SmbShare` to serve.

The common core is only what all three genuinely do; an operation a
backend cannot do is refused with `TE_EOPNOTSUPP`, never quietly
skipped.

## The password never goes on the command line

`smbclient` reads its password from the `PASSWD` environment variable,
and that is how this library passes it: the user name goes on the
command line with `-U`, and the password is in the job's environment,
where only the process's own user and root can see it. `-U
user%password` would put the password where anyone running `ps` on the
agent could read it.

The user name still goes on `-U` even for the password check, and this
is not cosmetic. Measured on Samba 4.17, a **wrong password supplied
in `USER` alone was not refused** — the session quietly continued
without those credentials, as an anonymous one — while `-U` with the
same wrong password failed with `NT_STATUS_LOGON_FAILURE`, which is the
answer a test that means to check a password needs.

## Measured, and what it shaped

- **A failure is an NT status in the output, not the exit code.** A
  single `smbclient -c` command's exit status is the last command's,
  and some commands lie in it: `rmdir` of a missing directory prints
  `NT_STATUS_OBJECT_NAME_NOT_FOUND` and still exits 0. So the output is
  always read for `NT_STATUS_*`, which is mapped to a TE error —
  `LOGON_FAILURE` to `TE_EACCES`, `BAD_NETWORK_NAME` to `TE_ENOENT`,
  and so on.
- **A usershare ACL is a SID, not a name.** `net usershare add ...
  Everyone:F` was refused for a non-root user with "cannot convert name
  Everyone to a SID"; the well-known SID `S-1-1-0` was taken. So that
  is what `tapi_smb_serve()` writes.
- **A guest usershare needs the server's blessing.** `guest_ok=y` is
  refused unless `smb.conf` has `usershare allow guests = yes`, and
  `net` says so plainly; that becomes `TE_EPERM` rather than an
  authenticated share pretending to be a guest one.
- **macOS attaches an extended attribute to every file this process
  writes** (`com.apple.provenance`), which appears on the share as a
  `._name` AppleDouble sidecar. It cannot be avoided by `cp -X`; it is
  a fact of writing from a Mac and a suite that counts files on a share
  should expect it.

## What the posture is worth

`tapi_smb_audit()` reads a server the way an attacker on the same
network would — over the wire, not from the server's configuration —
so it works against any SMB server the agent can reach. The
negotiation is done by a small `python3` helper put on the agent,
because a client tells you it connected, not what the server would and
would not agree to. It sends a raw SMB1 and an SMB2 negotiate per
dialect and reads back what was accepted, signed and encrypted.

| Finding | Severity | Read from |
|---|---|---|
| `smb.smb1-enabled` | high | the server accepts an SMB1 negotiate |
| `smb.no-signing-required` | medium | it accepts a connection it will not sign |
| `smb.no-encryption` | medium | it offers no SMB3 dialect, so nothing is encrypted |
| `smb.anonymous-shares` | medium | a null session lists its shares |
| `smb.guest-writable` | high | a guest login can write to a share |
| `smb.not-assessed` | info | the negotiation could not be done (no python3) |

`smb.smb1-enabled` is the one worth knowing about: SMB1 is the protocol
WannaCry spread over, it has no real integrity protection, and a
current Samba and Windows have it off by default. A server that answers
it was turned back on for something that should have been fixed another
way.

The negotiate helper's answers were checked against `nmap --script
smb2-security-mode,smb-protocols`: where nmap reported "Message signing
enabled and required" and listed `NT LM 0.12 (SMBv1)` among the
dialects, the helper reported `signing=required` and `smb1 accepted`,
and where the server was reconfigured the two moved together.

## What was verified, and what was not

**Samba (4.17, Debian 12) — verified through a Test Agent.** A TE suite
with a real agent (`Agt_A`, `ta_rpcprovider`) ran every call through
the job factory against a Samba server on the same host, and all tests
passed:

- `detect` — Samba found (not macOS or Windows), the capability table,
  listing `localhost`'s shares as a user, and a wrong password refused
  with `TE_EACCES`.
- `serve_files` — the agent served a scratch directory as a usershare,
  connected back to it, and round-tripped files: a byte-exact write and
  read, `exists()` true for a present file and false for an absent one,
  a directory made and listed (`hello.txt` at 16 bytes and `sub/` both
  in the listing), a file and directory removed, and a get of a missing
  file returning `TE_ENOENT`.
- `negotiate` — a default connection negotiated SMB3.1.1; capped at
  SMB2.1 it negotiated SMB2.1; `can_connect()` confirmed reachability;
  and macOS was refused a per-connection dialect it cannot force with
  `TE_EOPNOTSUPP`.
- `audit` — a server built to fail on purpose was read over the wire
  and every planted weakness reported: `smb.smb1-enabled`,
  `smb.no-signing-required`, `smb.anonymous-shares` and, for the
  guest-writable `public` share, `smb.guest-writable`. The negotiate
  helper's SMB1/signing findings were cross-checked against `nmap`.

**macOS (client) — command shapes verified live, not through an agent.**
`smbutil view`, `mount_smbfs`, `smbutil statshares` and the negotiate
helper were run on a real Mac against a Samba server: shares listed,
a share mounted and its files worked, and the mounted connection read
back as SMB3.1.1. The library code itself ran only on Linux; the macOS
backend's command strings are taken from those runs. macOS attaches
`com.apple.provenance` to files it writes, seen as `._name` sidecars on
the share — noted rather than fought.

**Windows — not verified.** Written from the PrintManagement, SmbShare
and SmbClient cmdlet documentation with no Windows machine to run it
on. The scripts name their own failures (`SMBERR`, `NOPRINTER`,
`SMBFAIL`) rather than arriving as a bare exit status.

## Scope

- **Files and shares change the world.** A test that writes to a share
  writes to a real server. The library's own verification wrote only to
  a share the agent served itself, in a scratch directory removed with
  the share.
- **Serving a share changes the agent**, and this library does not put
  it back: a test that serves removes the share in a cleanup section
  that runs even when the test failed.
- **The audit reads a server.** Beyond the SMB2 negotiate and, for the
  guest-writable check, one write it removes again, it sends nothing —
  it does not try an administrative operation to see whether it is
  allowed.
