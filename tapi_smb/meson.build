# SPDX-License-Identifier: MIT
# Copyright (C) 2026 Interpretica Unipessoal Lda
#
# External TE library (see TE_EXT_REPO): engine-side SMB/CIFS - reaching a
# file server from an agent, the files on its shares, serving a share from
# the agent, and reading a server as a security posture - over Samba,
# macOS and Windows. Built as a shared library on the engine platform
# only, like tapi_bt: it calls tapi and tapi_job, engine libraries with no
# static variant, so a static build of it would fail the configure.

if get_option('engine')
    build_lib_shared = true
endif
build_lib_static = false
install_lib = install_dev

headers += files(
    'tapi_smb.h',
    'tapi_smb_audit.h',
    'tapi_smb_file.h',
    'tapi_smb_share.h',
)

# tapi_smb_internal.h is internal to this library and is not installed.
sources += files(
    'tapi_smb.c',
    'tapi_smb_audit.c',
    'tapi_smb_cmd.c',
    'tapi_smb_file.c',
    'tapi_smb_share.c',
)

te_libs += [
    'tapi',
    'tapi_job',
    'tapi_devtool',
    'tapi_cybersec',
]
