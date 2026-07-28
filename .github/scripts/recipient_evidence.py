#!/usr/bin/env python3
"""Verify and safely materialize one Extra CODEOWNERS container evidence archive."""

from __future__ import annotations

import argparse
import contextlib
import dataclasses
import hashlib
import json
import os
import re
import shutil
import stat
import struct
import sys
import tomllib
import urllib.parse
import zlib
from collections.abc import Iterator, Mapping, Sequence
from pathlib import Path, PurePosixPath
from typing import Any, NoReturn

SCHEMA_VERSION = 9
VERIFIER_SCHEMA_VERSION = 1
EVIDENCE_MEDIA_TYPE = f"application/vnd.stampbot.container-evidence.v{SCHEMA_VERSION}+tar+gzip"
VERIFICATION_KIND = "extra-codeowners/container-evidence-verification"
REPOSITORY = "stampbot/extra-codeowners"

MAX_ARCHIVE_BYTES = 1024 * 1024 * 1024
MAX_EXPANDED_TAR_BYTES = 2 * 1024 * 1024 * 1024
MAX_RETAINED_BYTES = 1024 * 1024 * 1024
MAX_MEMBER_BYTES = 64 * 1024 * 1024
MAX_LARGE_SOURCE_BYTES = 128 * 1024 * 1024
MAX_MEMBERS = 100_000
MAX_PATH_BYTES = 4096
MAX_PATH_DEPTH = 32
MAX_TOTAL_PATH_COMPONENTS = 500_000
MAX_TOTAL_PATH_BYTES = 32 * 1024 * 1024
MAX_PAX_BYTES = 1024 * 1024
MAX_TOTAL_PAX_BYTES = 16 * 1024 * 1024
MAX_JSON_BYTES = 64 * 1024 * 1024
MAX_JSON_DEPTH = 64
MAX_JSON_ITEMS = 250_000
MAX_TOTAL_JSON_BYTES = 64 * 1024 * 1024
MAX_TOTAL_JSON_ITEMS = 300_000
MAX_FILESYSTEM_REPLAY_OPERATIONS = 10_000_000
MAX_FILESYSTEM_STATE_ENTRIES = 200_000
MAX_SPDX_TOKENS = 1024
MAX_SPDX_NESTING = 64
MAX_TOML_NESTING = 64
SPDX_LICENSE_LIST_REVISION = "421fbabbe80c94c58c12316af1bc6a2dca2362bc"
SPDX_LICENSE_LIST_VERSION = "3dfd9aa"
SPDX_LICENSE_IDS = frozenset(
    """
0BSD 3D-Slicer-1.0 AAL Abstyles AdaCore-doc Adobe-2006 Adobe-Display-PostScript Adobe-Glyph
Adobe-Utopia ADSL Advanced-Cryptics-Dictionary AFL-1.1 AFL-1.2 AFL-2.0 AFL-2.1 AFL-3.0 Afmparse
AGPL-1.0 AGPL-1.0-only AGPL-1.0-or-later AGPL-3.0 AGPL-3.0-only AGPL-3.0-or-later Aladdin
ALGLIB-Documentation AMD-newlib AMDPLPA AML AML-glslang AMPAS ANTLR-PD ANTLR-PD-fallback any-OSI
any-OSI-perl-modules Apache-1.0 Apache-1.1 Apache-2.0 APAFML APL-1.0 App-s2p APSL-1.0 APSL-1.1
APSL-1.2 APSL-2.0 Arphic-1999 Artistic-1.0 Artistic-1.0-cl8 Artistic-1.0-Perl Artistic-2.0
Artistic-dist Aspell-RU ASWF-Digital-Assets-1.0 ASWF-Digital-Assets-1.1 Baekmuk Bahyph Barr
bcrypt-Solar-Designer Beerware Bitstream-Charter Bitstream-Vera BitTorrent-1.0 BitTorrent-1.1
blessing BlueOak-1.0.0 Boehm-GC Boehm-GC-without-fee BOLA-1.1 Borceux Brian-Gladman-2-Clause
Brian-Gladman-3-Clause Brian-Gladman-3-Clause-no-conversion BSD-1-Clause BSD-2-Clause
BSD-2-Clause-Darwin BSD-2-Clause-first-lines BSD-2-Clause-FreeBSD BSD-2-Clause-NetBSD
BSD-2-Clause-Patent BSD-2-Clause-pkgconf-disclaimer BSD-2-Clause-Views BSD-3-Clause
BSD-3-Clause-acpica BSD-3-Clause-Attribution BSD-3-Clause-Clear BSD-3-Clause-flex
BSD-3-Clause-HP BSD-3-Clause-LBNL BSD-3-Clause-Modification BSD-3-Clause-No-Military-License
BSD-3-Clause-No-Nuclear-License BSD-3-Clause-No-Nuclear-License-2014
BSD-3-Clause-No-Nuclear-Warranty BSD-3-Clause-Open-MPI BSD-3-Clause-Sun BSD-3-Clause-Tso
BSD-4-Clause BSD-4-Clause-Shortened BSD-4-Clause-UC BSD-4.3RENO BSD-4.3TAHOE
BSD-Advertising-Acknowledgement BSD-Attribution-HPND-disclaimer BSD-Inferno-Nettverk
BSD-Mark-Modifications BSD-Protection BSD-Source-beginning-file BSD-Source-Code BSD-Systemics
BSD-Systemics-W3Works BSL-1.0 Buddy BUSL-1.1 bzip2-1.0.5 bzip2-1.0.6 C-UDA-1.0 CAL-1.0
CAL-1.0-Combined-Work-Exception Caldera Caldera-no-preamble CAPEC-tou Catharon CATOSL-1.1
CC-BY-1.0 CC-BY-2.0 CC-BY-2.5 CC-BY-2.5-AU CC-BY-3.0 CC-BY-3.0-AT CC-BY-3.0-AU CC-BY-3.0-DE
CC-BY-3.0-IGO CC-BY-3.0-NL CC-BY-3.0-US CC-BY-4.0 CC-BY-NC-1.0 CC-BY-NC-2.0 CC-BY-NC-2.5
CC-BY-NC-3.0 CC-BY-NC-3.0-DE CC-BY-NC-4.0 CC-BY-NC-ND-1.0 CC-BY-NC-ND-2.0 CC-BY-NC-ND-2.5
CC-BY-NC-ND-3.0 CC-BY-NC-ND-3.0-DE CC-BY-NC-ND-3.0-IGO CC-BY-NC-ND-4.0 CC-BY-NC-SA-1.0
CC-BY-NC-SA-2.0 CC-BY-NC-SA-2.0-DE CC-BY-NC-SA-2.0-FR CC-BY-NC-SA-2.0-UK CC-BY-NC-SA-2.5
CC-BY-NC-SA-3.0 CC-BY-NC-SA-3.0-DE CC-BY-NC-SA-3.0-IGO CC-BY-NC-SA-4.0 CC-BY-ND-1.0 CC-BY-ND-2.0
CC-BY-ND-2.5 CC-BY-ND-3.0 CC-BY-ND-3.0-DE CC-BY-ND-4.0 CC-BY-SA-1.0 CC-BY-SA-2.0 CC-BY-SA-2.0-UK
CC-BY-SA-2.1-JP CC-BY-SA-2.5 CC-BY-SA-3.0 CC-BY-SA-3.0-AT CC-BY-SA-3.0-DE CC-BY-SA-3.0-IGO
CC-BY-SA-4.0 CC-PDDC CC-PDM-1.0 CC-SA-1.0 CC0-1.0 CDDL-1.0 CDDL-1.1 CDL-1.0 CDLA-Permissive-1.0
CDLA-Permissive-2.0 CDLA-Sharing-1.0 CECILL-1.0 CECILL-1.1 CECILL-2.0 CECILL-2.1 CECILL-B
CECILL-C CERN-OHL-1.1 CERN-OHL-1.2 CERN-OHL-P-2.0 CERN-OHL-S-2.0 CERN-OHL-W-2.0 CFITSIO
check-cvs checkmk ClArtistic Clips CMU-Mach CMU-Mach-nodoc CNRI-Jython CNRI-Python
CNRI-Python-GPL-Compatible COIL-1.0 Community-Spec-1.0 Condor-1.1 copyleft-next-0.3.0
copyleft-next-0.3.1 Cornell-Lossless-JPEG CPAL-1.0 CPL-1.0 CPOL-1.02 Cronyx Crossword
CryptoSwift CrystalStacker CUA-OPL-1.0 Cube curl cve-tou D-FSL-1.0 DEC-3-Clause diffmark
DL-DE-BY-2.0 DL-DE-ZERO-2.0 DOC DocBook-DTD DocBook-Schema DocBook-Stylesheet DocBook-XML
Dotseqn DRL-1.0 DRL-1.1 DSDP dtoa dvipdfm ECL-1.0 ECL-2.0 eCos-2.0 EFL-1.0 EFL-2.0 eGenix
Elastic-2.0 Entessa EPICS EPL-1.0 EPL-2.0 ErlPL-1.1 ESA-PL-permissive-2.4
ESA-PL-strong-copyleft-2.4 ESA-PL-weak-copyleft-2.4 etalab-2.0 EUDatagrid EUPL-1.0 EUPL-1.1
EUPL-1.2 Eurosym Fair FBM FDK-AAC Ferguson-Twofish Frameworx-1.0 FreeBSD-DOC FreeImage FSFAP
FSFAP-no-warranty-disclaimer FSFUL FSFULLR FSFULLRSD FSFULLRWD FSL-1.1-ALv2 FSL-1.1-MIT FTL
Furuseth fwlw Game-Programming-Gems GCR-docs GD generic-xts GFDL-1.1 GFDL-1.1-invariants-only
GFDL-1.1-invariants-or-later GFDL-1.1-no-invariants-only GFDL-1.1-no-invariants-or-later
GFDL-1.1-only GFDL-1.1-or-later GFDL-1.2 GFDL-1.2-invariants-only GFDL-1.2-invariants-or-later
GFDL-1.2-no-invariants-only GFDL-1.2-no-invariants-or-later GFDL-1.2-only GFDL-1.2-or-later
GFDL-1.3 GFDL-1.3-invariants-only GFDL-1.3-invariants-or-later GFDL-1.3-no-invariants-only
GFDL-1.3-no-invariants-or-later GFDL-1.3-only GFDL-1.3-or-later Giftware GL2PS Glide Glulxe
GLWTPL gnuplot GPL-1.0 GPL-1.0+ GPL-1.0-only GPL-1.0-or-later GPL-2.0 GPL-2.0+ GPL-2.0-only
GPL-2.0-or-later GPL-2.0-with-autoconf-exception GPL-2.0-with-bison-exception
GPL-2.0-with-classpath-exception GPL-2.0-with-font-exception GPL-2.0-with-GCC-exception GPL-3.0
GPL-3.0+ GPL-3.0-only GPL-3.0-or-later GPL-3.0-with-autoconf-exception
GPL-3.0-with-GCC-exception Graphics-Gems gSOAP-1.3b gtkbook Gutmann HaskellReport HDF5 hdparm
HIDAPI Hippocratic-2.1 HP-1986 HP-1989 HPND HPND-DEC HPND-doc HPND-doc-sell HPND-export-US
HPND-export-US-acknowledgement HPND-export-US-modify HPND-export2-US HPND-Fenneberg-Livingston
HPND-INRIA-IMAG HPND-Intel HPND-Kevlin-Henney HPND-Markus-Kuhn HPND-merchantability-variant
HPND-MIT-disclaimer HPND-Netrek HPND-Pbmplus HPND-sell-MIT-disclaimer-xserver HPND-sell-regexpr
HPND-sell-variant HPND-sell-variant-critical-systems HPND-sell-variant-MIT-disclaimer
HPND-sell-variant-MIT-disclaimer-rev HPND-SMC HPND-UC HPND-UC-export-US HTMLTIDY
hyphen-bulgarian IBM-pibs ICU IEC-Code-Components-EULA IJG IJG-short ImageMagick iMatix Imlib2
Info-ZIP Inner-Net-2.0 InnoSetup Intel Intel-ACPI Interbase-1.0 IPA IPL-1.0 ISC ISC-Veillard
ISO-permission Jam JasPer-2.0 jove JPL-image JPNIC JSON Kastrup Kazlib Knuth-CTAN LAL-1.2
LAL-1.3 Latex2e Latex2e-translated-notice Leptonica LGPL-2.0 LGPL-2.0+ LGPL-2.0-only
LGPL-2.0-or-later LGPL-2.1 LGPL-2.1+ LGPL-2.1-only LGPL-2.1-or-later LGPL-3.0 LGPL-3.0+
LGPL-3.0-only LGPL-3.0-or-later LGPLLR Libpng libpng-1.6.35 libpng-2.0 libselinux-1.0 libtiff
libutil-David-Nugent LiLiQ-P-1.1 LiLiQ-R-1.1 LiLiQ-Rplus-1.1 Linux-man-pages-1-para
Linux-man-pages-copyleft Linux-man-pages-copyleft-2-para Linux-man-pages-copyleft-var
Linux-OpenIB LOOP LPD-document LPL-1.0 LPL-1.02 LPPL-1.0 LPPL-1.1 LPPL-1.2 LPPL-1.3a LPPL-1.3c
lsof Lucida-Bitmap-Fonts LZMA-SDK-9.11-to-9.20 LZMA-SDK-9.22 Mackerras-3-Clause
Mackerras-3-Clause-acknowledgment magaz mailprio MakeIndex man2html Martin-Birgmeier
McPhee-slideshow metamail Minpack MIPS MirOS MIT MIT-0 MIT-advertising MIT-Click MIT-CMU
MIT-enna MIT-feh MIT-Festival MIT-Khronos-old MIT-Modern-Variant MIT-open-group MIT-STK
MIT-testregex MIT-Wu MITNFA MMIXware MMPL-1.0.1 Motosoto MPEG-SSG mpi-permissive mpich2 MPL-1.0
MPL-1.1 MPL-2.0 MPL-2.0-no-copyleft-exception mplus MS-LPL MS-PL MS-RL MTLL MulanPSL-1.0
MulanPSL-2.0 Multics Mup MVT-1.1 NAIST-2003 NASA-1.3 Naumen NBPL-1.0 NCBI-PD NCGL-UK-2.0 NCL
NCSA Net-SNMP NetCDF Newsletr NGPL ngrep NICTA-1.0 NIST-PD NIST-PD-fallback NIST-PD-TNT
NIST-Software NLOD-1.0 NLOD-2.0 NLPL Nokia NOSL Noweb NPL-1.0 NPL-1.1 NPOSL-3.0 NRL NTIA-PD NTP
NTP-0 Nunit O-UDA-1.0 OAR OCCT-PL OCLC-2.0 ODbL-1.0 ODC-By-1.0 OFFIS OFL-1.0 OFL-1.0-no-RFN
OFL-1.0-RFN OFL-1.1 OFL-1.1-no-RFN OFL-1.1-RFN OGC-1.0 OGDL-Taiwan-1.0 OGL-Canada-2.0 OGL-UK-1.0
OGL-UK-2.0 OGL-UK-3.0 OGTSL OLDAP-1.1 OLDAP-1.2 OLDAP-1.3 OLDAP-1.4 OLDAP-2.0 OLDAP-2.0.1
OLDAP-2.1 OLDAP-2.2 OLDAP-2.2.1 OLDAP-2.2.2 OLDAP-2.3 OLDAP-2.4 OLDAP-2.5 OLDAP-2.6 OLDAP-2.7
OLDAP-2.8 OLFL-1.3 OML OpenMDW-1.0 OpenPBS-2.3 OpenSSL OpenSSL-standalone OpenVision OPL-1.0
OPL-UK-3.0 OPUBL-1.0 OSC-1.0 OSET-PL-2.1 OSL-1.0 OSL-1.1 OSL-2.0 OSL-2.1 OSL-3.0 OSSP PADL
ParaType-Free-Font-1.3 Parity-6.0.0 Parity-7.0.0 PDDL-1.0 PHP-3.0 PHP-3.01 Pixar pkgconf Plexus
pnmstitch PolyForm-Noncommercial-1.0.0 PolyForm-Small-Business-1.0.0 PostgreSQL PPL PSF-2.0
psfrag psutils Python-2.0 Python-2.0.1 python-ldap Qhull QPL-1.0 QPL-1.0-INRIA-2004 radvd Rdisc
RHeCos-1.1 RPL-1.1 RPL-1.5 RPSL-1.0 RSA-MD RSCPL Ruby Ruby-pty SAX-PD SAX-PD-2.0 Saxpath SCEA
SchemeReport Sendmail Sendmail-8.23 Sendmail-Open-Source-1.1 SGI-B-1.0 SGI-B-1.1 SGI-B-2.0
SGI-OpenGL SGMLUG-PM SGP4 SHL-0.5 SHL-0.51 SimPL-2.0 SISSL SISSL-1.2 SL Sleepycat SMAIL-GPL
SMLNJ SMPPL SNIA snprintf SOFA softSurfer Soundex Spencer-86 Spencer-94 Spencer-99 SPL-1.0
ssh-keyscan SSH-OpenSSH SSH-short SSLeay-standalone SSPL-1.0 StandardML-NJ SugarCRM-1.1.3
SUL-1.0 Sun-PPP Sun-PPP-2000 SunPro SWL swrule Symlinks TAPR-OHL-1.0 TCL TCP-wrappers TekHVC
TermReadKey TGPPL-1.0 ThirdEye threeparttable TMate TORQUE-1.1 TOSL TPDL TPL-1.0 TrustedQSL TTWL
TTYP0 TU-Berlin-1.0 TU-Berlin-2.0 Ubuntu-font-1.0 UCAR UCL-1.0 ulem UMich-Merit Unicode-3.0
Unicode-DFS-2015 Unicode-DFS-2016 Unicode-TOU UnixCrypt Unlicense Unlicense-libtelnet
Unlicense-libwhirlpool UnRAR UPL-1.0 URT-RLE Vim Vixie-Cron VOSTROM VSL-1.0 W3C W3C-19980720
W3C-20150513 w3m Watcom-1.0 Widget-Workshop WordNet Wsuipa WTFNMFPL WTFPL wwl wxWindows X11
X11-distribute-modifications-variant X11-no-permit-persons X11-swapped Xdebug-1.03 Xerox Xfig
XFree86-1.1 xinetd xkeyboard-config-Zinoviev xlock Xnet xpp XSkat xzoom YPL-1.0 YPL-1.1 Zed
Zeeff Zend-2.0 Zimbra-1.3 Zimbra-1.4 Zlib zlib-acknowledgement ZPL-1.1 ZPL-2.0 ZPL-2.1
""".split()  # noqa: SIM905 - compact frozen upstream identifier data
)
SPDX_EXCEPTION_IDS = frozenset(
    """
389-exception Asterisk-exception Asterisk-linking-protocols-exception Autoconf-exception-2.0
Autoconf-exception-3.0 Autoconf-exception-generic Autoconf-exception-generic-3.0
Autoconf-exception-macro Bison-exception-1.24 Bison-exception-2.2 Bootloader-exception
CGAL-linking-exception Classpath-exception-2.0 Classpath-exception-2.0-short CLISP-exception-2.0
cryptsetup-OpenSSL-exception Digia-Qt-LGPL-exception-1.1 DigiRule-FOSS-exception
eCos-exception-2.0 erlang-otp-linking-exception Fawkes-Runtime-exception FLTK-exception
fmt-exception Font-exception-2.0 freertos-exception-2.0 GCC-exception-2.0 GCC-exception-2.0-note
GCC-exception-3.1 Gmsh-exception GNAT-exception GNOME-examples-exception GNU-compiler-exception
gnu-javamail-exception Google-Patent-WebM GPL-3.0-389-ds-base-exception
GPL-3.0-interface-exception GPL-3.0-linking-exception GPL-3.0-linking-source-exception
GPL-CC-1.0 GStreamer-exception-2005 GStreamer-exception-2008 harbour-exception
i2p-gpl-java-exception Independent-modules-exception KiCad-libraries-exception
kvirc-openssl-exception LGPL-3.0-linking-exception libpri-OpenH323-exception Libtool-exception
Linux-syscall-note LLGPL LLVM-exception LZMA-exception mif-exception mxml-exception
Nokia-Qt-exception-1.1 OCaml-LGPL-linking-exception OCCT-exception-1.0
OpenJDK-assembly-exception-1.0 openvpn-openssl-exception PCRE2-exception polyparse-exception
PS-or-PDF-font-exception-20170817 QPL-1.0-INRIA-2004-exception Qt-GPL-exception-1.0
Qt-LGPL-exception-1.1 Qwt-exception-1.0 romic-exception RRDtool-FLOSS-exception-2.0
rsync-linking-exception SANE-exception SHL-2.0 SHL-2.1 Simple-Library-Usage-exception
sqlitestudio-OpenSSL-exception stunnel-exception SWI-exception Swift-exception Texinfo-exception
u-boot-exception-2.0 UBDL-exception Universal-FOSS-exception-1.0 vsftpd-openssl-exception
WxWindows-exception-3.1 x11vnc-openssl-exception
""".split()  # noqa: SIM905 - compact frozen upstream identifier data
)

READ_BYTES = 1024 * 1024
TAR_BLOCK_BYTES = 512
TAR_RECORD_BYTES = 20 * TAR_BLOCK_BYTES
MAX_TAR_NUMBER = 0o77777777777

GZIP_HEADER = b"\x1f\x8b\x08\x00\x00\x00\x00\x00\x02\xff"
ZERO_BLOCK = bytes(TAR_BLOCK_BYTES)
HEX40 = re.compile(r"^[0-9a-f]{40}$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")
HEX128 = re.compile(r"^[0-9a-f]{128}$")
OCI_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
VERSION = re.compile(r"^(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)$")
WHEELHOUSE_IMAGE = "ghcr.io/stampbot/extra-codeowners-native-wheelhouse"
WHEELHOUSE_SOURCE_REF = "refs/heads/main"
WHEELHOUSE_CERTIFICATE_IDENTITY = (
    "https://github.com/stampbot/extra-codeowners/"
    ".github/workflows/native-wheelhouse.yml@refs/heads/main"
)
WHEELHOUSE_OIDC_ISSUER = "https://token.actions.githubusercontent.com"
WHEELHOUSE_MANIFEST_SCHEMA_VERSION = 2
WHEELHOUSE_STORE_KIND = "extra-codeowners/native-wheelhouse-consumer-store"
WHEELHOUSE_STORE_SCHEMA_VERSION = 1
PACKAGE_URL = re.compile(
    r"^pkg:[a-z][a-z0-9.+-]*/[^\s/?#]+(?:/[^\s/?#]+)*(?:@[^\s/?#]+)?"
    r"(?:\?[^\s#]+)?(?:#[^\s]+)?$"
)
CARGO_CRATES_IO_SOURCE = "registry+https://github.com/rust-lang/crates.io-index"
CARGO_PACKAGE_NAME = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.-]*$")
ALPINE_SHARED_LIBRARY = re.compile(r"^[A-Za-z0-9+_.-]+\.so(?:\.[0-9]+)*$")
CYCLONEDX_COMPONENT_TYPES = {
    "application",
    "container",
    "cryptographic-asset",
    "data",
    "device",
    "device-driver",
    "file",
    "firmware",
    "framework",
    "library",
    "machine-learning-model",
    "operating-system",
    "platform",
}

MANIFEST_FIELDS = {
    "application_artifacts",
    "base_image_index_digest",
    "legal_status",
    "license_records",
    "name",
    "native_component_coverage",
    "native_wheel_artifacts",
    "native_wheelhouse_artifacts",
    "platform",
    "policy_sha256",
    "schema_version",
    "source_completeness",
    "source_records",
    "subject_digest",
    "version",
}
PREDICATE_FIELDS = {
    "artifact",
    "media_type",
    "platform",
    "release_url",
    "schema_version",
    "subject_digest",
}
COVERAGE_FIELDS = {
    "complete",
    "observed_sbom_anomalies",
    "platform",
    "remaining_owner_count",
    "remaining_owner_names",
    "resolved_owners",
    "schema_version",
    "unresolved_owners",
}
POLICY_FIELDS = {
    "alpine_distfiles_release",
    "alpine_recipe_archives",
    "alpine_recipe_exceptions",
    "base_image",
    "base_image_index_digest",
    "base_image_platforms",
    "cpython_source",
    "custom_license_evidence",
    "distribution_approval",
    "docker_python_recipe",
    "filesystem_baselines",
    "license_resolutions",
    "license_texts",
    "native_component_coverage",
    "native_component_sources",
    "native_wheelhouse_contract_sha256",
    "platforms",
    "python_sources",
    "schema_version",
    "unexpanded_python_payloads",
}
COMPONENT_INVENTORY_FIELDS = {
    "apk_database_occurrences",
    "apk_database_sha256",
    "apk_shared_libraries",
    "application_selection_record_sha256",
    "application_wheel_sha256",
    "components",
    "embedded_sboms",
    "image_config_digest",
    "image_revision",
    "image_version",
    "native_payloads",
    "native_wheelhouse_index_digest",
    "native_wheelhouse_revision",
    "native_wheelhouse_schema",
    "platform",
    "python_record_ownership",
    "schema_version",
    "subject_digest",
    "wheel_identity_files",
    "wheel_installations",
}
PLATFORMS = ("linux/amd64", "linux/arm64")
REGULAR_OCCURRENCE_FIELDS = {
    "effective",
    "gid",
    "layer",
    "mode",
    "path",
    "sha256",
    "size",
    "uid",
}
ALL_LAYER_FIELDS = {
    "directories",
    "image_config_digest",
    "layers",
    "non_regular_files",
    "platform",
    "regular_files",
    "schema_version",
    "subject_digest",
    "whiteouts",
}
ALL_LAYER_RECORD_FIELDS = REGULAR_OCCURRENCE_FIELDS | {"layer_digest"}
ALL_LAYER_DIRECTORY_FIELDS = {
    "effective",
    "gid",
    "layer",
    "layer_digest",
    "mode",
    "path",
    "uid",
}
ALL_LAYER_HEADER_FIELDS = {
    "gid",
    "layer",
    "layer_digest",
    "mode",
    "path",
    "uid",
}
LAYER_FIELDS = {
    "digest",
    "directory_count",
    "index",
    "non_regular_file_count",
    "regular_file_count",
    "whiteout_count",
}
PAYLOAD_RECORD_FIELDS = REGULAR_OCCURRENCE_FIELDS
WHEEL_IDENTITY_FILE = re.compile(r"(?:^|/)site-packages/[^/]+\.dist-info/(?:RECORD|WHEEL)$")
DIST_INFO_SBOM = re.compile(r"(?:^|/)site-packages/[^/]+\.dist-info/sboms/.+$")
NATIVE_LIBRARY = re.compile(r"(?:\.so(?:\.[0-9]+)*|\.dylib|\.dll)$", re.IGNORECASE)
WHEEL_TAG = re.compile(r"^[A-Za-z0-9_.]+-[A-Za-z0-9_.]+-[A-Za-z0-9_.]+$")
SCRIPT_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
PYTHON_IDENTIFIER = re.compile(r"^[A-Za-z_]\w*$")
FILESYSTEM_BASELINE_FIELDS = {
    "apk_database_occurrences",
    "post_base_apk_world_occurrences",
    "post_base_directory_effects",
    "post_base_removals",
    "post_base_system_links",
    "post_base_system_regular_occurrences",
}
APK_WORLD_PATH = "etc/apk/world"
POST_BASE_SYSTEM_REGULAR_MODES = {
    "lib/apk/db/scripts.tar.gz": 0o644,
    "lib/apk/db/triggers": 0o644,
    "usr/lib/libgcc_s.so.1": 0o644,
    "usr/lib/libpq.so.5.18": 0o755,
    "var/log/apk.log": 0o644,
}
POST_BASE_SYSTEM_LINK_PATHS = {"usr/lib/libpq.so.5"}
NATIVE_OWNER_FIELDS = {
    "canonical_relationships",
    "cargo_lock",
    "component_reviews",
    "known_omissions",
    "native_payloads",
    "owner",
    "owner_source",
    "payload_dispositions",
    "review",
    "sboms",
    "wheel",
    "wheelhouse_build",
}
REQUIRED_FILES = {
    "MANIFEST.json",
    "SHA256SUMS",
    "THIRD_PARTY_NOTICES.md",
    "inventory/all-layer-files.json",
    "inventory/components.json",
    "inventory/native-component-coverage.json",
    "policy/container-policy.json",
    "policy/native-wheelhouse-consumer.json",
}
REQUIRED_PREFIXES = (
    "artifacts/application/",
    "artifacts/native-wheelhouse/",
    "artifacts/native-wheels/",
    "licenses/from-source/",
    "licenses/standard/",
    "sources/alpine/",
    "sources/application/",
    "sources/base/",
    "sources/cargo-locks/",
    "sources/native-components/",
    "sources/python/",
)


class VerificationError(RuntimeError):
    """The recipient evidence contract was violated."""


@dataclasses.dataclass(frozen=True)
class ExpectedIdentity:
    """Trusted release values that all untrusted evidence must match."""

    version: str
    platform: str
    subject_digest: str
    source_revision: str
    source_date_epoch: int


@dataclasses.dataclass(frozen=True)
class FileIdentity:
    """Metadata used to detect replacement or mutation of an input file."""

    device: int
    inode: int
    mode: int
    links: int
    uid: int
    gid: int
    size: int
    modified_ns: int
    changed_ns: int


@dataclasses.dataclass(frozen=True)
class MemberRecord:
    """One fully consumed regular archive member."""

    path: str
    size: int
    sha256: str
    sha512: str


@dataclasses.dataclass(frozen=True)
class ArchiveResult:
    """Bounded facts returned only after complete gzip and tar verification."""

    sha256: str
    size: int
    member_count: int
    retained_bytes: int
    members: Mapping[str, MemberRecord]


@dataclasses.dataclass
class JsonBudget:
    """Aggregate raw and materialized JSON limits for one untrusted archive."""

    raw_bytes: int = 0
    items: int = 0

    def consume(self, *, raw_bytes: int, items: int, source: str) -> None:
        self.raw_bytes += raw_bytes
        self.items += items
        if self.raw_bytes > MAX_TOTAL_JSON_BYTES:
            raise VerificationError(f"{source} exceeds the aggregate JSON byte budget")
        if self.items > MAX_TOTAL_JSON_ITEMS:
            raise VerificationError(f"{source} exceeds the aggregate JSON value budget")


@dataclasses.dataclass(frozen=True)
class FilesystemReplay:
    """Derived final state and reviewed post-base transitions."""

    effective: Mapping[str, tuple[str, int]]
    directory_effects: tuple[Mapping[str, Any], ...]
    removals: tuple[Mapping[str, Any], ...]


def canonical_json(value: object) -> bytes:
    """Return the one schema-9 JSON encoding, including its final line feed."""

    output = bytearray()
    encoder = json.JSONEncoder(
        allow_nan=False,
        ensure_ascii=False,
        indent=2,
        sort_keys=True,
    )
    try:
        for chunk in encoder.iterencode(value):
            output.extend(chunk.encode("utf-8"))
            if len(output) >= MAX_JSON_BYTES:
                raise VerificationError("canonical JSON exceeds the size limit")
    except (TypeError, ValueError, UnicodeEncodeError) as exc:
        raise VerificationError("value cannot be encoded as canonical JSON") from exc
    output.extend(b"\n")
    return bytes(output)


def require_canonical_json(raw: bytes, value: object, source: str) -> None:
    """Compare canonical JSON incrementally without constructing a second document."""

    encoder = json.JSONEncoder(
        allow_nan=False,
        ensure_ascii=False,
        indent=2,
        sort_keys=True,
    )
    position = 0
    try:
        for chunk in encoder.iterencode(value):
            encoded = chunk.encode("utf-8")
            if raw[position : position + len(encoded)] != encoded:
                raise VerificationError(f"{source} is not in canonical JSON form")
            position += len(encoded)
    except VerificationError:
        raise
    except (TypeError, ValueError, UnicodeEncodeError) as exc:
        raise VerificationError(f"{source} cannot be encoded as canonical JSON") from exc
    if raw[position:] != b"\n":
        raise VerificationError(f"{source} is not in canonical JSON form")


def _reject_constant(value: str) -> NoReturn:
    raise VerificationError(f"JSON contains a non-finite number: {value}")


def _reject_float(value: str) -> NoReturn:
    raise VerificationError(f"JSON contains a floating-point number: {value}")


def _object_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise VerificationError(f"JSON repeats object key: {key!r}")
        result[key] = value
    return result


class _JsonPreflight:
    """Validate JSON grammar and resource bounds without building its object graph."""

    def __init__(self, raw: bytes, source: str) -> None:
        self.raw = raw
        self.source = source
        self.position = 0
        self.items = 0

    def verify(self) -> int:
        self._whitespace()
        self._value(1)
        self._whitespace()
        if self.position != len(self.raw):
            self._invalid()
        return self.items

    def _invalid(self) -> NoReturn:
        raise VerificationError(f"{self.source} is not valid bounded JSON")

    def _item(self, depth: int) -> None:
        self.items += 1
        if self.items > MAX_JSON_ITEMS:
            raise VerificationError(f"{self.source} has too many JSON values")
        if depth > MAX_JSON_DEPTH:
            raise VerificationError(f"{self.source} exceeds the JSON depth limit")

    def _whitespace(self) -> None:
        while self.position < len(self.raw) and self.raw[self.position] in b" \t\r\n":
            self.position += 1

    def _value(self, depth: int) -> None:
        self._item(depth)
        if self.position >= len(self.raw):
            self._invalid()
        marker = self.raw[self.position]
        if marker == ord("{"):
            self._object(depth)
        elif marker == ord("["):
            self._array(depth)
        elif marker == ord('"'):
            self._string()
        elif (
            self.raw.startswith(b"NaN", self.position)
            or self.raw.startswith(b"Infinity", self.position)
            or self.raw.startswith(b"-Infinity", self.position)
        ):
            raise VerificationError(f"{self.source} contains a non-finite number")
        elif marker == ord("-") or ord("0") <= marker <= ord("9"):
            self._number()
        elif self.raw.startswith(b"true", self.position):
            self.position += 4
        elif self.raw.startswith(b"false", self.position):
            self.position += 5
        elif self.raw.startswith(b"null", self.position):
            self.position += 4
        else:
            self._invalid()

    def _object(self, depth: int) -> None:
        self.position += 1
        self._whitespace()
        if self.position < len(self.raw) and self.raw[self.position] == ord("}"):
            self.position += 1
            return
        while True:
            if self.position >= len(self.raw) or self.raw[self.position] != ord('"'):
                self._invalid()
            # Count keys too. json.loads creates a string and an object-pair
            # tuple for each one before object_pairs_hook can reject it.
            self._item(depth + 1)
            self._string()
            self._whitespace()
            if self.position >= len(self.raw) or self.raw[self.position] != ord(":"):
                self._invalid()
            self.position += 1
            self._whitespace()
            self._value(depth + 1)
            self._whitespace()
            if self.position >= len(self.raw):
                self._invalid()
            marker = self.raw[self.position]
            self.position += 1
            if marker == ord("}"):
                return
            if marker != ord(","):
                self._invalid()
            self._whitespace()

    def _array(self, depth: int) -> None:
        self.position += 1
        self._whitespace()
        if self.position < len(self.raw) and self.raw[self.position] == ord("]"):
            self.position += 1
            return
        while True:
            self._value(depth + 1)
            self._whitespace()
            if self.position >= len(self.raw):
                self._invalid()
            marker = self.raw[self.position]
            self.position += 1
            if marker == ord("]"):
                return
            if marker != ord(","):
                self._invalid()
            self._whitespace()

    def _string(self) -> None:
        self.position += 1
        while self.position < len(self.raw):
            marker = self.raw[self.position]
            self.position += 1
            if marker == ord('"'):
                return
            if marker < 0x20:
                self._invalid()
            if marker != ord("\\"):
                continue
            if self.position >= len(self.raw):
                self._invalid()
            escape = self.raw[self.position]
            self.position += 1
            if escape in b'"\\/bfnrt':
                continue
            if escape != ord("u") or self.position + 4 > len(self.raw):
                self._invalid()
            digits = self.raw[self.position : self.position + 4]
            if any(
                not (
                    ord("0") <= digit <= ord("9")
                    or ord("a") <= digit <= ord("f")
                    or ord("A") <= digit <= ord("F")
                )
                for digit in digits
            ):
                self._invalid()
            self.position += 4
        self._invalid()

    def _number(self) -> None:
        if self.raw[self.position] == ord("-"):
            self.position += 1
            if self.position >= len(self.raw):
                self._invalid()
        if self.raw[self.position] == ord("0"):
            self.position += 1
            if self.position < len(self.raw) and ord("0") <= self.raw[self.position] <= ord("9"):
                self._invalid()
        elif ord("1") <= self.raw[self.position] <= ord("9"):
            self.position += 1
            while self.position < len(self.raw) and ord("0") <= self.raw[self.position] <= ord("9"):
                self.position += 1
        else:
            self._invalid()
        if self.position < len(self.raw) and self.raw[self.position] in b".eE":
            raise VerificationError(f"{self.source} contains a floating-point number")


def strict_json_value_bytes(
    raw: bytes,
    source: str,
    *,
    budget: JsonBudget | None = None,
) -> Any:
    """Parse one canonical, bounded JSON value without materializing it first."""

    if not 0 < len(raw) <= MAX_JSON_BYTES:
        raise VerificationError(f"{source} has an invalid size")
    item_count = _JsonPreflight(raw, source).verify()
    if budget is not None:
        budget.consume(raw_bytes=len(raw), items=item_count, source=source)
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise VerificationError(f"{source} is not UTF-8") from exc
    try:
        value = json.loads(
            text,
            object_pairs_hook=_object_pairs,
            parse_constant=_reject_constant,
            parse_float=_reject_float,
        )
    except VerificationError:
        raise
    except (ValueError, RecursionError) as exc:
        raise VerificationError(f"{source} is not valid bounded JSON") from exc

    count = 0
    stack: list[tuple[Any, int]] = [(value, 1)]
    while stack:
        item, depth = stack.pop()
        count += 1
        if count > MAX_JSON_ITEMS:
            raise VerificationError(f"{source} has too many JSON values")
        if depth > MAX_JSON_DEPTH:
            raise VerificationError(f"{source} exceeds the JSON depth limit")
        if isinstance(item, str):
            try:
                item.encode("utf-8")
            except UnicodeEncodeError as exc:
                raise VerificationError(f"{source} contains invalid Unicode") from exc
        elif isinstance(item, dict):
            stack.extend((child, depth + 1) for child in item.values())
        elif isinstance(item, list):
            stack.extend((child, depth + 1) for child in item)
        elif isinstance(item, float):
            raise VerificationError(f"{source} contains a floating-point number")
    require_canonical_json(raw, value, source)
    return value


def strict_json_bytes(
    raw: bytes,
    source: str,
    *,
    budget: JsonBudget | None = None,
) -> Mapping[str, Any]:
    """Parse one canonical, bounded JSON object."""

    value = strict_json_value_bytes(raw, source, budget=budget)
    if not isinstance(value, dict):
        raise VerificationError(f"{source} must be a JSON object")
    return value


def _exact_mapping(value: object, fields: set[str], source: str) -> Mapping[str, Any]:
    if not isinstance(value, dict) or set(value) != fields:
        raise VerificationError(f"{source} must contain exactly {sorted(fields)}")
    return value


def _integer(value: object, source: str, *, minimum: int, maximum: int) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or not minimum <= value <= maximum:
        raise VerificationError(f"{source} is outside its integer bounds")
    return value


def _boolean(value: object, source: str) -> bool:
    if not isinstance(value, bool):
        raise VerificationError(f"{source} must be a boolean")
    return value


def _bounded_text(value: object, source: str, *, maximum: int = 4096) -> str:
    if not isinstance(value, str) or not value or len(value.encode("utf-8")) > maximum:
        raise VerificationError(f"{source} is invalid")
    if any(ord(character) < 32 or 0x7F <= ord(character) <= 0x9F for character in value):
        raise VerificationError(f"{source} contains control characters")
    return value


def _bounded_optional_text(value: object, source: str, *, maximum: int = 4096) -> str:
    if not isinstance(value, str) or len(value.encode("utf-8")) > maximum:
        raise VerificationError(f"{source} is invalid")
    if any(ord(character) < 32 or 0x7F <= ord(character) <= 0x9F for character in value):
        raise VerificationError(f"{source} contains control characters")
    return value


def _preflight_toml_nesting(document: str, source: str) -> None:
    """Bound TOML array and inline-table nesting without counting quoted text."""

    stack: list[str] = []
    position = 0
    state = "normal"
    while position < len(document):
        character = document[position]
        if state == "comment":
            if character == "\n":
                state = "normal"
            position += 1
            continue
        if state == "basic":
            if character == "\\":
                position += 2
            else:
                if character == '"':
                    state = "normal"
                position += 1
            continue
        if state == "literal":
            if character == "'":
                state = "normal"
            position += 1
            continue
        if state in {"multiline-basic", "multiline-literal"}:
            quote = '"' if state == "multiline-basic" else "'"
            if character == quote:
                end = position
                while end < len(document) and document[end] == quote:
                    end += 1
                if end - position >= 3:
                    state = "normal"
                position = end
            elif state == "multiline-basic" and character == "\\":
                position += 2
            else:
                position += 1
            continue
        if character == "#":
            state = "comment"
            position += 1
            continue
        if document.startswith('"""', position):
            state = "multiline-basic"
            position += 3
            continue
        if document.startswith("'''", position):
            state = "multiline-literal"
            position += 3
            continue
        if character == '"':
            state = "basic"
            position += 1
            continue
        if character == "'":
            state = "literal"
            position += 1
            continue
        if character in "[{":
            stack.append(character)
            if len(stack) > MAX_TOML_NESTING:
                raise VerificationError(f"{source} exceeds its TOML nesting limit")
        elif character in "]}":
            expected = "[" if character == "]" else "{"
            if not stack or stack[-1] != expected:
                raise VerificationError(f"{source} has mismatched TOML delimiters")
            stack.pop()
        position += 1


def _validate_toml_shape(value: object, source: str) -> None:
    stack: list[tuple[object, int]] = [(value, 1)]
    items = 0
    while stack:
        item, depth = stack.pop()
        items += 1
        if depth > MAX_TOML_NESTING:
            raise VerificationError(f"{source} exceeds its TOML nesting limit")
        if items > MAX_JSON_ITEMS:
            raise VerificationError(f"{source} exceeds its TOML value limit")
        if isinstance(item, dict):
            stack.extend((child, depth + 1) for child in item.values())
        elif isinstance(item, list):
            stack.extend((child, depth + 1) for child in item)


def _strict_toml_bytes(raw: bytes, source: str, *, maximum: int) -> Mapping[str, Any]:
    """Parse one size- and nesting-bounded TOML document."""

    if not 0 < len(raw) <= maximum:
        raise VerificationError(f"{source} has an invalid size")
    try:
        document = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise VerificationError(f"{source} is not valid UTF-8 TOML") from exc
    _preflight_toml_nesting(document, source)
    try:
        parsed = tomllib.loads(document)
    except (RecursionError, tomllib.TOMLDecodeError) as exc:
        raise VerificationError(f"{source} is invalid") from exc
    if not isinstance(parsed, dict):
        raise VerificationError(f"{source} is not a TOML table")
    _validate_toml_shape(parsed, source)
    return parsed


class _SpdxExpressionParser:
    """Parse the SPDX expression grammar used by reviewed policy."""

    def __init__(self, expression: str, source: str) -> None:
        self.expression = expression
        self.source = source
        self.tokens = re.findall(r"\(|\)|[^\s()]+", expression)
        self.position = 0
        self.nesting = 0

    def parse(self) -> tuple[Any, ...]:
        if not self.tokens or len(self.tokens) > MAX_SPDX_TOKENS:
            self._invalid()
        result = self._or_expression()
        if self.position != len(self.tokens):
            self._invalid()
        return result

    def _invalid(self) -> NoReturn:
        raise VerificationError(f"{self.source} is not a valid canonical SPDX expression")

    def _peek(self) -> str | None:
        return self.tokens[self.position] if self.position < len(self.tokens) else None

    def _take(self, token: str) -> bool:
        if self._peek() != token:
            return False
        self.position += 1
        return True

    def _or_expression(self) -> tuple[Any, ...]:
        result = self._and_expression()
        while self._take("OR"):
            result = ("OR", result, self._and_expression())
        return result

    def _and_expression(self) -> tuple[Any, ...]:
        result = self._with_expression()
        while self._take("AND"):
            result = ("AND", result, self._with_expression())
        return result

    def _with_expression(self) -> tuple[Any, ...]:
        result = self._primary()
        if not self._take("WITH"):
            return result
        if result[0] != "license":
            self._invalid()
        exception = self._peek()
        if (
            exception is None
            or exception in {"AND", "OR", "WITH", "(", ")"}
            or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.-]*", exception) is None
            or exception not in SPDX_EXCEPTION_IDS
        ):
            self._invalid()
        self.position += 1
        return ("WITH", result, exception)

    def _primary(self) -> tuple[Any, ...]:
        if self._take("("):
            self.nesting += 1
            if self.nesting > MAX_SPDX_NESTING:
                self._invalid()
            try:
                result = self._or_expression()
                if not self._take(")"):
                    self._invalid()
                return result
            finally:
                self.nesting -= 1
        token = self._peek()
        if token is None or token in {"AND", "OR", "WITH", "(", ")"}:
            self._invalid()
        reference = re.fullmatch(
            r"(?:(?:DocumentRef-[A-Za-z0-9.-]+):)?"
            r"LicenseRef-[A-Za-z0-9.-]+",
            token,
        )
        if reference is not None:
            self.position += 1
            return ("license-ref", token)
        if token.startswith(("DocumentRef-", "LicenseRef-")):
            self._invalid()
        license_id = re.fullmatch(r"([A-Za-z0-9][A-Za-z0-9.-]*)(\+)?", token)
        if license_id is None or (
            license_id.group(1) not in SPDX_LICENSE_IDS and token not in SPDX_LICENSE_IDS
        ):
            self._invalid()
        self.position += 1
        return ("license", license_id.group(1), license_id.group(2) is not None)


def _render_spdx_expression(node: tuple[Any, ...], parent_precedence: int = 0) -> str:
    kind = str(node[0])
    if kind == "license":
        return f"{node[1]}{'+' if node[2] else ''}"
    if kind == "license-ref":
        return str(node[1])
    if kind == "WITH":
        return f"{_render_spdx_expression(node[1], 3)} WITH {node[2]}"
    precedence = {"OR": 1, "AND": 2}.get(kind)
    if precedence is None:
        raise VerificationError("internal SPDX expression node is invalid")
    rendered = (
        f"{_render_spdx_expression(node[1], precedence)} {kind} "
        f"{_render_spdx_expression(node[2], precedence)}"
    )
    return f"({rendered})" if precedence < parent_precedence else rendered


def _validate_spdx_expression(
    value: object,
    source: str,
) -> tuple[set[str], set[str]]:
    expression = _bounded_text(value, source, maximum=16 * 1024)
    try:
        parsed = _SpdxExpressionParser(expression, source).parse()
        rendered = _render_spdx_expression(parsed)
    except RecursionError as exc:  # defense in depth around recursive grammar descent
        raise VerificationError(f"{source} is not a valid canonical SPDX expression") from exc
    if rendered != expression:
        raise VerificationError(f"{source} is not a valid canonical SPDX expression")
    identifiers: set[str] = set()
    references: set[str] = set()
    stack = [parsed]
    while stack:
        node = stack.pop()
        kind = str(node[0])
        if kind == "license":
            identifiers.add(str(node[1]))
        elif kind == "license-ref":
            references.add(str(node[1]))
        elif kind == "WITH":
            identifiers.add(str(node[2]))
            stack.append(node[1])
        else:
            stack.extend((node[1], node[2]))
    return identifiers, references


def _digest(value: object, source: str) -> str:
    if not isinstance(value, str) or HEX64.fullmatch(value) is None:
        raise VerificationError(f"{source} is not a lowercase SHA-256")
    return value


def _oci_digest(value: object, source: str) -> str:
    if not isinstance(value, str) or OCI_DIGEST.fullmatch(value) is None:
        raise VerificationError(f"{source} is not a lowercase OCI SHA-256 digest")
    return value


def validate_expected_identity(expected: ExpectedIdentity) -> None:
    """Reject malformed trusted arguments before comparing untrusted data."""

    if VERSION.fullmatch(expected.version) is None:
        raise VerificationError("expected version is not a canonical semantic version")
    if expected.platform not in {"linux/amd64", "linux/arm64"}:
        raise VerificationError("expected platform is unsupported")
    _oci_digest(expected.subject_digest, "expected platform manifest digest")
    if HEX40.fullmatch(expected.source_revision) is None:
        raise VerificationError("expected source revision is not a lowercase Git SHA-1")
    _integer(
        expected.source_date_epoch,
        "expected source timestamp",
        minimum=0,
        maximum=MAX_TAR_NUMBER,
    )


def expected_archive_filename(expected: ExpectedIdentity) -> str:
    architecture = expected.platform.removeprefix("linux/")
    return f"extra-codeowners-{expected.version}-linux-{architecture}-evidence.tar.gz"


def _identity(metadata: os.stat_result, source: str, *, maximum: int) -> FileIdentity:
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
        or not 0 < metadata.st_size <= maximum
    ):
        raise VerificationError(f"{source} must be one bounded, single-link regular file")
    return FileIdentity(
        device=metadata.st_dev,
        inode=metadata.st_ino,
        mode=metadata.st_mode,
        links=metadata.st_nlink,
        uid=metadata.st_uid,
        gid=metadata.st_gid,
        size=metadata.st_size,
        modified_ns=metadata.st_mtime_ns,
        changed_ns=metadata.st_ctime_ns,
    )


def open_real_directory(path: Path, source: str) -> int:
    """Open an absolute directory chain without traversing a symbolic link."""

    if not hasattr(os, "O_NOFOLLOW") or not hasattr(os, "O_DIRECTORY"):
        raise VerificationError("verification requires no-follow directory support")
    absolute = Path(os.path.abspath(path))
    descriptor = -1
    try:
        descriptor = os.open(
            "/",
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0),
        )
        for part in absolute.parts[1:]:
            following = os.open(
                part,
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0),
                dir_fd=descriptor,
            )
            metadata = os.fstat(following)
            if not stat.S_ISDIR(metadata.st_mode):
                os.close(following)
                raise VerificationError(f"{source} contains a non-directory component")
            os.close(descriptor)
            descriptor = following
        return descriptor
    except VerificationError:
        if descriptor >= 0:
            with contextlib.suppress(OSError):
                os.close(descriptor)
        raise
    except OSError as exc:
        if descriptor >= 0:
            with contextlib.suppress(OSError):
                os.close(descriptor)
        raise VerificationError(f"{source} contains an unsafe directory component") from exc


@contextlib.contextmanager
def open_stable_input(
    path: Path, source: str, *, maximum: int
) -> Iterator[tuple[int, FileIdentity]]:
    """Open one no-follow input and prove its path identity stays stable."""

    if not hasattr(os, "O_NOFOLLOW") or not hasattr(os, "pread"):
        raise VerificationError("verification requires no-follow descriptor support")
    absolute = Path(os.path.abspath(path))
    parent_descriptor = -1
    descriptor = -1
    try:
        parent_descriptor = open_real_directory(absolute.parent, f"{source} parent")
        before = _identity(
            os.stat(absolute.name, dir_fd=parent_descriptor, follow_symlinks=False),
            source,
            maximum=maximum,
        )
        descriptor = os.open(
            absolute.name,
            os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0),
            dir_fd=parent_descriptor,
        )
        opened = _identity(os.fstat(descriptor), source, maximum=maximum)
        if opened != before:
            raise VerificationError(f"{source} changed while it was opened")
        yield descriptor, opened
        after_open = _identity(os.fstat(descriptor), source, maximum=maximum)
        after_path = _identity(
            os.stat(absolute.name, dir_fd=parent_descriptor, follow_symlinks=False),
            source,
            maximum=maximum,
        )
        if opened != after_open or opened != after_path:
            raise VerificationError(f"{source} changed while it was verified")
    except VerificationError:
        raise
    except OSError as exc:
        raise VerificationError(f"cannot open {source} safely") from exc
    finally:
        if descriptor >= 0:
            with contextlib.suppress(OSError):
                os.close(descriptor)
        if parent_descriptor >= 0:
            with contextlib.suppress(OSError):
                os.close(parent_descriptor)


def read_stable_input(path: Path, source: str, *, maximum: int) -> bytes:
    """Read one stable bounded input without following its final path."""

    with open_stable_input(path, source, maximum=maximum) as (descriptor, identity):
        try:
            content = os.pread(descriptor, identity.size + 1, 0)
        except OSError as exc:
            raise VerificationError(f"cannot read {source} safely") from exc
        if len(content) != identity.size:
            raise VerificationError(f"{source} changed size while it was read")
        return content


class _RawReader:
    """Hash and bound every byte read from an already-open descriptor."""

    def __init__(self, descriptor: int, size: int) -> None:
        self._descriptor = descriptor
        self._size = size
        self._read = 0
        self._digest = hashlib.sha256()

    @property
    def sha256(self) -> str:
        return self._digest.hexdigest()

    def read(self, maximum: int) -> bytes:
        if self._read >= self._size:
            return b""
        try:
            chunk = os.read(self._descriptor, min(maximum, self._size - self._read))
        except OSError as exc:
            raise VerificationError("cannot read the evidence archive safely") from exc
        if not chunk:
            raise VerificationError("evidence archive ended before its recorded size")
        self._read += len(chunk)
        self._digest.update(chunk)
        return chunk

    def read_exact(self, size: int) -> bytes:
        chunks: list[bytes] = []
        remaining = size
        while remaining:
            chunk = self.read(remaining)
            if not chunk:
                raise VerificationError("evidence archive is truncated")
            chunks.append(chunk)
            remaining -= len(chunk)
        return b"".join(chunks)


def decompressed_gzip_chunks(descriptor: int, size: int) -> Iterator[bytes | tuple[str, str]]:
    """Yield one exact deterministic gzip member and finally its raw SHA-256."""

    raw = _RawReader(descriptor, size)
    if raw.read_exact(len(GZIP_HEADER)) != GZIP_HEADER:
        raise VerificationError("evidence archive has a noncanonical gzip header")
    decompressor = zlib.decompressobj(wbits=-zlib.MAX_WBITS)
    expanded = 0
    crc32 = 0
    unused = b""
    while True:
        compressed = raw.read(READ_BYTES)
        if not compressed:
            raise VerificationError("evidence archive has a truncated deflate stream")
        pending = compressed
        while pending and not decompressor.eof:
            try:
                output = decompressor.decompress(pending, READ_BYTES)
            except zlib.error as exc:
                raise VerificationError("evidence archive has an invalid deflate stream") from exc
            pending = decompressor.unconsumed_tail
            if output:
                expanded += len(output)
                if expanded > MAX_EXPANDED_TAR_BYTES:
                    raise VerificationError("evidence archive exceeds the expansion limit")
                crc32 = zlib.crc32(output, crc32)
                yield output
        if decompressor.eof:
            unused = decompressor.unused_data
            break
    try:
        flushed = decompressor.flush()
    except zlib.error as exc:
        raise VerificationError("evidence archive cannot finish its deflate stream") from exc
    if flushed:
        expanded += len(flushed)
        if expanded > MAX_EXPANDED_TAR_BYTES:
            raise VerificationError("evidence archive exceeds the expansion limit")
        crc32 = zlib.crc32(flushed, crc32)
        yield flushed

    trailer = bytearray(unused)
    while len(trailer) < 8:
        chunk = raw.read(8 - len(trailer))
        if not chunk:
            break
        trailer.extend(chunk)
    if len(trailer) < 8:
        raise VerificationError("evidence archive has a truncated gzip trailer")
    if len(trailer) > 8:
        raise VerificationError("evidence archive has bytes after its gzip member")
    if raw.read(1):
        raise VerificationError("evidence archive has bytes after its gzip member")
    recorded_crc, recorded_size = struct.unpack("<II", trailer)
    if recorded_crc != crc32 or recorded_size != expanded % (2**32):
        raise VerificationError("evidence archive gzip trailer does not match its payload")
    yield ("sha256", raw.sha256)


class _ChunkReader:
    """Present bounded decompressor output as exact reads without whole-file buffering."""

    def __init__(self, chunks: Iterator[bytes | tuple[str, str]]) -> None:
        self._chunks = chunks
        self._pending = b""
        self._final_sha256: str | None = None
        self.consumed = 0

    @property
    def final_sha256(self) -> str:
        if self._final_sha256 is None:
            raise VerificationError("gzip stream did not reach its verified end")
        return self._final_sha256

    def _next(self) -> bytes:
        try:
            value = next(self._chunks)
        except StopIteration:
            return b""
        if isinstance(value, tuple):
            if value[0] != "sha256" or self._final_sha256 is not None:
                raise VerificationError("gzip verifier returned invalid terminal state")
            self._final_sha256 = value[1]
            return b""
        return value

    def iter_exact(self, size: int) -> Iterator[bytes]:
        remaining = size
        while remaining:
            if not self._pending:
                self._pending = self._next()
                if not self._pending:
                    raise VerificationError("tar stream ended before a complete record")
            selected = self._pending[:remaining]
            self._pending = self._pending[len(selected) :]
            self.consumed += len(selected)
            remaining -= len(selected)
            yield selected

    def read_exact(self, size: int) -> bytes:
        return b"".join(self.iter_exact(size))

    def require_end(self) -> None:
        if self._pending:
            raise VerificationError("tar stream has trailing decompressed bytes")
        while True:
            value = self._next()
            if value:
                raise VerificationError("tar stream has trailing decompressed bytes")
            if self._final_sha256 is not None:
                break
            raise VerificationError("gzip stream ended without a verification result")
        try:
            next(self._chunks)
        except StopIteration:
            return
        raise VerificationError("gzip verifier returned data after its terminal state")


class ExtractionRoot:
    """An exclusive output directory with descriptor-relative file operations."""

    def __init__(self, output: Path) -> None:
        self.path = Path(os.path.abspath(output))
        self._parent_descriptor = -1
        self._root_descriptor = -1
        self._root_identity: tuple[int, int] | None = None
        self._committed = False

    def __enter__(self) -> ExtractionRoot:
        if (
            not hasattr(os, "O_NOFOLLOW")
            or not hasattr(os, "O_DIRECTORY")
            or not shutil.rmtree.avoids_symlink_attacks
        ):
            raise VerificationError("materialization requires no-follow directory support")
        parent = self.path.parent
        created = False
        try:
            self._parent_descriptor = open_real_directory(parent, "output parent")
            os.mkdir(self.path.name, 0o700, dir_fd=self._parent_descriptor)
            created = True
            self._root_descriptor = os.open(
                self.path.name,
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0),
                dir_fd=self._parent_descriptor,
            )
            metadata = os.fstat(self._root_descriptor)
            if not stat.S_ISDIR(metadata.st_mode):
                raise VerificationError("created output is not a directory")
            self._root_identity = (metadata.st_dev, metadata.st_ino)
            self._require_root_identity()
        except FileExistsError as exc:
            self._close_parent_descriptor()
            raise VerificationError("output directory already exists") from exc
        except VerificationError:
            self._abort_enter(created)
            raise
        except OSError as exc:
            try:
                self._abort_enter(created)
            except VerificationError as cleanup_error:
                raise cleanup_error from exc
            raise VerificationError("cannot create the output directory safely") from exc
        return self

    def _close_root_descriptor(self) -> None:
        if self._root_descriptor >= 0:
            with contextlib.suppress(OSError):
                os.close(self._root_descriptor)
            self._root_descriptor = -1

    def _close_parent_descriptor(self) -> None:
        if self._parent_descriptor >= 0:
            with contextlib.suppress(OSError):
                os.close(self._parent_descriptor)
            self._parent_descriptor = -1

    def _abort_enter(self, created: bool) -> None:
        self._close_root_descriptor()
        try:
            if created and self._parent_descriptor >= 0:
                self._remove_uncommitted()
        finally:
            self._close_parent_descriptor()

    def _remove_uncommitted(self) -> None:
        try:
            metadata = os.stat(
                self.path.name,
                dir_fd=self._parent_descriptor,
                follow_symlinks=False,
            )
        except FileNotFoundError:
            return
        except OSError as exc:
            raise VerificationError("cannot inspect incomplete output safely") from exc
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or stat.S_ISLNK(metadata.st_mode)
            or self._root_identity is None
            or (metadata.st_dev, metadata.st_ino) != self._root_identity
        ):
            raise VerificationError("incomplete output was replaced before cleanup")
        try:
            shutil.rmtree(self.path.name, dir_fd=self._parent_descriptor)
        except OSError as exc:
            raise VerificationError("cannot remove incomplete output safely") from exc

    def _require_root_identity(self) -> None:
        if self._root_descriptor < 0 or self._parent_descriptor < 0 or self._root_identity is None:
            raise VerificationError("output directory has no stable identity")
        try:
            opened = os.fstat(self._root_descriptor)
            named = os.stat(
                self.path.name,
                dir_fd=self._parent_descriptor,
                follow_symlinks=False,
            )
        except OSError as exc:
            raise VerificationError("output directory changed during verification") from exc
        if (
            not stat.S_ISDIR(opened.st_mode)
            or not stat.S_ISDIR(named.st_mode)
            or (opened.st_dev, opened.st_ino) != self._root_identity
            or (named.st_dev, named.st_ino) != self._root_identity
        ):
            raise VerificationError("output directory changed during verification")

    def _open_parent(self, path: PurePosixPath, *, create: bool) -> tuple[int, str]:
        current = os.dup(self._root_descriptor)
        try:
            for part in path.parts[:-1]:
                if create:
                    with contextlib.suppress(FileExistsError):
                        os.mkdir(part, 0o700, dir_fd=current)
                following = os.open(
                    part,
                    os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0),
                    dir_fd=current,
                )
                os.close(current)
                current = following
            return current, path.parts[-1]
        except OSError as exc:
            with contextlib.suppress(OSError):
                os.close(current)
            raise VerificationError(f"cannot traverse materialized path safely: {path}") from exc

    def write(
        self, path: PurePosixPath, content: Iterator[bytes], expected_size: int
    ) -> MemberRecord:
        parent, name = self._open_parent(path, create=True)
        descriptor = -1
        sha256 = hashlib.sha256()
        sha512 = hashlib.sha512()
        written = 0
        try:
            descriptor = os.open(
                name,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0),
                0o600,
                dir_fd=parent,
            )
            for chunk in content:
                view = memoryview(chunk)
                while view:
                    count = os.write(descriptor, view)
                    if count <= 0:
                        raise VerificationError(f"cannot materialize archive member: {path}")
                    view = view[count:]
                written += len(chunk)
                sha256.update(chunk)
                sha512.update(chunk)
            if written != expected_size:
                raise VerificationError(f"archive member changed size while materialized: {path}")
            os.fsync(descriptor)
        except VerificationError:
            raise
        except OSError as exc:
            raise VerificationError(f"cannot materialize archive member safely: {path}") from exc
        finally:
            if descriptor >= 0:
                with contextlib.suppress(OSError):
                    os.close(descriptor)
            os.close(parent)
        return MemberRecord(
            path=str(path),
            size=written,
            sha256=sha256.hexdigest(),
            sha512=sha512.hexdigest(),
        )

    def read(self, path: str, *, maximum: int) -> bytes:
        checked = checked_path(path)
        parent, name = self._open_parent(checked, create=False)
        descriptor = -1
        try:
            descriptor = os.open(
                name,
                os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0),
                dir_fd=parent,
            )
            metadata = os.fstat(descriptor)
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_nlink != 1
                or not 0 < metadata.st_size <= maximum
            ):
                raise VerificationError(f"materialized member is not bounded and regular: {path}")
            chunks: list[bytes] = []
            remaining = metadata.st_size
            while remaining:
                chunk = os.read(descriptor, min(READ_BYTES, remaining))
                if not chunk:
                    raise VerificationError(f"materialized member changed while read: {path}")
                chunks.append(chunk)
                remaining -= len(chunk)
            content = b"".join(chunks)
            if len(content) != metadata.st_size:
                raise VerificationError(f"materialized member changed while read: {path}")
            return content
        except VerificationError:
            raise
        except OSError as exc:
            raise VerificationError(f"cannot read materialized member safely: {path}") from exc
        finally:
            if descriptor >= 0:
                with contextlib.suppress(OSError):
                    os.close(descriptor)
            os.close(parent)

    def commit(self) -> None:
        self._require_root_identity()
        self._committed = True

    def __exit__(self, _type: object, _value: object, _traceback: object) -> None:
        self._close_root_descriptor()
        try:
            if not self._committed and self._parent_descriptor >= 0:
                self._remove_uncommitted()
        finally:
            self._close_parent_descriptor()


def checked_path(value: str) -> PurePosixPath:
    """Return one canonical relative POSIX file path."""

    try:
        encoded = value.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise VerificationError(f"archive path is not valid UTF-8: {value!r}") from exc
    if (
        not encoded
        or value in {".", ".."}
        or len(encoded) > MAX_PATH_BYTES
        or "\\" in value
        or any(ord(character) < 32 or 0x7F <= ord(character) <= 0x9F for character in value)
    ):
        raise VerificationError(f"archive path is unsafe: {value!r}")
    path = PurePosixPath(value)
    if (
        path.is_absolute()
        or path.as_posix() != value
        or any(part in {"", ".", ".."} for part in path.parts)
    ):
        raise VerificationError(f"archive path is not canonical: {value!r}")
    if len(path.parts) > MAX_PATH_DEPTH:
        raise VerificationError(f"archive path exceeds the component-depth limit: {value!r}")
    return path


def _octal(value: int, width: int) -> bytes:
    if not 0 <= value <= int("7" * (width - 1), 8):
        raise VerificationError("tar numeric field exceeds its canonical range")
    return f"{value:0{width - 1}o}\0".encode("ascii")


def _parse_octal(field: bytes, source: str) -> int:
    if len(field) < 2 or field[-1:] != b"\0" or any(byte not in b"01234567" for byte in field[:-1]):
        raise VerificationError(f"{source} is not a canonical tar octal field")
    return int(field[:-1], 8)


def _header(
    *,
    name: bytes,
    mode: int,
    size: int,
    mtime: int,
    typeflag: bytes,
    uname: bytes,
    gname: bytes,
) -> bytes:
    if len(name) > 100 or len(typeflag) != 1 or len(uname) > 32 or len(gname) > 32:
        raise VerificationError("tar header value exceeds its canonical field")
    header = bytearray(TAR_BLOCK_BYTES)
    header[0 : len(name)] = name
    header[100:108] = _octal(mode, 8)
    header[108:116] = _octal(0, 8)
    header[116:124] = _octal(0, 8)
    header[124:136] = _octal(size, 12)
    header[136:148] = _octal(mtime, 12)
    header[148:156] = b"        "
    header[156:157] = typeflag
    header[257:263] = b"ustar\0"
    header[263:265] = b"00"
    header[265 : 265 + len(uname)] = uname
    header[297 : 297 + len(gname)] = gname
    checksum = sum(header)
    if checksum > 0o777777:
        raise VerificationError("tar header checksum exceeds its canonical range")
    header[148:156] = f"{checksum:06o}\0 ".encode("ascii")
    return bytes(header)


def _canonical_pax_payload(path: str) -> bytes:
    body = b" path=" + path.encode("utf-8") + b"\n"
    size = len(body) + 1
    while len(str(size)) + len(body) != size:
        size = len(str(size)) + len(body)
    return str(size).encode("ascii") + body


def _member_size_limit(path: str) -> int:
    parts = PurePosixPath(path).parts
    if parts[:2] == ("sources", "native-components"):
        return MAX_LARGE_SOURCE_BYTES
    if len(parts) == 6 and parts[:2] == ("sources", "alpine") and parts[4] == "distfiles":
        return MAX_LARGE_SOURCE_BYTES
    return MAX_MEMBER_BYTES


def _padding(size: int) -> int:
    return (-size) % TAR_BLOCK_BYTES


def _read_zero_padding(reader: _ChunkReader, size: int, source: str) -> None:
    padding = _padding(size)
    if padding and reader.read_exact(padding) != bytes(padding):
        raise VerificationError(f"{source} has nonzero tar padding")


def _read_pax_path(reader: _ChunkReader, header: bytes, total_pax: int) -> tuple[str, int]:
    size = _parse_octal(header[124:136], "PAX size")
    if not 0 < size <= MAX_PAX_BYTES or total_pax + size > MAX_TOTAL_PAX_BYTES:
        raise VerificationError("tar PAX headers exceed their resource limits")
    expected_header = _header(
        name=b"././@PaxHeader",
        mode=0,
        size=size,
        mtime=0,
        typeflag=b"x",
        uname=b"",
        gname=b"",
    )
    if header != expected_header:
        raise VerificationError("tar PAX header is not in canonical producer form")
    payload = reader.read_exact(size)
    _read_zero_padding(reader, size, "PAX header")
    try:
        marker, path_bytes = payload.split(b" path=", maxsplit=1)
        declared = int(marker.decode("ascii"))
        if declared != len(payload) or not path_bytes.endswith(b"\n"):
            raise ValueError
        path = path_bytes[:-1].decode("utf-8")
    except (UnicodeDecodeError, UnicodeEncodeError, ValueError) as exc:
        raise VerificationError("tar PAX path record is malformed") from exc
    checked_path(path)
    if payload != _canonical_pax_payload(path):
        raise VerificationError("tar PAX path record is not canonical")
    encoded = path.encode("utf-8")
    if len(encoded) <= 100 and path.isascii():
        raise VerificationError("tar uses a redundant PAX path record")
    return path, total_pax + size


def parse_archive(
    descriptor: int,
    archive_size: int,
    output: ExtractionRoot,
    expected: ExpectedIdentity,
) -> ArchiveResult:
    """Parse a complete deterministic gzip/PAX stream without generic extraction."""

    reader = _ChunkReader(decompressed_gzip_chunks(descriptor, archive_size))
    records: dict[str, MemberRecord] = {}
    casefolded: set[str] = set()
    previous_path: bytes | None = None
    pending_pax: str | None = None
    total_retained = 0
    total_paths = 0
    total_path_components = 0
    total_pax = 0
    end_started = 0

    while True:
        header = reader.read_exact(TAR_BLOCK_BYTES)
        if header == ZERO_BLOCK:
            if pending_pax is not None:
                raise VerificationError("tar ends after an unconsumed PAX header")
            end_started = reader.consumed
            if reader.read_exact(TAR_BLOCK_BYTES) != ZERO_BLOCK:
                raise VerificationError("tar has only one end-of-archive block")
            break
        typeflag = header[156:157]
        if typeflag == b"x":
            if pending_pax is not None:
                raise VerificationError("tar repeats PAX headers for one member")
            pending_pax, total_pax = _read_pax_path(reader, header, total_pax)
            continue
        if typeflag != b"0":
            raise VerificationError("tar contains a non-regular or unsupported member")

        size = _parse_octal(header[124:136], "member size")
        if pending_pax is None:
            raw_name = header[:100]
            if b"\0" in raw_name:
                name, tail = raw_name.split(b"\0", maxsplit=1)
                if any(tail):
                    raise VerificationError("tar member name has nonzero field padding")
            else:
                name = raw_name
            try:
                path_value = name.decode("ascii")
            except UnicodeDecodeError as exc:
                raise VerificationError("tar member without PAX has a non-ASCII path") from exc
        else:
            path_value = pending_pax
        path = checked_path(path_value)
        encoded_path = path_value.encode("utf-8")
        expected_name = (
            encoded_path if pending_pax is None else path_value.encode("ascii", "replace")[:100]
        )
        expected_header = _header(
            name=expected_name,
            mode=0o644,
            size=size,
            mtime=expected.source_date_epoch,
            typeflag=b"0",
            uname=b"root",
            gname=b"root",
        )
        if header != expected_header:
            raise VerificationError(f"tar member metadata is not canonical: {path_value}")
        pending_pax = None

        if size > _member_size_limit(path_value):
            raise VerificationError(f"tar member exceeds its path-scoped size limit: {path_value}")
        if len(records) >= MAX_MEMBERS:
            raise VerificationError("tar contains too many retained members")
        total_retained += size
        if total_retained > MAX_RETAINED_BYTES:
            raise VerificationError("tar exceeds the cumulative retained-byte limit")
        total_paths += len(encoded_path)
        if total_paths > MAX_TOTAL_PATH_BYTES:
            raise VerificationError("tar paths exceed the cumulative path-byte limit")
        total_path_components += max(0, len(path.parts) - 1)
        if total_path_components > MAX_TOTAL_PATH_COMPONENTS:
            raise VerificationError("tar paths exceed the cumulative component limit")
        if path_value in records:
            raise VerificationError(f"tar repeats member path: {path_value}")
        folded = path_value.casefold()
        if folded in casefolded:
            raise VerificationError(f"tar contains a case-folding path collision: {path_value}")
        casefolded.add(folded)
        if previous_path is not None and encoded_path <= previous_path:
            raise VerificationError("tar member paths are not in canonical byte order")
        previous_path = encoded_path

        record = output.write(path, reader.iter_exact(size), size)
        _read_zero_padding(reader, size, f"member {path_value}")
        records[path_value] = record

    after_two_zeros = end_started + TAR_BLOCK_BYTES
    expected_total = (
        (after_two_zeros + TAR_RECORD_BYTES - 1) // TAR_RECORD_BYTES
    ) * TAR_RECORD_BYTES
    remaining_padding = expected_total - after_two_zeros
    if remaining_padding and reader.read_exact(remaining_padding) != bytes(remaining_padding):
        raise VerificationError("tar end-of-archive record has nonzero padding")
    reader.require_end()
    return ArchiveResult(
        sha256=reader.final_sha256,
        size=archive_size,
        member_count=len(records),
        retained_bytes=total_retained,
        members=records,
    )


def _member_binding(
    value: object,
    path_field: str,
    source: str,
    members: Mapping[str, MemberRecord],
) -> str:
    if not isinstance(value, dict):
        raise VerificationError(f"{source} is not an object")
    path_value = value.get(path_field)
    if not isinstance(path_value, str):
        raise VerificationError(f"{source} has no archive path")
    path = str(checked_path(path_value))
    digest = _digest(value.get("sha256"), f"{source} digest")
    size = _integer(
        value.get("size"),
        f"{source} size",
        minimum=0,
        maximum=_member_size_limit(path),
    )
    record = members.get(path)
    if record is None or record.sha256 != digest or record.size != size:
        raise VerificationError(f"{source} does not match the retained archive member")
    return path


def _https_url(value: object, source: str) -> str:
    url = _bounded_text(value, source, maximum=16 * 1024)
    try:
        parsed = urllib.parse.urlparse(url)
        port = parsed.port
    except ValueError as exc:
        raise VerificationError(f"{source} is not a valid URL") from exc
    if (
        parsed.scheme != "https"
        or not parsed.netloc
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.fragment
        or (port is not None and not 0 <= port <= 65535)
    ):
        raise VerificationError(f"{source} is not credential-free HTTPS")
    return url


def _verify_source_records(
    value: object,
    members: Mapping[str, MemberRecord],
) -> set[str]:
    if not isinstance(value, list) or not value:
        raise VerificationError("manifest source records must be a nonempty list")
    paths: list[str] = []
    identities: set[tuple[str, str]] = set()
    for index, item in enumerate(value):
        source = f"manifest source record {index}"
        record = _exact_mapping(
            item,
            {"component", "path", "sha256", "size", "url", "urls"}
            | ({"sha512"} if isinstance(item, dict) and "sha512" in item else set()),
            source,
        )
        component = _bounded_text(record["component"], f"{source} component")
        path = _member_binding(record, "path", source, members)
        url = _https_url(record["url"], f"{source} URL")
        urls = record["urls"]
        if (
            not isinstance(urls, list)
            or not 1 <= len(urls) <= 8
            or urls[0] != url
            or any(_https_url(candidate, f"{source} URL chain") != candidate for candidate in urls)
        ):
            raise VerificationError(f"{source} has an invalid URL chain")
        if "sha512" in record:
            sha512 = record["sha512"]
            if (
                not isinstance(sha512, str)
                or HEX128.fullmatch(sha512) is None
                or members[path].sha512 != sha512
            ):
                raise VerificationError(f"{source} has an invalid SHA-512")
        paths.append(path)
        identity = (component, path)
        if identity in identities:
            raise VerificationError("manifest source records repeat a component/path binding")
        identities.add(identity)
    if paths != sorted(paths):
        raise VerificationError("manifest source records are not sorted by retained path")
    return set(paths)


def _verify_application_source_record(
    value: object,
    expected: ExpectedIdentity,
) -> None:
    records = _bounded_list(
        value,
        "manifest source records",
        maximum=MAX_MEMBERS,
        nonempty=True,
    )
    application_records = [
        record
        for record in records
        if isinstance(record, dict)
        and (
            record.get("component") == "extra-codeowners"
            or record.get("path") == "sources/application/extra-codeowners.tar"
        )
    ]
    expected_url = f"https://github.com/stampbot/extra-codeowners/tree/{expected.source_revision}"
    if len(application_records) != 1:
        raise VerificationError("manifest must bind one canonical application source archive")
    record = application_records[0]
    if (
        set(record) != {"component", "path", "sha256", "size", "url", "urls"}
        or record["component"] != "extra-codeowners"
        or record["path"] != "sources/application/extra-codeowners.tar"
        or record["url"] != expected_url
        or record["urls"] != [expected_url]
    ):
        raise VerificationError("manifest application source does not bind the trusted revision")


def _application_license_member(
    value: object,
    members: Mapping[str, MemberRecord],
) -> MemberRecord:
    records = _bounded_list(
        value,
        "manifest license records",
        maximum=MAX_MEMBERS,
        nonempty=True,
    )
    application_records = [
        record
        for record in records
        if isinstance(record, dict)
        and (
            record.get("component") == "extra-codeowners"
            or record.get("path") == "licenses/from-source/extra-codeowners/LICENSE"
        )
    ]
    if len(application_records) != 1:
        raise VerificationError("manifest must bind one canonical application license")
    record = application_records[0]
    if (
        set(record) != {"component", "path", "sha256", "size"}
        or record["component"] != "extra-codeowners"
        or record["path"] != "licenses/from-source/extra-codeowners/LICENSE"
    ):
        raise VerificationError("manifest application license record is not canonical")
    path = _member_binding(
        record,
        "path",
        "manifest application license record",
        members,
    )
    return members[path]


def _application_source_members(
    raw: bytes,
) -> tuple[dict[str, tuple[int, int, str]], Mapping[str, Any]]:
    """Parse the producer's deterministic, uncompressed application source tar."""

    if not 0 < len(raw) <= MAX_MEMBER_BYTES:
        raise VerificationError("application source archive has an invalid size")
    position = 0
    pending_pax: str | None = None
    total_pax = 0
    total_path_bytes = 0
    total_path_components = 0
    previous_path: bytes | None = None
    records: dict[str, tuple[int, int, str]] = {}
    casefolded_paths: set[str] = set()
    package_found = False
    pyproject = b""

    def read_exact(size: int, source: str) -> bytes:
        nonlocal position
        end = position + size
        if end > len(raw):
            raise VerificationError(f"application source archive ends inside {source}")
        content = raw[position:end]
        position = end
        return content

    def consume_padding(size: int, source: str) -> None:
        padding = _padding(size)
        if padding and read_exact(padding, source) != bytes(padding):
            raise VerificationError(f"application source {source} has nonzero padding")

    while True:
        header = read_exact(TAR_BLOCK_BYTES, "a tar header")
        if header == ZERO_BLOCK:
            if pending_pax is not None:
                raise VerificationError(
                    "application source archive ends after an unconsumed PAX header"
                )
            if read_exact(TAR_BLOCK_BYTES, "the second end block") != ZERO_BLOCK:
                raise VerificationError(
                    "application source archive has only one end-of-archive block"
                )
            break
        typeflag = header[156:157]
        if typeflag == b"x":
            if pending_pax is not None:
                raise VerificationError(
                    "application source archive repeats PAX headers for one member"
                )
            size = _parse_octal(header[124:136], "application source PAX size")
            total_pax += size
            if (
                not 0 < size <= MAX_PAX_BYTES
                or total_pax > MAX_TOTAL_PAX_BYTES
                or header
                != _header(
                    name=b"././@PaxHeader",
                    mode=0,
                    size=size,
                    mtime=0,
                    typeflag=b"x",
                    uname=b"",
                    gname=b"",
                )
            ):
                raise VerificationError(
                    "application source PAX header is not in canonical producer form"
                )
            payload = read_exact(size, "a PAX payload")
            consume_padding(size, "PAX header")
            try:
                marker, path_bytes = payload.split(b" path=", maxsplit=1)
                declared = int(marker.decode("ascii"))
                if declared != len(payload) or not path_bytes.endswith(b"\n"):
                    raise ValueError
                pending_pax = path_bytes[:-1].decode("utf-8")
            except (UnicodeDecodeError, ValueError) as exc:
                raise VerificationError("application source PAX path is malformed") from exc
            checked_path(pending_pax)
            if payload != _canonical_pax_payload(pending_pax):
                raise VerificationError("application source PAX path is not canonical")
            if len(pending_pax.encode("utf-8")) <= 100 and pending_pax.isascii():
                raise VerificationError("application source uses a redundant PAX path")
            continue
        if typeflag != b"0":
            raise VerificationError("application source archive contains a non-regular member")

        size = _parse_octal(header[124:136], "application source member size")
        mode = _parse_octal(header[100:108], "application source member mode")
        if mode not in {0o644, 0o755} or size > MAX_MEMBER_BYTES:
            raise VerificationError("application source member has invalid metadata or size")
        if pending_pax is None:
            raw_name = header[:100]
            if b"\0" in raw_name:
                name, tail = raw_name.split(b"\0", maxsplit=1)
                if any(tail):
                    raise VerificationError("application source member name has nonzero padding")
            else:
                name = raw_name
            try:
                path_value = name.decode("ascii")
            except UnicodeDecodeError as exc:
                raise VerificationError(
                    "application source member without PAX has a non-ASCII path"
                ) from exc
        else:
            path_value = pending_pax
        path = checked_path(path_value)
        encoded_path = path_value.encode("utf-8")
        expected_name = (
            encoded_path if pending_pax is None else path_value.encode("ascii", "replace")[:100]
        )
        if header != _header(
            name=expected_name,
            mode=mode,
            size=size,
            mtime=0,
            typeflag=b"0",
            uname=b"root",
            gname=b"root",
        ):
            raise VerificationError(
                f"application source member metadata is not canonical: {path_value}"
            )
        pending_pax = None
        folded_path = path_value.casefold()
        if (
            path_value in records
            or folded_path in casefolded_paths
            or (previous_path is not None and encoded_path <= previous_path)
        ):
            raise VerificationError(
                "application source member paths are repeated, colliding, or non-canonical"
            )
        if len(records) >= MAX_MEMBERS:
            raise VerificationError("application source archive contains too many members")
        total_path_bytes += len(encoded_path)
        total_path_components += max(0, len(path.parts) - 1)
        if (
            total_path_bytes > MAX_TOTAL_PATH_BYTES
            or total_path_components > MAX_TOTAL_PATH_COMPONENTS
        ):
            raise VerificationError("application source paths exceed their cumulative limits")
        previous_path = encoded_path
        casefolded_paths.add(folded_path)
        content = read_exact(size, f"member {path_value}")
        consume_padding(size, f"member {path_value}")
        records[path_value] = (mode, size, hashlib.sha256(content).hexdigest())
        if path_value == "pyproject.toml":
            if size > 1024 * 1024:
                raise VerificationError("application pyproject.toml exceeds its size limit")
            pyproject = content
        elif path_value.startswith("extra_codeowners/"):
            package_found = True

    expected_total = ((position + TAR_RECORD_BYTES - 1) // TAR_RECORD_BYTES) * TAR_RECORD_BYTES
    if len(raw) != expected_total or raw[position:] != bytes(expected_total - position):
        raise VerificationError("application source archive has a non-canonical end record")
    if "LICENSE" not in records or not pyproject or not package_found:
        raise VerificationError(
            "application source archive omits its license, project identity, or package"
        )
    project = _strict_toml_bytes(
        pyproject,
        "application source pyproject.toml",
        maximum=1024 * 1024,
    ).get("project")
    if not isinstance(project, dict):
        raise VerificationError("application source pyproject.toml has no project table")
    return records, project


def _verify_application_source_archive(
    raw: bytes,
    files: Mapping[str, Any],
    components: Mapping[str, Any],
    application_license: MemberRecord,
    expected: ExpectedIdentity,
) -> None:
    records, project = _application_source_members(raw)
    if records["LICENSE"] != (
        0o644,
        application_license.size,
        application_license.sha256,
    ):
        raise VerificationError(
            "application source license differs from retained application license"
        )
    if project.get("name") != "extra-codeowners" or project.get("version") != expected.version:
        raise VerificationError(
            "application source project identity differs from the trusted release"
        )
    application_components = [
        component
        for component in components["components"]
        if component["ecosystem"] == "python" and component["name"] == "extra-codeowners"
    ]
    if (
        len(application_components) != 1
        or application_components[0]["version"] != expected.version
        or application_components[0]["effective"] is not True
    ):
        raise VerificationError(
            "component inventory does not contain the effective application source identity"
        )
    application = application_components[0]
    metadata_records = [
        record
        for record in files["regular_files"]
        if record["effective"] is True
        and record["sha256"] == application["metadata_sha256"]
        and str(record["path"]).endswith(".dist-info/METADATA")
    ]
    if len(metadata_records) != 1:
        raise VerificationError(
            "all-layer inventory does not identify one effective application metadata file"
        )
    site_root = PurePosixPath(str(metadata_records[0]["path"])).parent.parent
    source_records = {
        path: identity for path, identity in records.items() if path.startswith("extra_codeowners/")
    }
    installed_records = {
        str(PurePosixPath(str(record["path"])).relative_to(site_root)): record
        for record in files["regular_files"]
        if record["effective"] is True
        and PurePosixPath(str(record["path"])).is_relative_to(site_root / "extra_codeowners")
    }
    if set(source_records) != set(installed_records):
        raise VerificationError(
            "application source archive differs from installed application files"
        )
    for path, (_mode, size, digest) in source_records.items():
        installed = installed_records[path]
        if installed["size"] != size or installed["sha256"] != digest:
            raise VerificationError(f"application source differs from installed file: {path}")


def _verify_license_records(
    value: object,
    members: Mapping[str, MemberRecord],
) -> set[str]:
    if not isinstance(value, list) or not value:
        raise VerificationError("manifest license records must be a nonempty list")
    ordering: list[tuple[str, str]] = []
    paths: set[str] = set()
    for index, item in enumerate(value):
        source = f"manifest license record {index}"
        record = _exact_mapping(item, {"component", "path", "sha256", "size"}, source)
        component = _bounded_text(record["component"], f"{source} component")
        path = _member_binding(record, "path", source, members)
        ordering.append((component, path))
        paths.add(path)
    if ordering != sorted(ordering) or len(ordering) != len(set(ordering)):
        raise VerificationError("manifest license records are not uniquely sorted")
    return paths


def _verify_application_artifacts(
    value: object,
    members: Mapping[str, MemberRecord],
    expected: ExpectedIdentity,
    installations_by_owner: Mapping[str, list[Mapping[str, Any]]],
) -> tuple[set[str], str, str]:
    record = _exact_mapping(
        value,
        {
            "files",
            "launcher_interpreter",
            "selection_record_sha256",
            "source_revision",
            "wheel_sha256",
        },
        "manifest application artifacts",
    )
    if record["source_revision"] != expected.source_revision:
        raise VerificationError("application artifacts have the wrong source revision")
    wheel_sha256 = _digest(record["wheel_sha256"], "application wheel digest")
    selection_sha256 = _digest(
        record["selection_record_sha256"],
        "application selection-record digest",
    )
    launcher_interpreter = _bounded_text(
        record["launcher_interpreter"],
        "application launcher interpreter",
        maximum=32,
    )
    if launcher_interpreter not in {"python", "python3", "python3.14"}:
        raise VerificationError("application launcher interpreter is unsupported")
    owner = f"python:extra-codeowners@{expected.version}"
    active_installations = [
        installation
        for installation in installations_by_owner.get(owner, [])
        if isinstance(installation.get("record"), dict)
        and installation["record"].get("effective") is True
    ]
    if len(active_installations) != 1:
        raise VerificationError("application artifacts have no unique active installation")
    launcher_path = "opt/venv/bin/extra-codeowners"
    launcher_entries = [
        entry
        for entry in active_installations[0]["entries"]
        if isinstance(entry, dict) and str(entry.get("path", "")).startswith("opt/venv/bin/")
    ]
    if len(launcher_entries) != 1 or launcher_entries[0].get("path") != launcher_path:
        raise VerificationError("active application installation has the wrong launcher set")
    launcher_entry = launcher_entries[0]
    occurrence = _validate_occurrence(
        launcher_entry["occurrence"],
        "active application launcher occurrence",
    )
    launcher = _expected_native_launcher(
        "extra_codeowners.cli",
        "main",
        interpreter=launcher_interpreter,
    )
    if (
        occurrence["path"] != launcher_path
        or occurrence["effective"] is not True
        or occurrence["mode"] != 0o755
        or occurrence["uid"] != 0
        or occurrence["gid"] != 0
        or occurrence["sha256"] != hashlib.sha256(launcher).hexdigest()
        or occurrence["size"] != len(launcher)
        or launcher_entry.get("recorded_sha256") != occurrence["sha256"]
        or launcher_entry.get("recorded_size") != occurrence["size"]
    ):
        raise VerificationError(
            "application launcher interpreter differs from the active installation"
        )
    files = record["files"]
    if not isinstance(files, list) or len(files) != 5:
        raise VerificationError("application artifacts must bind exactly five files")
    ordered_paths: list[str] = []
    for index, item in enumerate(files):
        binding = _exact_mapping(
            item,
            {"path", "sha256", "size"},
            f"application artifact {index}",
        )
        ordered_paths.append(
            _member_binding(binding, "path", f"application artifact {index}", members)
        )
    paths = set(ordered_paths)
    if (
        ordered_paths != sorted(ordered_paths)
        or len(paths) != 5
        or any(not path.startswith("artifacts/application/") for path in paths)
    ):
        raise VerificationError("application artifact paths are invalid or repeated")
    required_paths = {
        f"artifacts/application/extra_codeowners-{expected.version}-py3-none-any.whl",
        f"artifacts/application/extra_codeowners-{expected.version}.tar.gz",
        "artifacts/application/python-build-record-amd64.json",
        "artifacts/application/python-build-record-arm64.json",
        "artifacts/application/python-selection-record.json",
    }
    if paths != required_paths:
        raise VerificationError("application artifacts do not have the exact five-file identity")
    if not any(members[path].sha256 == wheel_sha256 and path.endswith(".whl") for path in paths):
        raise VerificationError("application wheel digest is not retained")
    selection_path = "artifacts/application/python-selection-record.json"
    if selection_path not in paths or members[selection_path].sha256 != selection_sha256:
        raise VerificationError("application selection record is not retained")
    return paths, wheel_sha256, selection_sha256


def _verify_wheelhouse_artifacts(
    value: object,
    members: Mapping[str, MemberRecord],
    expected: ExpectedIdentity,
    policy: Mapping[str, Any],
    components: Mapping[str, Any],
    contract: Mapping[str, Any],
    consumer_store: Mapping[str, Any],
) -> set[str]:
    record = _exact_mapping(
        value,
        {
            "consumer_store",
            "contract",
            "files",
            "index_digest",
            "platform",
            "source_revision",
            "store_schema_version",
        },
        "manifest native wheelhouse artifacts",
    )
    if record["platform"] != expected.platform:
        raise VerificationError("native wheelhouse artifacts have the wrong platform")
    index_digest = _oci_digest(record["index_digest"], "native wheelhouse index digest")
    if (
        not isinstance(record["source_revision"], str)
        or HEX40.fullmatch(record["source_revision"]) is None
    ):
        raise VerificationError("native wheelhouse artifacts have an invalid source revision")
    store_schema_version = _integer(
        record["store_schema_version"],
        "native wheelhouse store schema",
        minimum=1,
        maximum=1024,
    )
    contract_record = _exact_mapping(
        contract,
        {
            "image",
            "index_digest",
            "manifest_schema_version",
            "platforms",
            "signature",
            "source_ref",
            "source_revision",
        },
        "native wheelhouse consumer contract",
    )
    if (
        contract_record["image"] != WHEELHOUSE_IMAGE
        or contract_record["source_ref"] != WHEELHOUSE_SOURCE_REF
        or contract_record["manifest_schema_version"] != WHEELHOUSE_MANIFEST_SCHEMA_VERSION
    ):
        raise VerificationError("native wheelhouse consumer contract has the wrong identity")
    contract_revision = contract_record["source_revision"]
    if (
        not isinstance(contract_revision, str)
        or HEX40.fullmatch(contract_revision) is None
        or contract_revision == "0" * 40
    ):
        raise VerificationError("native wheelhouse consumer contract has an invalid revision")
    contract_index_digest = _oci_digest(
        contract_record["index_digest"],
        "native wheelhouse consumer contract index digest",
    )
    contract_platforms = _exact_mapping(
        contract_record["platforms"],
        {"linux/amd64", "linux/arm64"},
        "native wheelhouse consumer contract platforms",
    )
    for platform_name in ("linux/amd64", "linux/arm64"):
        platform_record = _exact_mapping(
            contract_platforms[platform_name],
            {"manifest_digest"},
            f"native wheelhouse consumer contract platform {platform_name}",
        )
        _oci_digest(
            platform_record["manifest_digest"],
            f"native wheelhouse consumer contract platform {platform_name} manifest digest",
        )
    signature = _exact_mapping(
        contract_record["signature"],
        {"certificate_identity", "oidc_issuer"},
        "native wheelhouse consumer contract signature",
    )
    if signature != {
        "certificate_identity": WHEELHOUSE_CERTIFICATE_IDENTITY,
        "oidc_issuer": WHEELHOUSE_OIDC_ISSUER,
    }:
        raise VerificationError("native wheelhouse consumer contract has the wrong signer")

    store_record = _exact_mapping(
        consumer_store,
        {"contract", "kind", "platforms", "schema_version"},
        "native wheelhouse consumer store",
    )
    consumer_store_schema_version = _integer(
        store_record["schema_version"],
        "native wheelhouse consumer store schema",
        minimum=1,
        maximum=1024,
    )
    if (
        store_record["kind"] != WHEELHOUSE_STORE_KIND
        or consumer_store_schema_version != WHEELHOUSE_STORE_SCHEMA_VERSION
        or store_record["contract"] != contract_record
    ):
        raise VerificationError("native wheelhouse consumer store has the wrong identity")
    store_platforms = _exact_mapping(
        store_record["platforms"],
        {"linux/amd64", "linux/arm64"},
        "native wheelhouse consumer store platforms",
    )
    selected_store_files: list[Mapping[str, Any]] | None = None
    for platform_name in ("linux/amd64", "linux/arm64"):
        platform_record = _exact_mapping(
            store_platforms[platform_name],
            {"directory", "files"},
            f"native wheelhouse consumer store platform {platform_name}",
        )
        expected_directory = platform_name.replace("/", "-")
        if platform_record["directory"] != expected_directory:
            raise VerificationError(
                f"native wheelhouse consumer store platform {platform_name} has the wrong directory"
            )
        store_files = platform_record["files"]
        if not isinstance(store_files, list) or not store_files:
            raise VerificationError(
                f"native wheelhouse consumer store platform {platform_name} "
                "has an empty file inventory"
            )
        observed_names: list[str] = []
        validated_files: list[Mapping[str, Any]] = []
        for file_index, item in enumerate(store_files):
            file_record = _exact_mapping(
                item,
                {"path", "sha256", "size"},
                f"native wheelhouse consumer store platform {platform_name} file {file_index}",
            )
            filename = file_record["path"]
            if not isinstance(filename, str) or len(checked_path(filename).parts) != 1:
                raise VerificationError(
                    f"native wheelhouse consumer store platform {platform_name} "
                    f"file {file_index} has an invalid path"
                )
            _digest(
                file_record["sha256"],
                f"native wheelhouse consumer store platform {platform_name} "
                f"file {file_index} digest",
            )
            _integer(
                file_record["size"],
                f"native wheelhouse consumer store platform {platform_name} file {file_index} size",
                minimum=0,
                maximum=MAX_LARGE_SOURCE_BYTES,
            )
            observed_names.append(filename)
            validated_files.append(file_record)
        if observed_names != sorted(observed_names) or len(observed_names) != len(
            set(observed_names)
        ):
            raise VerificationError(
                f"native wheelhouse consumer store platform {platform_name} "
                "files are not uniquely sorted"
            )
        if platform_name == expected.platform:
            selected_store_files = validated_files
    assert selected_store_files is not None
    contract_binding = _exact_mapping(
        record["contract"],
        {"path", "sha256", "size"},
        "native wheelhouse contract",
    )
    contract_path = _member_binding(
        contract_binding,
        "path",
        "native wheelhouse contract",
        members,
    )
    store_binding = _exact_mapping(
        record["consumer_store"],
        {"path", "sha256", "size"},
        "native wheelhouse consumer store",
    )
    store_path = _member_binding(
        store_binding,
        "path",
        "native wheelhouse consumer store",
        members,
    )
    if (
        contract_path != "policy/native-wheelhouse-consumer.json"
        or store_path != "artifacts/native-wheelhouse/source.json"
    ):
        raise VerificationError("native wheelhouse metadata has the wrong retained paths")
    if policy.get("native_wheelhouse_contract_sha256") != members[contract_path].sha256:
        raise VerificationError("container policy does not bind the retained wheelhouse contract")
    if (
        contract_index_digest != index_digest
        or contract_revision != record["source_revision"]
        or consumer_store_schema_version != store_schema_version
    ):
        raise VerificationError("native wheelhouse metadata disagrees with its retained records")
    if (
        components.get("native_wheelhouse_index_digest") != index_digest
        or components.get("native_wheelhouse_revision") != record["source_revision"]
        or components.get("native_wheelhouse_schema") != str(WHEELHOUSE_MANIFEST_SCHEMA_VERSION)
    ):
        raise VerificationError("component inventory disagrees with native wheelhouse identity")
    paths = {contract_path, store_path}
    files = record["files"]
    if not isinstance(files, list) or not files:
        raise VerificationError("native wheelhouse artifact file list is empty")
    file_paths: list[str] = []
    retained_prefix = f"artifacts/native-wheelhouse/{expected.platform.replace('/', '-')}/"
    for index, item in enumerate(files):
        file_record = _exact_mapping(
            item,
            {"path", "retained_path", "sha256", "size"},
            f"native wheelhouse retained file {index}",
        )
        relative_path = file_record["path"]
        if not isinstance(relative_path, str) or len(checked_path(relative_path).parts) != 1:
            raise VerificationError(
                f"native wheelhouse retained file {index} has an invalid source path"
            )
        retained_path = _member_binding(
            file_record,
            "retained_path",
            f"native wheelhouse retained file {index}",
            members,
        )
        if retained_path != f"{retained_prefix}{relative_path}":
            raise VerificationError(
                f"native wheelhouse retained file {index} has the wrong retained path"
            )
        file_paths.append(retained_path)
        paths.add(retained_path)
    if file_paths != sorted(file_paths) or len(file_paths) != len(set(file_paths)):
        raise VerificationError("native wheelhouse retained files are not uniquely sorted")
    manifest_store_files = [
        {
            "path": file_record["path"],
            "sha256": file_record["sha256"],
            "size": file_record["size"],
        }
        for file_record in files
    ]
    if manifest_store_files != selected_store_files:
        raise VerificationError("native wheelhouse retained files differ from the consumer store")
    return paths


def _expected_native_launcher(
    module: str,
    callable_name: str,
    *,
    interpreter: str,
) -> bytes:
    python = f"/opt/venv/bin/{interpreter}"
    return (
        f"#!{python}\n"
        "# -*- coding: utf-8 -*-\n"
        "import sys\n"
        f"from {module} import {callable_name}\n"
        'if __name__ == "__main__":\n'
        '    if sys.argv[0].endswith("-script.pyw"):\n'
        "        sys.argv[0] = sys.argv[0][:-11]\n"
        '    elif sys.argv[0].endswith(".exe"):\n'
        "        sys.argv[0] = sys.argv[0][:-4]\n"
        f"    sys.exit({callable_name}())\n"
    ).encode()


def _validate_generated_files(
    value: object,
    *,
    owner: str,
    installation: Mapping[str, Any],
    source: str,
) -> None:
    entries = {
        str(entry["path"]): entry
        for entry in installation["entries"]
        if isinstance(entry, dict) and isinstance(entry.get("path"), str)
    }
    generated_paths: list[str] = []
    for index, raw_record in enumerate(
        _bounded_list(value, f"{source} generated files", maximum=10_000)
    ):
        record_source = f"{source} generated file {index}"
        record = _exact_mapping(
            raw_record,
            {
                "callable",
                "installed_occurrence",
                "kind",
                "launcher_interpreter",
                "module",
                "name",
                "source_path",
            },
            record_source,
        )
        name = _bounded_text(record["name"], f"{record_source} name", maximum=512)
        kind = _bounded_text(record["kind"], f"{record_source} kind", maximum=32)
        module = _bounded_text(record["module"], f"{record_source} module", maximum=512)
        callable_name = _bounded_text(
            record["callable"],
            f"{record_source} callable",
            maximum=512,
        )
        source_path = _bounded_text(
            record["source_path"],
            f"{record_source} source path",
        )
        interpreter = _bounded_text(
            record["launcher_interpreter"],
            f"{record_source} launcher interpreter",
            maximum=32,
        )
        if (
            SCRIPT_NAME.fullmatch(name) is None
            or kind not in {"console_scripts", "gui_scripts"}
            or not all(PYTHON_IDENTIFIER.fullmatch(part) for part in module.split("."))
            or PYTHON_IDENTIFIER.fullmatch(callable_name) is None
            or str(checked_path(source_path)) != source_path
            or not source_path.endswith(".dist-info/entry_points.txt")
            or interpreter not in {"python", "python3", "python3.14"}
        ):
            raise VerificationError(f"{record_source} has an invalid launcher identity")
        source_matches = [
            path for path in entries if path.endswith(f"/site-packages/{source_path}")
        ]
        if len(source_matches) != 1:
            raise VerificationError(
                f"{record_source} is not bound to its installed entry_points.txt"
            )
        occurrence = _validate_occurrence(
            record["installed_occurrence"],
            f"{record_source} installed occurrence",
        )
        path = f"opt/venv/bin/{name}"
        entry = entries.get(path)
        if (
            occurrence["path"] != path
            or entry is None
            or entry.get("occurrence") != occurrence
            or entry.get("recorded_sha256") != occurrence["sha256"]
            or entry.get("recorded_size") != occurrence["size"]
            or occurrence["mode"] != 0o755
            or occurrence["uid"] != 0
            or occurrence["gid"] != 0
        ):
            raise VerificationError(f"{record_source} is not bound to {owner}'s installed RECORD")
        launcher = _expected_native_launcher(
            module,
            callable_name,
            interpreter=str(interpreter),
        )
        if occurrence["sha256"] != hashlib.sha256(launcher).hexdigest() or occurrence[
            "size"
        ] != len(launcher):
            raise VerificationError(f"{record_source} differs from reviewed launcher bytes")
        generated_paths.append(path)
    expected_paths = sorted(path for path in entries if path.startswith("opt/venv/bin/"))
    if (
        generated_paths != sorted(generated_paths)
        or len(generated_paths) != len(set(generated_paths))
        or generated_paths != expected_paths
    ):
        raise VerificationError(
            f"{source} generated files do not exactly cover installed launchers"
        )


def _verify_native_wheels(
    value: object,
    members: Mapping[str, MemberRecord],
    expected: ExpectedIdentity,
    policy: Mapping[str, Any],
    installations_by_owner: Mapping[str, list[Mapping[str, Any]]],
) -> set[str]:
    if not isinstance(value, list) or not value:
        raise VerificationError("manifest native wheel artifacts must be nonempty")
    raw_coverage = policy.get("native_component_coverage")
    configured = raw_coverage.get(expected.platform) if isinstance(raw_coverage, dict) else None
    if not isinstance(configured, list):
        raise VerificationError("container policy has no selected native-wheel owners")
    configured_by_owner = {
        str(record["owner"]): record for record in configured if isinstance(record, dict)
    }
    if len(configured_by_owner) != len(configured) or len(value) != len(configured):
        raise VerificationError(
            "manifest native wheel artifacts differ from reviewed policy owners"
        )
    paths: set[str] = set()
    owners: list[str] = []
    for index, item in enumerate(value):
        if not isinstance(item, dict):
            raise VerificationError(f"native wheel artifact {index} is not an object")
        provider = item.get("provider")
        artifact_fields = {
            "build",
            "embedded_sboms",
            "filename",
            "generated_files",
            "owner",
            "path",
            "platform",
            "sha256",
            "size",
            "tags",
            "urls",
        }
        if provider == "native-wheelhouse":
            artifact_fields |= {"provider", "source"}
        elif provider is None:
            artifact_fields.add("url")
        else:
            raise VerificationError(f"native wheel artifact {index} has an unsupported provider")
        artifact = _exact_mapping(
            item,
            artifact_fields,
            f"native wheel artifact {index}",
        )
        if artifact["platform"] != expected.platform:
            raise VerificationError(f"native wheel artifact {index} has the wrong platform")
        owner = _bounded_text(artifact["owner"], f"native wheel artifact {index} owner")
        owner_match = re.fullmatch(r"python:([^/@]+)@([^/@]+)", owner)
        if owner_match is None:
            raise VerificationError(f"native wheel artifact {index} has an invalid owner")
        policy_owner = configured_by_owner.get(owner)
        if policy_owner is None:
            raise VerificationError(f"native wheel artifact {index} has no reviewed policy owner")
        policy_wheel = policy_owner["wheel"]
        if provider == "native-wheelhouse":
            expected_wheel = {
                field: artifact[field]
                for field in ("filename", "provider", "sha256", "size", "source")
            }
        else:
            expected_wheel = {field: artifact[field] for field in ("sha256", "size", "url")}
        if policy_wheel != expected_wheel:
            raise VerificationError(f"native wheel artifact {index} differs from reviewed policy")
        owners.append(owner)
        path = _member_binding(artifact, "path", f"native wheel artifact {index}", members)
        filename = artifact["filename"]
        expected_prefix = f"artifacts/native-wheels/{owner_match.group(1)}/{owner_match.group(2)}/"
        if (
            not isinstance(filename, str)
            or len(checked_path(filename).parts) != 1
            or path != f"{expected_prefix}{filename}"
            or (
                provider is None
                and PurePosixPath(urllib.parse.urlparse(str(artifact["url"])).path).name != filename
            )
        ):
            raise VerificationError(f"native wheel artifact {index} has the wrong retained path")
        if path in paths:
            raise VerificationError("native wheel artifacts repeat a retained path")
        paths.add(path)
        build = artifact["build"]
        if build is not None:
            _bounded_text(build, f"native wheel artifact {index} build", maximum=512)
        tags = _bounded_list(
            artifact["tags"],
            f"native wheel artifact {index} tags",
            maximum=256,
            nonempty=True,
        )
        if (
            not all(isinstance(tag, str) and tag for tag in tags)
            or tags != sorted(tags)
            or len(tags) != len(set(tags))
        ):
            raise VerificationError(f"native wheel artifact {index} tags are invalid")
        matching_installations = installations_by_owner.get(owner, [])
        if len(matching_installations) != 1:
            raise VerificationError(
                f"native wheel artifact {index} has no unique historical installation"
            )
        installation = matching_installations[0]
        normalized_build = "" if build is None else build
        if normalized_build != installation["build"] or tags != installation["tags"]:
            raise VerificationError(
                f"native wheel artifact {index} build or tags differ from its installation"
            )
        _validate_generated_files(
            artifact["generated_files"],
            owner=owner,
            installation=installation,
            source=f"native wheel artifact {index}",
        )
        urls = _bounded_list(
            artifact["urls"],
            f"native wheel artifact {index} URL chain",
            maximum=16,
        )
        if provider == "native-wheelhouse":
            if urls:
                raise VerificationError(
                    f"native wheel artifact {index} wheelhouse URL chain is invalid"
                )
        elif (
            not urls
            or urls[0] != artifact["url"]
            or not all(isinstance(url, str) for url in urls)
            or len(urls) != len(set(urls))
            or any(_https_url(url, f"native wheel artifact {index} URL") != url for url in urls)
        ):
            raise VerificationError(f"native wheel artifact {index} URL chain is invalid")

        sboms = artifact["embedded_sboms"]
        if not isinstance(sboms, list):
            raise VerificationError(f"native wheel artifact {index} has invalid embedded SBOMs")
        expected_sboms = {str(record["path"]): record for record in policy_owner["sboms"]}
        observed_sbom_paths: list[str] = []
        for sbom_index, item in enumerate(sboms):
            sbom_fields = {
                "archive_path",
                "installed_occurrence",
                "owner",
                "path",
                "platform",
                "sha256",
                "size",
                "urls",
            }
            if provider == "native-wheelhouse":
                sbom_fields |= {"provider", "source"}
            else:
                sbom_fields.add("url")
            sbom = _exact_mapping(
                item,
                sbom_fields,
                f"native wheel artifact {index} embedded SBOM {sbom_index}",
            )
            expected_provider_fields = (
                {"provider": provider, "source": artifact["source"]}
                if provider == "native-wheelhouse"
                else {"url": artifact["url"]}
            )
            if (
                sbom["owner"] != owner
                or sbom["platform"] != expected.platform
                or {field: sbom[field] for field in expected_provider_fields}
                != expected_provider_fields
                or sbom["urls"] != urls
            ):
                raise VerificationError(
                    f"native wheel artifact {index} embedded SBOM {sbom_index} "
                    "has the wrong identity"
                )
            archive_path_value = _bounded_text(
                sbom["archive_path"],
                f"native wheel artifact {index} embedded SBOM {sbom_index} archive path",
            )
            archive_path = str(checked_path(archive_path_value))
            if archive_path != archive_path_value:
                raise VerificationError(
                    f"native wheel artifact {index} embedded SBOM {sbom_index} "
                    "has a noncanonical archive path"
                )
            sbom_path = _member_binding(
                sbom,
                "path",
                f"native wheel artifact {index} embedded SBOM {sbom_index}",
                members,
            )
            if sbom_path != f"{expected_prefix}embedded-sboms/{archive_path}":
                raise VerificationError(
                    f"native wheel artifact {index} embedded SBOM {sbom_index} "
                    "has the wrong retained path"
                )
            occurrence = _validate_occurrence(
                sbom["installed_occurrence"],
                f"native wheel artifact {index} embedded SBOM {sbom_index} occurrence",
            )
            reviewed_sbom = expected_sboms.get(str(occurrence["path"]))
            if (
                occurrence["effective"] is not True
                or reviewed_sbom is None
                or reviewed_sbom["sha256"] != sbom["sha256"]
                or occurrence["sha256"] != sbom["sha256"]
                or occurrence["size"] != sbom["size"]
            ):
                raise VerificationError(
                    f"native wheel artifact {index} embedded SBOM {sbom_index} "
                    "differs from reviewed policy"
                )
            if sbom_path in paths:
                raise VerificationError("native wheel artifacts repeat a retained path")
            paths.add(sbom_path)
            observed_sbom_paths.append(str(occurrence["path"]))
        if (
            observed_sbom_paths != sorted(observed_sbom_paths)
            or len(observed_sbom_paths) != len(set(observed_sbom_paths))
            or set(observed_sbom_paths) != set(expected_sboms)
        ):
            raise VerificationError(
                f"native wheel artifact {index} embedded SBOMs differ from reviewed policy"
            )
    if (
        owners != sorted(owners)
        or len(owners) != len(set(owners))
        or set(owners) != set(configured_by_owner)
    ):
        raise VerificationError(
            "native wheel artifacts are not exact and uniquely sorted policy owners"
        )
    return paths


def _require_identity_record(
    value: Mapping[str, Any],
    source: str,
    expected: ExpectedIdentity,
) -> None:
    if value.get("schema_version") != SCHEMA_VERSION:
        raise VerificationError(f"{source} has an unsupported schema")
    if value.get("platform") != expected.platform:
        raise VerificationError(f"{source} has the wrong platform")
    if value.get("subject_digest") != expected.subject_digest:
        raise VerificationError(f"{source} has the wrong platform subject")


def _bounded_list(
    value: object,
    source: str,
    *,
    maximum: int = MAX_MEMBERS,
    nonempty: bool = False,
) -> list[Any]:
    if not isinstance(value, list) or len(value) > maximum or (nonempty and not value):
        raise VerificationError(f"{source} has invalid list bounds")
    return value


def _validate_occurrence(value: object, source: str) -> Mapping[str, Any]:
    record = _exact_mapping(value, REGULAR_OCCURRENCE_FIELDS, source)
    _boolean(record["effective"], f"{source} effective state")
    _integer(record["layer"], f"{source} layer", minimum=0, maximum=MAX_MEMBERS)
    path = _bounded_text(record["path"], f"{source} path")
    checked_path(path)
    _digest(record["sha256"], f"{source} digest")
    _integer(
        record["size"],
        f"{source} size",
        minimum=0,
        maximum=MAX_MEMBER_BYTES,
    )
    _integer(record["mode"], f"{source} mode", minimum=0, maximum=0o7777)
    _integer(record["uid"], f"{source} UID", minimum=0, maximum=2**31 - 1)
    _integer(record["gid"], f"{source} GID", minimum=0, maximum=2**31 - 1)
    return record


def _checked_image_link_target(value: object, source: str) -> str:
    target = _bounded_text(value, source)
    try:
        encoded = target.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise VerificationError(f"{source} is not valid UTF-8") from exc
    if (
        not target
        or len(encoded) > MAX_PATH_BYTES
        or any(ord(character) < 32 or 0x7F <= ord(character) <= 0x9F for character in target)
    ):
        raise VerificationError(f"{source} is invalid")
    return target


def _replay_filesystem_state(
    files: Mapping[str, Any],
    *,
    layer_count: int,
    base_layer_count: int,
) -> FilesystemReplay:
    """Derive final filesystem state from OCI layer operations."""

    grouped: dict[str, list[list[Mapping[str, Any]]]] = {
        kind: [[] for _ in range(layer_count)]
        for kind in ("directory", "regular", "non-regular", "removal")
    }
    for kind, field in (
        ("directory", "directories"),
        ("regular", "regular_files"),
        ("non-regular", "non_regular_files"),
        ("removal", "whiteouts"),
    ):
        records = files[field]
        assert isinstance(records, list)
        for record in records:
            assert isinstance(record, dict)
            grouped[kind][int(record["layer"])].append(record)

    state: dict[str, dict[str, Any]] = {}
    directory_effects: list[Mapping[str, Any]] = []
    removals: list[Mapping[str, Any]] = []
    replay_operations = 0

    def spend_operations(count: int) -> None:
        nonlocal replay_operations
        replay_operations += count
        if replay_operations > MAX_FILESYSTEM_REPLAY_OPERATIONS:
            raise VerificationError("all-layer filesystem replay exceeds its work budget")

    def check_state_budget() -> None:
        if len(state) > MAX_FILESYSTEM_STATE_ENTRIES:
            raise VerificationError("all-layer filesystem replay exceeds its state budget")

    def remove_state(target: str) -> None:
        existing = state.pop(target, None)
        if existing is None or existing["kind"] != "directory":
            return
        spend_operations(len(state))
        prefix = f"{target}/"
        for candidate in list(state):
            if candidate.startswith(prefix):
                state.pop(candidate, None)

    def ensure_parents(path: PurePosixPath, *, allow_implicit: bool) -> None:
        parents = [parent for parent in path.parents if str(parent) != "."]
        for parent in reversed(parents):
            parent_text = str(parent)
            existing = state.get(parent_text)
            if existing is not None and existing["kind"] != "directory":
                raise VerificationError(
                    "all-layer entry traverses a non-directory ancestor during replay: "
                    f"{path} through {parent_text}"
                )
            if existing is None:
                if not allow_implicit:
                    raise VerificationError(
                        "post-base all-layer entry has an implicit parent directory: "
                        f"{path} through {parent_text}"
                    )
                state[parent_text] = {
                    "implicit": True,
                    "kind": "directory",
                    "layer": -1,
                }
                check_state_budget()

    for layer_index in range(layer_count):
        current_directories = {str(record["path"]) for record in grouped["directory"][layer_index]}
        layer_removals: list[Mapping[str, Any]] = []
        for marker in grouped["removal"][layer_index]:
            kind = str(marker["kind"])
            path = str(marker["path"])
            target = str(marker["target"])
            parent = PurePosixPath(path).parent
            for ancestor in (parent, *parent.parents):
                ancestor_text = str(ancestor)
                if ancestor_text == ".":
                    continue
                existing = state.get(ancestor_text)
                if (
                    existing is not None
                    and existing["kind"] != "directory"
                    and ancestor_text not in current_directories
                ):
                    raise VerificationError(
                        "all-layer whiteout traverses a non-directory ancestor: "
                        f"{path} through {ancestor_text}"
                    )
            if kind == "whiteout":
                if target not in state:
                    raise VerificationError(
                        f"all-layer whiteout target is absent from lower layers: {target}"
                    )
            else:
                prefix = "" if target == "." else f"{target}/"
                spend_operations(len(state))
                if not any(candidate.startswith(prefix) for candidate in state):
                    raise VerificationError(
                        f"all-layer opaque whiteout removes no lower-layer entries: {target}"
                    )
            layer_removals.append(
                {
                    "kind": kind,
                    "path": path,
                    "target": target,
                }
            )

        for removal in layer_removals:
            target = str(removal["target"])
            if removal["kind"] == "opaque":
                prefix = "" if target == "." else f"{target}/"
                spend_operations(len(state))
                for candidate in list(state):
                    if candidate.startswith(prefix):
                        state.pop(candidate, None)
            else:
                remove_state(target)
            if layer_index >= base_layer_count:
                removals.append(removal)

        normalized: list[tuple[str, PurePosixPath, Mapping[str, Any]]] = []
        non_directory_paths: set[str] = set()
        for kind in ("directory", "regular", "non-regular"):
            for record in grouped[kind][layer_index]:
                ordinary_path = PurePosixPath(str(record["path"]))
                actual_kind = str(record["kind"]) if kind == "non-regular" else kind
                normalized.append((actual_kind, ordinary_path, record))
                if actual_kind != "directory":
                    non_directory_paths.add(str(ordinary_path))
        for _kind, ordinary_path, _record in normalized:
            if any(str(parent) in non_directory_paths for parent in ordinary_path.parents):
                raise VerificationError(
                    "one all-layer layer contains a non-directory ancestor and descendant: "
                    f"{ordinary_path}"
                )

        directories = sorted(
            (item for item in normalized if item[0] == "directory"),
            key=lambda item: (len(item[1].parts), str(item[1])),
        )
        for _kind, directory_path, record in directories:
            ensure_parents(directory_path, allow_implicit=layer_index < base_layer_count)
            path_text = str(directory_path)
            metadata = {
                "mode": int(record["mode"]),
                "uid": int(record["uid"]),
                "gid": int(record["gid"]),
            }
            if layer_index >= base_layer_count and (
                metadata["mode"] not in {0o555, 0o755}
                or metadata["uid"] != 0
                or metadata["gid"] != 0
            ):
                raise VerificationError(
                    "post-base directories must be root-owned with mode 0o0555 or 0o0755"
                )
            existing = state.get(path_text)
            is_noop = existing is not None and {
                field: existing.get(field) for field in ("kind", "mode", "uid", "gid")
            } == {"kind": "directory", **metadata}
            if existing is not None and existing["kind"] != "directory":
                remove_state(path_text)
            state[path_text] = {
                "kind": "directory",
                "layer": layer_index,
                **metadata,
            }
            check_state_budget()
            if layer_index >= base_layer_count and not is_noop:
                directory_effects.append(
                    {
                        "layer": layer_index,
                        "path": path_text,
                        **metadata,
                    }
                )

        for kind, ordinary_path, _record in sorted(
            (item for item in normalized if item[0] != "directory"),
            key=lambda item: str(item[1]),
        ):
            ensure_parents(ordinary_path, allow_implicit=layer_index < base_layer_count)
            path_text = str(ordinary_path)
            remove_state(path_text)
            state[path_text] = {
                "kind": kind,
                "layer": layer_index,
            }
            check_state_budget()

    for record in files["regular_files"]:
        path = str(record["path"])
        current = state.get(path)
        derived = (
            current is not None
            and current["kind"] == "regular"
            and current["layer"] == record["layer"]
        )
        if record["effective"] is not derived:
            raise VerificationError(f"all-layer regular file has a false effective state: {path}")
    for record in files["directories"]:
        path = str(record["path"])
        current = state.get(path)
        derived = (
            current is not None
            and current["kind"] == "directory"
            and current["layer"] == record["layer"]
        )
        if record["effective"] is not derived:
            raise VerificationError(f"all-layer directory has a false effective state: {path}")

    removal_identities = [
        (str(record["path"]), str(record["kind"]), str(record["target"])) for record in removals
    ]
    if len(removal_identities) != len(set(removal_identities)):
        raise VerificationError("post-base all-layer removals are not unique")
    return FilesystemReplay(
        effective={
            path: (str(record["kind"]), int(record["layer"])) for path, record in state.items()
        },
        directory_effects=tuple(
            sorted(
                directory_effects,
                key=lambda record: (int(record["layer"]), str(record["path"])),
            )
        ),
        removals=tuple(
            sorted(
                removals,
                key=lambda record: (
                    str(record["path"]),
                    str(record["kind"]),
                    str(record["target"]),
                ),
            )
        ),
    )


def _verify_filesystem_baseline(
    files: Mapping[str, Any],
    policy: Mapping[str, Any],
    expected: ExpectedIdentity,
    replay: FilesystemReplay,
    *,
    base_layer_count: int,
) -> None:
    """Recompute and compare every selected-platform filesystem baseline."""

    baseline = policy["filesystem_baselines"][expected.platform]

    def occurrence(record: Mapping[str, Any]) -> dict[str, Any]:
        return {field: record[field] for field in REGULAR_OCCURRENCE_FIELDS}

    regular = files["regular_files"]
    non_regular = files["non_regular_files"]
    assert isinstance(regular, list)
    assert isinstance(non_regular, list)
    observed: dict[str, list[Mapping[str, Any]]] = {
        "apk_database_occurrences": sorted(
            (occurrence(record) for record in regular if record["path"] == "lib/apk/db/installed"),
            key=lambda record: (int(record["layer"]), str(record["path"])),
        ),
        "post_base_apk_world_occurrences": sorted(
            (
                occurrence(record)
                for record in regular
                if record["layer"] >= base_layer_count and record["path"] == APK_WORLD_PATH
            ),
            key=lambda record: (int(record["layer"]), str(record["path"])),
        ),
        "post_base_directory_effects": list(replay.directory_effects),
        "post_base_removals": list(replay.removals),
        "post_base_system_links": sorted(
            (
                {
                    field: record[field]
                    for field in ("gid", "kind", "layer", "mode", "path", "target", "uid")
                }
                for record in non_regular
                if record["layer"] >= base_layer_count
                and record["path"] in POST_BASE_SYSTEM_LINK_PATHS
            ),
            key=lambda record: (int(record["layer"]), str(record["path"])),
        ),
        "post_base_system_regular_occurrences": sorted(
            (
                occurrence(record)
                for record in regular
                if record["layer"] >= base_layer_count
                and record["path"] in POST_BASE_SYSTEM_REGULAR_MODES
            ),
            key=lambda record: (int(record["layer"]), str(record["path"])),
        ),
    }
    for record in observed["post_base_apk_world_occurrences"]:
        if record["mode"] != 0o644 or record["uid"] != 0 or record["gid"] != 0:
            raise VerificationError("post-base APK world files must be root-owned with mode 0o0644")
    for record in observed["post_base_system_regular_occurrences"]:
        if (
            record["effective"] is not True
            or record["mode"] != POST_BASE_SYSTEM_REGULAR_MODES[str(record["path"])]
            or record["uid"] != 0
            or record["gid"] != 0
        ):
            raise VerificationError("post-base system regular-file state is invalid")
    for record in observed["post_base_system_links"]:
        if (
            record["kind"] != "symlink"
            or record["mode"] != 0o777
            or record["uid"] != 0
            or record["gid"] != 0
        ):
            raise VerificationError("post-base system link state is invalid")
    for category, derived in observed.items():
        if baseline[category] != derived:
            raise VerificationError(f"container policy {category} differs from all-layer inventory")


def _validate_all_layer_inventory(
    value: Mapping[str, Any],
    expected: ExpectedIdentity,
    policy: Mapping[str, Any],
) -> tuple[
    dict[tuple[int, str], Mapping[str, Any]],
    dict[tuple[int, str], Mapping[str, Any]],
    set[tuple[int, str]],
]:
    """Validate every schema-9 layer record and its per-layer accounting."""

    files = _exact_mapping(value, ALL_LAYER_FIELDS, "all-layer inventory")
    _require_identity_record(files, "all-layer inventory", expected)
    _oci_digest(files["image_config_digest"], "all-layer inventory image config digest")

    layers = _bounded_list(
        files["layers"],
        "all-layer inventory layers",
        maximum=MAX_MEMBERS,
        nonempty=True,
    )
    layer_digests: list[str] = []
    layer_counts: list[tuple[int, int, int, int]] = []
    for expected_index, raw_layer in enumerate(layers):
        source = f"all-layer inventory layer {expected_index}"
        layer_record = _exact_mapping(raw_layer, LAYER_FIELDS, source)
        index = _integer(
            layer_record["index"],
            f"{source} index",
            minimum=0,
            maximum=MAX_MEMBERS,
        )
        digest = _oci_digest(layer_record["digest"], f"{source} digest")
        counts = (
            _integer(
                layer_record["regular_file_count"],
                f"{source} regular_file_count",
                minimum=0,
                maximum=MAX_MEMBERS,
            ),
            _integer(
                layer_record["directory_count"],
                f"{source} directory_count",
                minimum=0,
                maximum=MAX_MEMBERS,
            ),
            _integer(
                layer_record["non_regular_file_count"],
                f"{source} non_regular_file_count",
                minimum=0,
                maximum=MAX_MEMBERS,
            ),
            _integer(
                layer_record["whiteout_count"],
                f"{source} whiteout_count",
                minimum=0,
                maximum=MAX_MEMBERS,
            ),
        )
        if index != expected_index or digest in layer_digests:
            raise VerificationError("all-layer inventory layers are not uniquely sequential")
        layer_digests.append(digest)
        layer_counts.append(counts)

    all_occurrences: set[tuple[int, str]] = set()
    effective_paths: set[str] = set()
    observed_regular = [0] * len(layers)
    total_regular_size = 0
    regular_by_occurrence: dict[tuple[int, str], Mapping[str, Any]] = {}
    regular_files = _bounded_list(
        files["regular_files"],
        "all-layer inventory regular files",
        maximum=MAX_MEMBERS,
    )
    for index, raw_record in enumerate(regular_files):
        source = f"all-layer inventory regular file {index}"
        record = _exact_mapping(raw_record, ALL_LAYER_RECORD_FIELDS, source)
        occurrence = _validate_occurrence(
            {field: record[field] for field in REGULAR_OCCURRENCE_FIELDS},
            source,
        )
        layer_index = int(occurrence["layer"])
        path = str(occurrence["path"])
        key = (layer_index, path)
        if (
            layer_index >= len(layers)
            or record["layer_digest"] != layer_digests[layer_index]
            or key in all_occurrences
            or (occurrence["effective"] is True and path in effective_paths)
        ):
            raise VerificationError(f"{source} has a conflicting occurrence identity")
        all_occurrences.add(key)
        regular_by_occurrence[key] = occurrence
        if occurrence["effective"] is True:
            effective_paths.add(path)
        observed_regular[layer_index] += 1
        total_regular_size += int(occurrence["size"])
        if total_regular_size > MAX_EXPANDED_TAR_BYTES:
            raise VerificationError("all-layer inventory exceeds its cumulative byte limit")

    observed_directories = [0] * len(layers)
    directories = _bounded_list(
        files["directories"],
        "all-layer inventory directories",
        maximum=MAX_MEMBERS,
    )
    for index, raw_record in enumerate(directories):
        source = f"all-layer inventory directory {index}"
        record = _exact_mapping(raw_record, ALL_LAYER_DIRECTORY_FIELDS, source)
        layer_index = _integer(
            record["layer"],
            f"{source} layer",
            minimum=0,
            maximum=MAX_MEMBERS,
        )
        path = _bounded_text(record["path"], f"{source} path")
        checked_path(path)
        _boolean(record["effective"], f"{source} effective state")
        for field, maximum in (("mode", 0o7777), ("uid", 2**31 - 1), ("gid", 2**31 - 1)):
            _integer(record[field], f"{source} {field}", minimum=0, maximum=maximum)
        key = (layer_index, path)
        if (
            layer_index >= len(layers)
            or record["layer_digest"] != layer_digests[layer_index]
            or key in all_occurrences
        ):
            raise VerificationError(f"{source} has a conflicting occurrence identity")
        all_occurrences.add(key)
        observed_directories[layer_index] += 1

    observed_non_regular = [0] * len(layers)
    non_regular_by_occurrence: dict[tuple[int, str], Mapping[str, Any]] = {}
    non_regular = _bounded_list(
        files["non_regular_files"],
        "all-layer inventory non-regular files",
        maximum=MAX_MEMBERS,
    )
    for index, raw_record in enumerate(non_regular):
        source = f"all-layer inventory non-regular file {index}"
        if not isinstance(raw_record, dict):
            raise VerificationError(f"{source} is not an object")
        kind = raw_record.get("kind")
        fields = ALL_LAYER_HEADER_FIELDS | {"kind"}
        if isinstance(kind, str) and kind in {"hardlink", "symlink"}:
            fields.add("target")
        elif kind != "other":
            raise VerificationError(f"{source} has an invalid kind")
        record = _exact_mapping(raw_record, fields, source)
        layer_index = _integer(
            record["layer"],
            f"{source} layer",
            minimum=0,
            maximum=MAX_MEMBERS,
        )
        path = _bounded_text(record["path"], f"{source} path")
        checked_path(path)
        for field, maximum in (("mode", 0o7777), ("uid", 2**31 - 1), ("gid", 2**31 - 1)):
            _integer(record[field], f"{source} {field}", minimum=0, maximum=maximum)
        if kind in {"hardlink", "symlink"}:
            _checked_image_link_target(record["target"], f"{source} target")
        key = (layer_index, path)
        if (
            layer_index >= len(layers)
            or record["layer_digest"] != layer_digests[layer_index]
            or key in all_occurrences
        ):
            raise VerificationError(f"{source} has a conflicting occurrence identity")
        all_occurrences.add(key)
        non_regular_by_occurrence[key] = record
        observed_non_regular[layer_index] += 1

    observed_whiteouts = [0] * len(layers)
    whiteouts = _bounded_list(
        files["whiteouts"],
        "all-layer inventory whiteouts",
        maximum=MAX_MEMBERS,
    )
    for index, raw_record in enumerate(whiteouts):
        source = f"all-layer inventory whiteout {index}"
        record = _exact_mapping(
            raw_record,
            ALL_LAYER_HEADER_FIELDS | {"kind", "target"},
            source,
        )
        layer_index = _integer(
            record["layer"],
            f"{source} layer",
            minimum=0,
            maximum=MAX_MEMBERS,
        )
        path_value = _bounded_text(record["path"], f"{source} path")
        target_value = _bounded_text(record["target"], f"{source} target")
        path_obj = checked_path(path_value)
        kind = record["kind"]
        if kind == "opaque":
            valid_target = path_obj.name == ".wh..wh..opq" and target_value == str(path_obj.parent)
        elif kind == "whiteout":
            target_obj = checked_path(target_value)
            valid_target = (
                path_obj.name == f".wh.{target_obj.name}" and path_obj.parent == target_obj.parent
            )
        else:
            valid_target = False
        for field, maximum in (("mode", 0o7777), ("uid", 2**31 - 1), ("gid", 2**31 - 1)):
            _integer(record[field], f"{source} {field}", minimum=0, maximum=maximum)
        key = (layer_index, path_value)
        if (
            not valid_target
            or layer_index >= len(layers)
            or record["layer_digest"] != layer_digests[layer_index]
            or key in all_occurrences
        ):
            raise VerificationError(f"{source} has a conflicting occurrence identity")
        all_occurrences.add(key)
        observed_whiteouts[layer_index] += 1

    observed_counts = list(
        zip(
            observed_regular,
            observed_directories,
            observed_non_regular,
            observed_whiteouts,
            strict=True,
        )
    )
    if observed_counts != layer_counts:
        raise VerificationError("all-layer inventory counts do not match its occurrences")
    if len(all_occurrences) > MAX_MEMBERS:
        raise VerificationError("all-layer inventory exceeds its cumulative entry limit")
    base_layers = policy["base_image_platforms"][expected.platform]["layer_diff_ids"]
    assert isinstance(base_layers, list)
    if len(base_layers) > len(layer_digests) or layer_digests[: len(base_layers)] != base_layers:
        raise VerificationError(
            "all-layer inventory does not begin with the reviewed base-image layers"
        )
    replay = _replay_filesystem_state(
        files,
        layer_count=len(layers),
        base_layer_count=len(base_layers),
    )
    _verify_filesystem_baseline(
        files,
        policy,
        expected,
        replay,
        base_layer_count=len(base_layers),
    )
    effective_non_regular = {
        key
        for key, record in non_regular_by_occurrence.items()
        if replay.effective.get(key[1]) == (record["kind"], key[0])
    }
    return regular_by_occurrence, non_regular_by_occurrence, effective_non_regular


def _validate_component(
    value: object,
    source: str,
    *,
    platform: str,
    runtime_version: str,
    base_layer_count: int,
) -> tuple[str, str]:
    if not isinstance(value, dict):
        raise VerificationError(f"{source} is not an object")
    ecosystem = value.get("ecosystem")
    if ecosystem == "python":
        record = _exact_mapping(
            value,
            {
                "ecosystem",
                "name",
                "version",
                "observed_license",
                "effective",
                "metadata_sha256",
            },
            source,
        )
        name = _bounded_text(record["name"], f"{source} name", maximum=512)
        version = _bounded_text(record["version"], f"{source} version", maximum=512)
        if re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*", name) is None or any(
            character.isspace() for character in version
        ):
            raise VerificationError(f"{source} has a non-canonical Python identity")
        _digest(record["metadata_sha256"], f"{source} metadata digest")
    elif ecosystem == "alpine":
        record = _exact_mapping(
            value,
            {
                "aports_commit",
                "architecture",
                "ecosystem",
                "effective",
                "name",
                "observed_license",
                "origin",
                "version",
            },
            source,
        )
        name = _bounded_text(record["name"], f"{source} name", maximum=512)
        version = _bounded_text(record["version"], f"{source} version", maximum=512)
        origin = _bounded_text(record["origin"], f"{source} origin", maximum=512)
        expected_architecture = {
            "linux/amd64": "x86_64",
            "linux/arm64": "aarch64",
        }[platform]
        if (
            re.fullmatch(r"[a-z0-9][a-z0-9+_.-]*", name) is None
            or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9+_.~-]*", version) is None
            or re.fullmatch(r"[a-z0-9][a-z0-9+_.-]*", origin) is None
            or record["architecture"] != expected_architecture
            or not isinstance(record["aports_commit"], str)
            or HEX40.fullmatch(record["aports_commit"]) is None
        ):
            raise VerificationError(f"{source} has an invalid Alpine identity")
    elif ecosystem == "runtime":
        record = _exact_mapping(
            value,
            {
                "ecosystem",
                "effective",
                "identity_files",
                "name",
                "observed_license",
                "purl",
                "version",
            },
            source,
        )
        name = record["name"]
        version = record["version"]
        if (
            name != "cpython"
            or version != runtime_version
            or record["purl"] != f"pkg:generic/python@{runtime_version}"
            or record["observed_license"] != ""
            or record["effective"] is not True
        ):
            raise VerificationError(f"{source} has an invalid CPython identity")
        minor = runtime_version.rsplit(".", maxsplit=1)[0]
        identities = _exact_mapping(
            record["identity_files"],
            {"interpreter", "interpreter_link", "shared_library", "version_header"},
            f"{source} identity files",
        )
        expected_regular = {
            "interpreter": (f"usr/local/bin/python{minor}", 0o755),
            "shared_library": (f"usr/local/lib/libpython{minor}.so.1.0", 0o755),
            "version_header": (
                f"usr/local/include/python{minor}/patchlevel.h",
                0o644,
            ),
        }
        identity_layers: set[int] = set()
        for role, (expected_path, expected_mode) in expected_regular.items():
            raw_identity = identities[role]
            occurrence_value = (
                {key: raw_identity[key] for key in REGULAR_OCCURRENCE_FIELDS}
                if isinstance(raw_identity, dict) and set(raw_identity) >= REGULAR_OCCURRENCE_FIELDS
                else raw_identity
            )
            occurrence = _validate_occurrence(
                occurrence_value,
                f"{source} {role}",
            )
            expected_fields = (
                REGULAR_OCCURRENCE_FIELDS | {"elf"}
                if role != "version_header"
                else REGULAR_OCCURRENCE_FIELDS
            )
            _exact_mapping(raw_identity, expected_fields, f"{source} {role}")
            if (
                occurrence["effective"] is not True
                or occurrence["path"] != expected_path
                or occurrence["mode"] != expected_mode
                or occurrence["uid"] != 0
                or occurrence["gid"] != 0
            ):
                raise VerificationError(f"{source} has an invalid {role} identity")
            if role != "version_header":
                machine_id, machine = {
                    "linux/amd64": (62, "x86_64"),
                    "linux/arm64": (183, "aarch64"),
                }[platform]
                elf = _exact_mapping(
                    raw_identity["elf"],
                    {"bits", "endianness", "machine", "machine_id"},
                    f"{source} {role} ELF identity",
                )
                if elf != {
                    "bits": 64,
                    "endianness": "little",
                    "machine": machine,
                    "machine_id": machine_id,
                }:
                    raise VerificationError(f"{source} has the wrong {role} ELF identity")
            identity_layers.add(int(occurrence["layer"]))
        link = _exact_mapping(
            identities["interpreter_link"],
            {"effective", "gid", "kind", "layer", "mode", "path", "target", "uid"},
            f"{source} interpreter link",
        )
        link_layer = _integer(
            link["layer"],
            f"{source} interpreter link layer",
            minimum=0,
            maximum=MAX_MEMBERS,
        )
        if (
            link["effective"] is not True
            or link["kind"] != "symlink"
            or link["path"] != f"usr/local/bin/python{runtime_version.split('.')[0]}"
            or link["target"] != f"python{minor}"
            or link["mode"] != 0o777
            or link["uid"] != 0
            or link["gid"] != 0
        ):
            raise VerificationError(f"{source} has an invalid interpreter link identity")
        checked_path(str(link["path"]))
        identity_layers.add(link_layer)
        if (
            len(identity_layers) != 1
            or not identity_layers
            or next(iter(identity_layers)) >= base_layer_count
        ):
            raise VerificationError(f"{source} identities are outside one reviewed base layer")
    else:
        raise VerificationError(f"{source} has an unsupported component ecosystem")

    observed = record["observed_license"]
    _bounded_optional_text(observed, f"{source} observed license", maximum=16 * 1024)
    _boolean(record["effective"], f"{source} effective state")
    return f"{ecosystem}:{name}@{version}", str(ecosystem)


def _validate_component_list(
    value: object,
    source: str,
    *,
    platform: str,
    runtime_version: str,
    base_layer_count: int,
) -> tuple[list[Mapping[str, Any]], set[str]]:
    raw_components = _bounded_list(value, source, maximum=10_000, nonempty=True)
    records: list[Mapping[str, Any]] = []
    identities: list[str] = []
    sort_keys: list[tuple[str, str, str]] = []
    runtime_count = 0
    python_metadata: set[str] = set()
    effective_python_names: set[str] = set()
    for index, raw_component in enumerate(raw_components):
        identity, ecosystem = _validate_component(
            raw_component,
            f"{source} component {index}",
            platform=platform,
            runtime_version=runtime_version,
            base_layer_count=base_layer_count,
        )
        if not isinstance(raw_component, dict):
            raise VerificationError(f"{source} component {index} is not an object")
        records.append(raw_component)
        identities.append(identity)
        sort_keys.append(
            (
                str(raw_component["ecosystem"]),
                str(raw_component["name"]),
                str(raw_component["version"]),
            )
        )
        runtime_count += ecosystem == "runtime"
        if ecosystem == "python":
            metadata = str(raw_component["metadata_sha256"])
            name = str(raw_component["name"])
            if metadata in python_metadata or (
                raw_component["effective"] is True and name in effective_python_names
            ):
                raise VerificationError(f"{source} has conflicting Python components")
            python_metadata.add(metadata)
            if raw_component["effective"] is True:
                effective_python_names.add(name)
    if sort_keys != sorted(sort_keys) or len(identities) != len(set(identities)):
        raise VerificationError(f"{source} components are not uniquely sorted")
    if runtime_count != 1:
        raise VerificationError(f"{source} must contain exactly one CPython runtime")
    return records, set(identities)


def _validate_artifact_pin(value: object, source: str) -> Mapping[str, Any]:
    record = _exact_mapping(value, {"sha256", "size", "url"}, source)
    url = _https_url(record["url"], f"{source} URL")
    if url != record["url"]:
        raise VerificationError(f"{source} URL is not canonical")
    _digest(record["sha256"], f"{source} digest")
    _integer(
        record["size"],
        f"{source} size",
        minimum=0,
        maximum=MAX_LARGE_SOURCE_BYTES,
    )
    return record


def _validate_notice_pin(value: object, source: str) -> Mapping[str, Any]:
    record = _exact_mapping(value, {"member", "sha256", "size"}, source)
    member = _bounded_text(record["member"], f"{source} member")
    checked_path(member)
    _digest(record["sha256"], f"{source} digest")
    _integer(
        record["size"],
        f"{source} size",
        minimum=0,
        maximum=MAX_MEMBER_BYTES,
    )
    return record


def _validate_native_source(
    source_id: str,
    value: object,
) -> tuple[list[Mapping[str, Any]], list[Mapping[str, Any]]]:
    source = f"native-component source {source_id}"
    if not isinstance(value, dict):
        raise VerificationError(f"{source} is not an object")
    kind = value.get("kind")
    artifact_pins: list[Mapping[str, Any]] = []
    if kind == "alpine-aports":
        record = _exact_mapping(
            value,
            {
                "allowed_recipe_links",
                "aports_commit",
                "distfiles",
                "distfiles_release",
                "kind",
                "notices",
                "observed_license",
                "origin",
                "recipe",
                "version",
            },
            source,
        )
        origin = _bounded_text(record["origin"], f"{source} origin", maximum=512)
        version = _bounded_text(record["version"], f"{source} version", maximum=512)
        if (
            source_id != f"alpine:{origin}@{version}"
            or not isinstance(record["aports_commit"], str)
            or HEX40.fullmatch(record["aports_commit"]) is None
            or not isinstance(record["distfiles_release"], str)
            or re.fullmatch(r"v[0-9]+\.[0-9]+", record["distfiles_release"]) is None
        ):
            raise VerificationError(f"{source} has an invalid identity")
        _bounded_text(
            record["observed_license"],
            f"{source} observed license",
            maximum=16 * 1024,
        )
        artifact_pins.append(_validate_artifact_pin(record["recipe"], f"{source} recipe"))
        filenames: list[str] = []
        for index, item in enumerate(
            _bounded_list(record["distfiles"], f"{source} distfiles", maximum=10_000)
        ):
            distfile = _exact_mapping(
                item,
                {"filename", "sha512", "size", "url"},
                f"{source} distfile {index}",
            )
            filename = _bounded_text(
                distfile["filename"],
                f"{source} distfile {index} filename",
            )
            if len(checked_path(filename).parts) != 1:
                raise VerificationError(f"{source} distfile {index} filename is invalid")
            _https_url(distfile["url"], f"{source} distfile {index} URL")
            if (
                not isinstance(distfile["sha512"], str)
                or HEX128.fullmatch(distfile["sha512"]) is None
            ):
                raise VerificationError(f"{source} distfile {index} has an invalid SHA-512")
            _integer(
                distfile["size"],
                f"{source} distfile {index} size",
                minimum=0,
                maximum=MAX_LARGE_SOURCE_BYTES,
            )
            filenames.append(filename)
            artifact_pins.append(distfile)
        if filenames != sorted(filenames) or len(filenames) != len(set(filenames)):
            raise VerificationError(f"{source} distfiles are not uniquely sorted")
        seen_links: set[str] = set()
        for index, item in enumerate(
            _bounded_list(
                record["allowed_recipe_links"],
                f"{source} allowed recipe links",
                maximum=10_000,
            )
        ):
            link = _exact_mapping(
                item,
                {"path", "target", "type"},
                f"{source} allowed recipe link {index}",
            )
            path = _bounded_text(link["path"], f"{source} allowed recipe link {index} path")
            target = _bounded_text(
                link["target"],
                f"{source} allowed recipe link {index} target",
            )
            if (
                str(checked_path(path)) != path
                or str(checked_path(target)) != target
                or PurePosixPath(path).parent != PurePosixPath(target).parent
                or path == target
                or link["type"] not in {"symlink", "hardlink"}
                or path in seen_links
            ):
                raise VerificationError(f"{source} has an invalid allowed recipe link")
            seen_links.add(path)
    elif kind == "crates-io":
        record = _exact_mapping(
            value,
            {
                "crate",
                "kind",
                "manifest",
                "name",
                "normalized_license",
                "notices",
                "raw_license",
                "version",
            },
            source,
        )
        name = _bounded_text(record["name"], f"{source} name", maximum=512)
        version = _bounded_text(record["version"], f"{source} version", maximum=512)
        if source_id != f"crates-io:{name}@{version}":
            raise VerificationError(f"{source} has an invalid identity")
        artifact_pins.append(_validate_artifact_pin(record["crate"], f"{source} crate"))
        _validate_notice_pin(record["manifest"], f"{source} manifest")
        _bounded_text(record["raw_license"], f"{source} raw license", maximum=16 * 1024)
        _bounded_text(
            record["normalized_license"],
            f"{source} normalized license",
            maximum=16 * 1024,
        )
    elif kind == "owner-sdist-subpath":
        record = _exact_mapping(
            value,
            {
                "cargo_packages",
                "expanded_size",
                "kind",
                "member_count",
                "notices",
                "owner",
                "path",
                "reviewed_license",
                "tree_sha256",
                "workspace_manifest",
            },
            source,
        )
        owner = _bounded_text(record["owner"], f"{source} owner", maximum=1056)
        path = _bounded_text(record["path"], f"{source} path")
        if (
            source_id != f"owner-sdist:{owner}#{path}"
            or re.fullmatch(r"python:[a-z0-9-]+@[^/@#]+", owner) is None
            or (path != "." and str(checked_path(path)) != path)
        ):
            raise VerificationError(f"{source} has an invalid identity")
        _digest(record["tree_sha256"], f"{source} tree digest")
        _integer(
            record["member_count"],
            f"{source} member count",
            minimum=1,
            maximum=MAX_MEMBERS,
        )
        _integer(
            record["expanded_size"],
            f"{source} expanded size",
            minimum=1,
            maximum=4 * MAX_LARGE_SOURCE_BYTES,
        )
        _bounded_text(
            record["reviewed_license"],
            f"{source} reviewed license",
            maximum=16 * 1024,
        )
        _validate_notice_pin(record["workspace_manifest"], f"{source} workspace manifest")
        package_identities: list[tuple[str, str, str]] = []
        for index, item in enumerate(
            _bounded_list(
                record["cargo_packages"],
                f"{source} Cargo packages",
                maximum=10_000,
                nonempty=True,
            )
        ):
            package = _exact_mapping(
                item,
                {"manifest", "name", "path", "version"},
                f"{source} Cargo package {index}",
            )
            name = _bounded_text(
                package["name"],
                f"{source} Cargo package {index} name",
                maximum=512,
            )
            version = _bounded_text(
                package["version"],
                f"{source} Cargo package {index} version",
                maximum=512,
            )
            package_path = _bounded_text(
                package["path"],
                f"{source} Cargo package {index} path",
            )
            if package_path != ".":
                checked_path(package_path)
            _validate_notice_pin(
                package["manifest"],
                f"{source} Cargo package {index} manifest",
            )
            package_identities.append((package_path, name, version))
        if package_identities != sorted(package_identities) or len(package_identities) != len(
            set(package_identities)
        ):
            raise VerificationError(f"{source} Cargo packages are not uniquely sorted")
    elif kind == "checksummed-upstream-release":
        record = _exact_mapping(
            value,
            {
                "archive",
                "checksum_document",
                "checksum_filename",
                "kind",
                "name",
                "notices",
                "reviewed_license",
                "version",
            },
            source,
        )
        name = _bounded_text(record["name"], f"{source} name", maximum=512)
        version = _bounded_text(record["version"], f"{source} version", maximum=512)
        if source_id != f"upstream-release:{name}@{version}":
            raise VerificationError(f"{source} has an invalid identity")
        archive = _validate_artifact_pin(record["archive"], f"{source} archive")
        artifact_pins.append(archive)
        artifact_pins.append(
            _validate_artifact_pin(
                record["checksum_document"],
                f"{source} checksum document",
            )
        )
        checksum_filename = _bounded_text(
            record["checksum_filename"],
            f"{source} checksum filename",
        )
        if (
            len(checked_path(checksum_filename).parts) != 1
            or PurePosixPath(str(archive["url"])).name != checksum_filename
        ):
            raise VerificationError(f"{source} checksum filename is invalid")
        _bounded_text(
            record["reviewed_license"],
            f"{source} reviewed license",
            maximum=16 * 1024,
        )
    else:
        raise VerificationError(f"{source} has an unsupported kind")

    notices: list[Mapping[str, Any]] = []
    notice_identities: list[tuple[str, str]] = []
    for index, item in enumerate(
        _bounded_list(record["notices"], f"{source} notices", maximum=10_000)
    ):
        notice = _validate_notice_pin(item, f"{source} notice {index}")
        notices.append(notice)
        notice_identities.append((str(notice["member"]), str(notice["sha256"])))
    if notice_identities != sorted(notice_identities) or len(notice_identities) != len(
        set(notice_identities)
    ):
        raise VerificationError(f"{source} notices are not uniquely sorted")
    return artifact_pins, notices


ObservationReference = tuple[str, str, str, str, str]


def _validate_observation_json(value: object, source: str) -> None:
    stack: list[tuple[object, str]] = [(value, source)]
    while stack:
        item, item_source = stack.pop()
        if item is None or isinstance(item, (bool, int)):
            continue
        if isinstance(item, str):
            if len(item.encode("utf-8")) > 16 * 1024 or any(
                (ord(character) < 32 and character not in "\t\n\r")
                or 0x7F <= ord(character) <= 0x9F
                for character in item
            ):
                raise VerificationError(f"{item_source} has invalid text")
            continue
        if isinstance(item, list):
            if len(item) > 16:
                raise VerificationError(f"{item_source} has too many values")
            stack.extend(
                (child, f"{item_source} value {index}") for index, child in enumerate(item)
            )
            continue
        if isinstance(item, dict):
            if len(item) > 16:
                raise VerificationError(f"{item_source} has too many fields")
            for key, child in item.items():
                _bounded_text(key, f"{item_source} key", maximum=512)
                stack.append((child, f"{item_source}.{key}"))
            continue
        raise VerificationError(f"{item_source} has an unsupported JSON value")


def _validate_observation_component(
    value: object,
    source: str,
) -> Mapping[str, Any]:
    record = _exact_mapping(
        value,
        {"bom_ref", "hashes", "licenses", "name", "purl", "type", "version"},
        source,
    )
    component_type = _bounded_text(record["type"], f"{source} type", maximum=64)
    _bounded_text(record["name"], f"{source} name", maximum=512)
    _bounded_optional_text(record["version"], f"{source} version", maximum=512)
    purl = _bounded_text(record["purl"], f"{source} purl", maximum=16 * 1024)
    _bounded_optional_text(
        record["bom_ref"],
        f"{source} bom-ref",
        maximum=16 * 1024,
    )
    if component_type not in CYCLONEDX_COMPONENT_TYPES or PACKAGE_URL.fullmatch(purl) is None:
        raise VerificationError(f"{source} has an invalid CycloneDX identity")

    hashes: list[tuple[str, str]] = []
    for index, item in enumerate(_bounded_list(record["hashes"], f"{source} hashes", maximum=16)):
        hashed = _exact_mapping(item, {"alg", "content"}, f"{source} hash {index}")
        algorithm = _bounded_text(
            hashed["alg"],
            f"{source} hash {index} algorithm",
            maximum=128,
        )
        content = _bounded_text(
            hashed["content"],
            f"{source} hash {index} content",
            maximum=16 * 1024,
        )
        if re.fullmatch(r"[0-9A-Fa-f]+", content) is None or len(content) % 2:
            raise VerificationError(f"{source} hash {index} is invalid")
        hashes.append((algorithm, content))
    if hashes != sorted(hashes) or len({algorithm.casefold() for algorithm, _ in hashes}) != len(
        hashes
    ):
        raise VerificationError(f"{source} hashes are not canonical")

    license_keys: list[bytes] = []
    for index, item in enumerate(
        _bounded_list(record["licenses"], f"{source} licenses", maximum=16)
    ):
        if not isinstance(item, dict):
            raise VerificationError(f"{source} license {index} is not an object")
        _validate_observation_json(item, f"{source} license {index}")
        encoded = canonical_json(item)
        if len(encoded) > 16 * 1024:
            raise VerificationError(f"{source} license {index} is too large")
        license_keys.append(encoded)
    if license_keys != sorted(license_keys) or len(license_keys) != len(set(license_keys)):
        raise VerificationError(f"{source} licenses are not canonical")
    return record


def _observation_sort_key(component: Mapping[str, Any]) -> tuple[object, ...]:
    identity_kind = "bom-ref" if component["bom_ref"] else "purl"
    identity = component["bom_ref"] or component["purl"]
    return (
        component["purl"],
        identity_kind,
        identity,
        component["type"],
        component["name"],
        component["version"],
        canonical_json(component["hashes"]),
        canonical_json(component["licenses"]),
    )


def _validate_observation_reference(
    value: object,
    source: str,
) -> ObservationReference:
    if not isinstance(value, dict):
        raise VerificationError(f"{source} is not an object")
    identity_kind = value.get("identity_kind")
    fields = {"identity_kind", "observation_sha256", "purl", "sbom_path"}
    if identity_kind == "bom-ref":
        fields.add("bom_ref")
    elif identity_kind != "purl":
        raise VerificationError(f"{source} has an invalid identity kind")
    record = _exact_mapping(value, fields, source)
    sbom_path = _bounded_text(record["sbom_path"], f"{source} SBOM path")
    if str(checked_path(sbom_path)) != sbom_path or ".dist-info/sboms/" not in sbom_path:
        raise VerificationError(f"{source} has an invalid SBOM path")
    observation_sha256 = _digest(
        record["observation_sha256"],
        f"{source} observation digest",
    )
    purl = _bounded_text(record["purl"], f"{source} purl", maximum=16 * 1024)
    if PACKAGE_URL.fullmatch(purl) is None:
        raise VerificationError(f"{source} has an invalid purl")
    identity = purl
    if identity_kind == "bom-ref":
        identity = _bounded_text(
            record["bom_ref"],
            f"{source} bom-ref",
            maximum=16 * 1024,
        )
    return sbom_path, observation_sha256, str(identity_kind), identity, purl


def _validate_observation_references(
    value: object,
    source: str,
    *,
    allow_empty: bool = False,
) -> list[ObservationReference]:
    references = [
        _validate_observation_reference(item, f"{source} reference {index}")
        for index, item in enumerate(
            _bounded_list(
                value,
                source,
                maximum=10_000,
                nonempty=not allow_empty,
            )
        )
    ]
    if references != sorted(references) or len(references) != len(set(references)):
        raise VerificationError(f"{source} references are not canonical")
    return references


def _component_reference(
    *,
    sbom_path: str,
    observation_sha256: str,
    component: Mapping[str, Any],
) -> ObservationReference:
    identity_kind = "bom-ref" if component["bom_ref"] else "purl"
    identity = str(component["bom_ref"] or component["purl"])
    return (
        sbom_path,
        observation_sha256,
        identity_kind,
        identity,
        str(component["purl"]),
    )


def _validate_retained_cyclonedx_identity(
    value: object,
    source: str,
) -> Mapping[str, Any]:
    record = _exact_mapping(
        value,
        {
            "bom_format",
            "components",
            "metadata_component",
            "metadata_root_echo",
            "observation_sha256",
            "spec_version",
            "upstream_invalid_duplicate_bom_ref",
        },
        source,
    )
    if record["bom_format"] != "CycloneDX" or record["spec_version"] not in {
        "1.4",
        "1.5",
        "1.6",
    }:
        raise VerificationError(f"{source} has an invalid CycloneDX format")
    raw_metadata = record["metadata_component"]
    metadata = (
        None
        if raw_metadata is None
        else _validate_observation_component(raw_metadata, f"{source} metadata component")
    )
    components = [
        _validate_observation_component(item, f"{source} component {index}")
        for index, item in enumerate(
            _bounded_list(
                record["components"],
                f"{source} components",
                maximum=10_000,
            )
        )
    ]
    if components != sorted(components, key=_observation_sort_key):
        raise VerificationError(f"{source} components are not canonical")
    identities: list[tuple[str, str]] = []
    for component in components:
        identities.append(
            (
                "bom-ref" if component["bom_ref"] else "purl",
                str(component["bom_ref"] or component["purl"]),
            )
        )
        if metadata is not None and component["purl"] == metadata["purl"]:
            raise VerificationError(f"{source} repeats its metadata component")
    if len(identities) != len(set(identities)):
        raise VerificationError(f"{source} has ambiguous component identities")

    raw_echo = record["metadata_root_echo"]
    echo = (
        None
        if raw_echo is None
        else _validate_observation_component(raw_echo, f"{source} metadata root echo")
    )
    upstream_duplicate = _boolean(
        record["upstream_invalid_duplicate_bom_ref"],
        f"{source} duplicate-bom-ref state",
    )
    if echo is None:
        if upstream_duplicate:
            raise VerificationError(f"{source} has an invalid metadata-root echo state")
    elif metadata is None or echo != metadata or not upstream_duplicate:
        raise VerificationError(f"{source} has an invalid metadata-root echo")
    expected_digest = hashlib.sha256(
        canonical_json(
            {
                "components": record["components"],
                "metadata_component": record["metadata_component"],
                "metadata_root_echo": record["metadata_root_echo"],
                "upstream_invalid_duplicate_bom_ref": upstream_duplicate,
            }
        )
    ).hexdigest()
    if record["observation_sha256"] != expected_digest:
        raise VerificationError(f"{source} observation digest is invalid")
    return record


def _validate_historical_installations(
    value: object,
    components: Sequence[Mapping[str, Any]],
    regular_by_occurrence: Mapping[tuple[int, str], Mapping[str, Any]],
) -> tuple[
    dict[tuple[int, str, str], str],
    dict[tuple[int, str, str], str],
    dict[str, list[Mapping[str, Any]]],
]:
    installations = _bounded_list(
        value,
        "component inventory wheel installations",
        maximum=MAX_MEMBERS,
    )
    python_components = {
        f"python:{component['name']}@{component['version']}": component
        for component in components
        if component["ecosystem"] == "python"
    }
    occurrence_owners: dict[tuple[int, str, str], str] = {}
    effective_occurrence_owners: dict[tuple[int, str, str], str] = {}
    installations_by_owner: dict[str, list[Mapping[str, Any]]] = {}
    ordering: list[tuple[int, str]] = []
    seen_records: set[tuple[int, str]] = set()
    total_entries = 0
    active_owners: set[str] = set()
    for index, raw_installation in enumerate(installations):
        source = f"component inventory wheel installation {index}"
        installation = _exact_mapping(
            raw_installation,
            {
                "build",
                "entries",
                "metadata",
                "owner",
                "record",
                "root_is_purelib",
                "tags",
                "wheel",
            },
            source,
        )
        owner = _bounded_text(installation["owner"], f"{source} owner", maximum=1056)
        component = python_components.get(owner)
        if component is None:
            raise VerificationError(f"{source} has an unknown owner")
        _boolean(installation["root_is_purelib"], f"{source} purelib state")
        build = _bounded_optional_text(installation["build"], f"{source} build", maximum=512)
        if build and re.fullmatch(r"[0-9]+[A-Za-z0-9_.]*", build) is None:
            raise VerificationError(f"{source} has an invalid build tag")
        tags = _bounded_list(
            installation["tags"],
            f"{source} tags",
            maximum=100,
            nonempty=True,
        )
        if (
            not all(isinstance(tag, str) and WHEEL_TAG.fullmatch(tag) for tag in tags)
            or tags != sorted(tags)
            or len(tags) != len(set(tags))
        ):
            raise VerificationError(f"{source} has invalid wheel tags")

        identities: dict[str, Mapping[str, Any]] = {}
        for field in ("metadata", "wheel", "record"):
            occurrence = _validate_occurrence(
                installation[field],
                f"{source} {field}",
            )
            key = (int(occurrence["layer"]), str(occurrence["path"]))
            if regular_by_occurrence.get(key) != occurrence:
                raise VerificationError(f"{source} {field} differs from all-layer inventory")
            identities[field] = occurrence
        record = identities["record"]
        record_key = (int(record["layer"]), str(record["path"]))
        record_path = str(record["path"])
        if (
            record_key in seen_records
            or not record_path.endswith(".dist-info/RECORD")
            or "/site-packages/" not in record_path
        ):
            raise VerificationError(f"{source} has an invalid RECORD identity")
        seen_records.add(record_key)
        ordering.append(record_key)
        dist_info = PurePosixPath(record_path).parent
        metadata_path = (dist_info / "METADATA").as_posix()
        wheel_path = (dist_info / "WHEEL").as_posix()
        if (
            identities["metadata"]["path"] != metadata_path
            or identities["wheel"]["path"] != wheel_path
            or identities["metadata"]["sha256"] != component["metadata_sha256"]
        ):
            raise VerificationError(f"{source} has conflicting identity files")
        if record["effective"] is True:
            if owner in active_owners or component["effective"] is not True:
                raise VerificationError(f"{source} repeats or contradicts an active owner")
            active_owners.add(owner)
            if any(identities[field]["effective"] is not True for field in ("metadata", "wheel")):
                raise VerificationError(f"{source} has ineffective active identity files")

        entries = _bounded_list(
            installation["entries"],
            f"{source} entries",
            maximum=250_000,
            nonempty=True,
        )
        total_entries += len(entries)
        if total_entries > 250_000:
            raise VerificationError("component inventory wheel entries exceed their limit")
        entry_paths: list[str] = []
        entry_occurrences: dict[str, Mapping[str, Any]] = {}
        for entry_index, raw_entry in enumerate(entries):
            entry_source = f"{source} entry {entry_index}"
            entry = _exact_mapping(
                raw_entry,
                {"occurrence", "path", "recorded_sha256", "recorded_size"},
                entry_source,
            )
            path = _bounded_text(entry["path"], f"{entry_source} path")
            if str(checked_path(path)) != path or not path.startswith("opt/venv/"):
                raise VerificationError(f"{entry_source} has an invalid path")
            occurrence = _validate_occurrence(entry["occurrence"], f"{entry_source} occurrence")
            occurrence_key = (int(occurrence["layer"]), path)
            if (
                occurrence["path"] != path
                or regular_by_occurrence.get(occurrence_key) != occurrence
                or path in entry_occurrences
            ):
                raise VerificationError(f"{entry_source} differs from all-layer inventory")
            recorded_sha256 = entry["recorded_sha256"]
            recorded_size = entry["recorded_size"]
            if path == record_path:
                if recorded_sha256 is not None or recorded_size is not None:
                    raise VerificationError(f"{entry_source} gives RECORD a self-identity")
            elif recorded_sha256 != occurrence["sha256"] or recorded_size != occurrence["size"]:
                raise VerificationError(f"{entry_source} has a conflicting recorded identity")
            identity = (int(occurrence["layer"]), path, str(occurrence["sha256"]))
            previous_owner = occurrence_owners.get(identity)
            if previous_owner is not None and previous_owner != owner:
                raise VerificationError(f"{entry_source} has a conflicting owner")
            occurrence_owners[identity] = owner
            if record["effective"] is True:
                if occurrence["effective"] is not True:
                    raise VerificationError(f"{entry_source} is ineffective under an active RECORD")
                effective_occurrence_owners[identity] = owner
            entry_paths.append(path)
            entry_occurrences[path] = occurrence
        if (
            entry_paths != sorted(entry_paths)
            or not {metadata_path, wheel_path, record_path} <= set(entry_paths)
            or any(
                entry_occurrences[path] != identities[field]
                for field, path in (
                    ("metadata", metadata_path),
                    ("wheel", wheel_path),
                    ("record", record_path),
                )
            )
        ):
            raise VerificationError(f"{source} entries do not bind its identity files")
        assert isinstance(raw_installation, dict)
        installations_by_owner.setdefault(owner, []).append(raw_installation)
    if ordering != sorted(ordering):
        raise VerificationError("component inventory wheel installations are not canonical")
    return occurrence_owners, effective_occurrence_owners, installations_by_owner


def _validate_component_inventory_evidence(
    components: Mapping[str, Any],
    files: Mapping[str, Any],
    policy: Mapping[str, Any],
    expected: ExpectedIdentity,
) -> dict[str, list[Mapping[str, Any]]]:
    """Bind every component-evidence collection to layers and reviewed policy."""

    regular, non_regular, effective_non_regular = _validate_all_layer_inventory(
        files,
        expected,
        policy,
    )
    component_records = _bounded_list(
        components["components"],
        "component inventory components",
        maximum=10_000,
        nonempty=True,
    )
    if not all(isinstance(component, dict) for component in component_records):
        raise VerificationError("component inventory contains a non-object component")
    typed_components = [component for component in component_records if isinstance(component, dict)]

    def validate_occurrence_list(field: str) -> list[Mapping[str, Any]]:
        records: list[Mapping[str, Any]] = []
        seen: set[tuple[int, str]] = set()
        for index, item in enumerate(
            _bounded_list(
                components[field],
                f"component inventory {field}",
                maximum=250_000,
            )
        ):
            occurrence = _validate_occurrence(
                item,
                f"component inventory {field} {index}",
            )
            key = (int(occurrence["layer"]), str(occurrence["path"]))
            if key in seen or regular.get(key) != occurrence:
                raise VerificationError(
                    f"component inventory {field} differs from all-layer inventory"
                )
            seen.add(key)
            records.append(occurrence)
        return records

    apk_occurrences = validate_occurrence_list("apk_database_occurrences")
    wheel_identities = validate_occurrence_list("wheel_identity_files")
    expected_apk_occurrences = [
        record for record in regular.values() if record["path"] == "lib/apk/db/installed"
    ]
    expected_wheel_identities = sorted(
        (record for record in regular.values() if WHEEL_IDENTITY_FILE.search(str(record["path"]))),
        key=lambda record: (record["layer"], record["path"]),
    )
    if apk_occurrences != expected_apk_occurrences:
        raise VerificationError("component inventory omits or alters APK database occurrences")
    if wheel_identities != expected_wheel_identities:
        raise VerificationError("component inventory omits or alters wheel identity files")
    apk_digest = _digest(
        components["apk_database_sha256"],
        "component inventory APK database digest",
    )
    if (
        len(
            [
                record
                for record in apk_occurrences
                if record["effective"] is True and record["sha256"] == apk_digest
            ]
        )
        != 1
    ):
        raise VerificationError(
            "component inventory APK digest does not identify one effective occurrence"
        )

    occurrence_owners, effective_owners, installations_by_owner = (
        _validate_historical_installations(
            components["wheel_installations"],
            typed_components,
            regular,
        )
    )
    installation_records = _bounded_list(
        components["wheel_installations"],
        "component inventory wheel installations",
        maximum=MAX_MEMBERS,
    )
    observed_record_occurrences = {
        (int(installation["record"]["layer"]), str(installation["record"]["path"]))
        for installation in installation_records
    }
    expected_record_occurrences = {
        (int(record["layer"]), str(record["path"]))
        for record in wheel_identities
        if str(record["path"]).endswith(".dist-info/RECORD")
        and "/site-packages/" in str(record["path"])
    }
    if observed_record_occurrences != expected_record_occurrences:
        raise VerificationError("component inventory omits a historical Python RECORD installation")
    python_owners = {
        f"python:{component['name']}@{component['version']}": component
        for component in typed_components
        if component["ecosystem"] == "python"
    }
    active_installation_owners = {
        str(installation["owner"])
        for installation in installation_records
        if installation["record"]["effective"] is True
    }
    effective_component_owners = {
        owner for owner, component in python_owners.items() if component["effective"] is True
    }
    if active_installation_owners != effective_component_owners:
        raise VerificationError(
            "component inventory active Python installations differ from effective components"
        )
    machine_id, machine = {
        "linux/amd64": (62, "x86_64"),
        "linux/arm64": (183, "aarch64"),
    }[expected.platform]

    structured: dict[str, list[Mapping[str, Any]]] = {}
    for field, identity_field in (("embedded_sboms", "cyclonedx"), ("native_payloads", "elf")):
        records: list[Mapping[str, Any]] = []
        seen: set[tuple[int, str]] = set()
        for index, raw_record in enumerate(
            _bounded_list(
                components[field],
                f"component inventory {field}",
                maximum=250_000,
            )
        ):
            source = f"component inventory {field} {index}"
            record = _exact_mapping(
                raw_record,
                REGULAR_OCCURRENCE_FIELDS | {"owner", identity_field},
                source,
            )
            occurrence = _validate_occurrence(
                {key: record[key] for key in REGULAR_OCCURRENCE_FIELDS},
                source,
            )
            owner = _bounded_text(record["owner"], f"{source} owner", maximum=1056)
            key = (int(occurrence["layer"]), str(occurrence["path"]))
            identity = (key[0], key[1], str(occurrence["sha256"]))
            if (
                owner not in python_owners
                or key in seen
                or regular.get(key) != occurrence
                or occurrence_owners.get(identity) != owner
            ):
                raise VerificationError(f"{source} has an unbound occurrence or owner")
            if identity_field == "elf":
                elf = _exact_mapping(
                    record["elf"],
                    {"bits", "endianness", "machine", "machine_id"},
                    f"{source} ELF identity",
                )
                if elf != {
                    "bits": 64,
                    "endianness": "little",
                    "machine": machine,
                    "machine_id": machine_id,
                } or not str(occurrence["path"]).startswith("opt/venv/"):
                    raise VerificationError(f"{source} has an invalid ELF identity")
            else:
                _validate_retained_cyclonedx_identity(
                    record["cyclonedx"],
                    f"{source} CycloneDX identity",
                )
                if DIST_INFO_SBOM.search(str(occurrence["path"])) is None:
                    raise VerificationError(f"{source} is outside a wheel SBOM directory")
            seen.add(key)
            records.append(record)
        structured[field] = records

    expected_native = {
        (
            str(owner["owner"]),
            str(payload["path"]),
            str(payload["sha256"]),
            int(payload["size"]),
        )
        for owner in policy["native_component_coverage"][expected.platform]
        for payload in owner["native_payloads"]
    }
    observed_native = {
        (
            str(record["owner"]),
            str(record["path"]),
            str(record["sha256"]),
            int(record["size"]),
        )
        for record in structured["native_payloads"]
    }
    expected_sboms = {
        (str(owner["owner"]), str(sbom["path"]), str(sbom["sha256"])): sbom
        for owner in policy["native_component_coverage"][expected.platform]
        for sbom in owner["sboms"]
    }
    observed_sboms = {
        (str(record["owner"]), str(record["path"]), str(record["sha256"])): record
        for record in structured["embedded_sboms"]
    }
    if (
        len(observed_native) != len(structured["native_payloads"])
        or observed_native != expected_native
    ):
        raise VerificationError(
            "component inventory native payloads differ from reviewed policy coverage"
        )
    if (
        len(observed_sboms) != len(structured["embedded_sboms"])
        or set(observed_sboms) != set(expected_sboms)
        or any(
            observed_sboms[identity]["cyclonedx"] != expected_sboms[identity]["observation"]
            for identity in expected_sboms
        )
    ):
        raise VerificationError(
            "component inventory embedded SBOMs differ from reviewed policy coverage"
        )
    all_layer_native = {
        (int(record["layer"]), str(record["path"]), str(record["sha256"]))
        for record in regular.values()
        if str(record["path"]).startswith("opt/venv/")
        and (
            any(part.endswith(".libs") for part in PurePosixPath(str(record["path"])).parts)
            or NATIVE_LIBRARY.search(str(record["path"])) is not None
        )
    }
    observed_native_occurrences = {
        (int(record["layer"]), str(record["path"]), str(record["sha256"]))
        for record in structured["native_payloads"]
    }
    all_layer_sboms = {
        (int(record["layer"]), str(record["path"]), str(record["sha256"]))
        for record in regular.values()
        if DIST_INFO_SBOM.search(str(record["path"]))
    }
    observed_sbom_occurrences = {
        (int(record["layer"]), str(record["path"]), str(record["sha256"]))
        for record in structured["embedded_sboms"]
    }
    if observed_native_occurrences != all_layer_native:
        raise VerificationError("component inventory omits or alters native layer payloads")
    if observed_sbom_occurrences != all_layer_sboms:
        raise VerificationError("component inventory omits or alters embedded layer SBOMs")
    for owner in {str(record["owner"]) for records in structured.values() for record in records}:
        if len(installations_by_owner.get(owner, [])) != 1:
            raise VerificationError(
                f"native-wheel owner must have exactly one historical installation: {owner}"
            )

    ownership = _bounded_list(
        components["python_record_ownership"],
        "component inventory Python RECORD ownership",
        maximum=250_000,
    )
    effective_python_names = {
        str(component["name"]): f"python:{component['name']}@{component['version']}"
        for component in typed_components
        if component["ecosystem"] == "python" and component["effective"] is True
    }
    observed_effective: set[tuple[int, str, str]] = set()
    ownership_paths: list[str] = []
    for index, raw_record in enumerate(ownership):
        source = f"component inventory Python RECORD ownership {index}"
        record = _exact_mapping(
            raw_record,
            REGULAR_OCCURRENCE_FIELDS | {"owner"},
            source,
        )
        owner_name = _bounded_text(record["owner"], f"{source} owner", maximum=512)
        occurrence = _validate_occurrence(
            {key: record[key] for key in REGULAR_OCCURRENCE_FIELDS},
            source,
        )
        identity = (
            int(occurrence["layer"]),
            str(occurrence["path"]),
            str(occurrence["sha256"]),
        )
        if (
            occurrence["effective"] is not True
            or regular.get(identity[:2]) != occurrence
            or effective_owners.get(identity) != effective_python_names.get(owner_name)
        ):
            raise VerificationError(f"{source} is not bound to its active RECORD owner")
        observed_effective.add(identity)
        ownership_paths.append(str(occurrence["path"]))
    if (
        observed_effective != set(effective_owners)
        or ownership_paths != sorted(ownership_paths)
        or len(ownership_paths) != len(set(ownership_paths))
    ):
        raise VerificationError(
            "component inventory Python RECORD ownership is incomplete or non-canonical"
        )

    libraries = _bounded_list(
        components["apk_shared_libraries"],
        "component inventory APK shared libraries",
        maximum=250_000,
    )
    effective_alpine_packages = {
        (str(component["name"]), str(component["version"]))
        for component in typed_components
        if component["ecosystem"] == "alpine" and component["effective"] is True
    }
    library_paths: list[str] = []
    for index, raw_library in enumerate(libraries):
        source = f"component inventory APK shared library {index}"
        library = _exact_mapping(
            raw_library,
            {"apk_sha1", "occurrence", "package", "path"},
            source,
        )
        package = _exact_mapping(
            library["package"],
            {"name", "version"},
            f"{source} package",
        )
        _bounded_text(package["name"], f"{source} package name", maximum=512)
        _bounded_text(package["version"], f"{source} package version", maximum=512)
        apk_sha1 = _bounded_text(library["apk_sha1"], f"{source} APK checksum", maximum=40)
        path = _bounded_text(library["path"], f"{source} path")
        checked_path(path)
        if (
            HEX40.fullmatch(apk_sha1) is None
            or (str(package["name"]), str(package["version"])) not in effective_alpine_packages
        ):
            raise VerificationError(f"{source} has an invalid APK checksum")
        occurrence_value = library["occurrence"]
        if not isinstance(occurrence_value, dict):
            raise VerificationError(f"{source} occurrence is not an object")
        if occurrence_value.get("kind") == "regular":
            occurrence = _exact_mapping(
                occurrence_value,
                REGULAR_OCCURRENCE_FIELDS | {"kind"},
                f"{source} occurrence",
            )
            projected = _validate_occurrence(
                {key: occurrence[key] for key in REGULAR_OCCURRENCE_FIELDS},
                f"{source} occurrence",
            )
            matches_layer = regular.get((int(projected["layer"]), path)) == projected
        elif occurrence_value.get("kind") == "symlink":
            occurrence = _exact_mapping(
                occurrence_value,
                {"effective", "gid", "kind", "layer", "mode", "path", "target", "uid"},
                f"{source} occurrence",
            )
            layer = _integer(
                occurrence["layer"],
                f"{source} occurrence layer",
                minimum=0,
                maximum=MAX_MEMBERS,
            )
            _checked_image_link_target(
                occurrence["target"],
                f"{source} occurrence target",
            )
            if (
                hashlib.sha1(
                    str(occurrence["target"]).encode("utf-8"),
                    usedforsecurity=False,
                ).hexdigest()
                != apk_sha1
            ):
                raise VerificationError(f"{source} symlink differs from its APK checksum")
            raw_layer_record = non_regular.get((layer, path))
            matches_layer = (
                raw_layer_record is not None
                and {
                    key: raw_layer_record[key]
                    for key in ("gid", "kind", "layer", "mode", "path", "target", "uid")
                }
                == {
                    key: occurrence[key]
                    for key in ("gid", "kind", "layer", "mode", "path", "target", "uid")
                }
                and (layer, path) in effective_non_regular
            )
        else:
            raise VerificationError(f"{source} has an invalid occurrence kind")
        if occurrence["effective"] is not True or occurrence["path"] != path or not matches_layer:
            raise VerificationError(f"{source} differs from all-layer inventory")
        library_paths.append(path)
    if library_paths != sorted(library_paths) or len(library_paths) != len(set(library_paths)):
        raise VerificationError("component inventory APK shared libraries are not canonical")

    for component in typed_components:
        if component["ecosystem"] != "runtime":
            continue
        identities = component["identity_files"]
        for role in ("interpreter", "shared_library", "version_header"):
            raw_identity = identities[role]
            projected = {key: raw_identity[key] for key in REGULAR_OCCURRENCE_FIELDS}
            occurrence = _validate_occurrence(projected, f"component inventory runtime {role}")
            if regular.get((int(occurrence["layer"]), str(occurrence["path"]))) != occurrence:
                raise VerificationError(
                    f"component inventory runtime {role} differs from all-layer inventory"
                )
        link = identities["interpreter_link"]
        raw_link = non_regular.get((int(link["layer"]), str(link["path"])))
        if (
            raw_link is None
            or {
                key: raw_link[key]
                for key in ("gid", "kind", "layer", "mode", "path", "target", "uid")
            }
            != {key: link[key] for key in ("gid", "kind", "layer", "mode", "path", "target", "uid")}
            or (int(link["layer"]), str(link["path"])) not in effective_non_regular
        ):
            raise VerificationError(
                "component inventory runtime interpreter link differs from all-layer inventory"
            )

    baselines = policy["filesystem_baselines"][expected.platform]
    if apk_occurrences != baselines["apk_database_occurrences"]:
        raise VerificationError(
            "component inventory APK database occurrences differ from reviewed policy"
        )
    unexpanded = policy["unexpanded_python_payloads"][expected.platform]
    projected_evidence = {
        "embedded_sboms": [
            {key: record[key] for key in REGULAR_OCCURRENCE_FIELDS}
            for record in structured["embedded_sboms"]
        ],
        "native_payloads": [
            {key: record[key] for key in REGULAR_OCCURRENCE_FIELDS}
            for record in structured["native_payloads"]
        ],
        "wheel_identity_files": wheel_identities,
    }
    if projected_evidence != unexpanded:
        raise VerificationError(
            "component inventory Python payload evidence differs from reviewed policy"
        )
    return installations_by_owner


def _validate_wheelhouse_build(
    value: object,
    *,
    source: str,
    wheel: Mapping[str, Any],
    native_sources: Mapping[str, Any],
) -> set[str]:
    record = _exact_mapping(
        value,
        {"cargo_source_ids", "linked_libraries", "local_cargo_packages", "source"},
        source,
    )
    build_source = _bounded_text(record["source"], f"{source} source", maximum=64)
    if (
        re.fullmatch(r"[a-z][a-z0-9-]{0,63}", build_source) is None
        or wheel.get("source") != build_source
    ):
        raise VerificationError(f"{source} disagrees with its wheel")

    cargo_sources = _bounded_list(
        record["cargo_source_ids"],
        f"{source} Cargo sources",
        maximum=10_000,
    )
    if (
        not all(isinstance(source_id, str) for source_id in cargo_sources)
        or cargo_sources != sorted(cargo_sources)
        or len(cargo_sources) != len(set(cargo_sources))
        or any(
            source_id not in native_sources or native_sources[source_id].get("kind") != "crates-io"
            for source_id in cargo_sources
        )
    ):
        raise VerificationError(f"{source} Cargo sources are invalid")

    local_packages: list[tuple[str, str]] = []
    for index, item in enumerate(
        _bounded_list(
            record["local_cargo_packages"],
            f"{source} local Cargo packages",
            maximum=10_000,
        )
    ):
        package = _exact_mapping(
            item,
            {"name", "version"},
            f"{source} local Cargo package {index}",
        )
        name = _bounded_text(
            package["name"],
            f"{source} local Cargo package {index} name",
            maximum=512,
        )
        version = _bounded_text(
            package["version"],
            f"{source} local Cargo package {index} version",
            maximum=512,
        )
        if CARGO_PACKAGE_NAME.fullmatch(name) is None:
            raise VerificationError(f"{source} local Cargo package {index} is invalid")
        local_packages.append((name, version))
    if local_packages != sorted(local_packages) or len(local_packages) != len(set(local_packages)):
        raise VerificationError(f"{source} local Cargo packages are not canonical")
    if bool(cargo_sources) != bool(local_packages):
        raise VerificationError(f"{source} Cargo closure is inconsistent")

    libraries: list[tuple[str, str, str, str, str]] = []
    for index, item in enumerate(
        _bounded_list(
            record["linked_libraries"],
            f"{source} linked libraries",
            maximum=10_000,
            nonempty=True,
        )
    ):
        library = _exact_mapping(
            item,
            {"name", "package", "resolved_path", "runtime_path"},
            f"{source} linked library {index}",
        )
        package = _exact_mapping(
            library["package"],
            {"name", "version"},
            f"{source} linked library {index} package",
        )
        name = _bounded_text(
            library["name"],
            f"{source} linked library {index} name",
            maximum=512,
        )
        runtime_path = _bounded_text(
            library["runtime_path"],
            f"{source} linked library {index} runtime path",
        )
        resolved_path = _bounded_text(
            library["resolved_path"],
            f"{source} linked library {index} resolved path",
        )
        runtime = checked_path(runtime_path)
        resolved = checked_path(resolved_path)
        package_name = _bounded_text(
            package["name"],
            f"{source} linked library {index} package name",
            maximum=512,
        )
        package_version = _bounded_text(
            package["version"],
            f"{source} linked library {index} package version",
            maximum=512,
        )
        if (
            ALPINE_SHARED_LIBRARY.fullmatch(name) is None
            or runtime.name != name
            or str(runtime.parent) not in {"lib", "usr/lib"}
            or runtime.parent != resolved.parent
            or ALPINE_SHARED_LIBRARY.fullmatch(resolved.name) is None
            or re.fullmatch(r"\.?[a-z0-9][a-z0-9+_.-]*", package_name) is None
        ):
            raise VerificationError(f"{source} linked library {index} is invalid")
        libraries.append((name, package_name, package_version, runtime_path, resolved_path))
    if libraries != sorted(libraries) or len(libraries) != len(set(libraries)):
        raise VerificationError(f"{source} linked libraries are not canonical")
    return set(cargo_sources)


def _validate_cargo_lock(
    value: object,
    *,
    source: str,
    crate_source_ids: set[str],
    native_sources: Mapping[str, Any],
) -> Mapping[str, Any] | None:
    if value is None:
        if crate_source_ids:
            raise VerificationError(f"{source} is required by crates.io component reviews")
        return None
    if not crate_source_ids:
        raise VerificationError(f"{source} is present without crates.io component reviews")
    record = _exact_mapping(
        value,
        {"member", "non_sbom_packages", "sha256", "size", "source_ids"},
        source,
    )
    member = _bounded_text(record["member"], f"{source} member")
    if str(checked_path(member)) != member or PurePosixPath(member).name != "Cargo.lock":
        raise VerificationError(f"{source} has an invalid member")
    _digest(record["sha256"], f"{source} digest")
    _integer(record["size"], f"{source} size", minimum=1, maximum=8 * 1024 * 1024)

    source_ids = _bounded_list(record["source_ids"], f"{source} source IDs", maximum=10_000)
    if (
        not all(isinstance(source_id, str) for source_id in source_ids)
        or source_ids != sorted(source_ids)
        or len(source_ids) != len(set(source_ids))
        or set(source_ids) != crate_source_ids
        or any(
            source_id not in native_sources or native_sources[source_id].get("kind") != "crates-io"
            for source_id in source_ids
        )
    ):
        raise VerificationError(f"{source} source IDs differ from component reviews")

    packages: list[tuple[str, str, str, str]] = []
    for index, item in enumerate(
        _bounded_list(
            record["non_sbom_packages"],
            f"{source} non-SBOM packages",
            maximum=10_000,
        )
    ):
        package = _exact_mapping(
            item,
            {"checksum", "name", "source", "version"},
            f"{source} non-SBOM package {index}",
        )
        name = _bounded_text(
            package["name"],
            f"{source} non-SBOM package {index} name",
            maximum=512,
        )
        version = _bounded_text(
            package["version"],
            f"{source} non-SBOM package {index} version",
            maximum=512,
        )
        checksum = _digest(
            package["checksum"],
            f"{source} non-SBOM package {index} checksum",
        )
        if (
            CARGO_PACKAGE_NAME.fullmatch(name) is None
            or package["source"] != CARGO_CRATES_IO_SOURCE
        ):
            raise VerificationError(f"{source} non-SBOM package {index} is invalid")
        packages.append((name, version, str(package["source"]), checksum))
    if packages != sorted(packages) or len(packages) != len(set(packages)):
        raise VerificationError(f"{source} non-SBOM packages are not canonical")
    reviewed_packages = {
        (str(native_sources[source_id]["name"]), str(native_sources[source_id]["version"]))
        for source_id in source_ids
    }
    if reviewed_packages & {(name, version) for name, version, _registry, _digest in packages}:
        raise VerificationError(f"{source} repeats a reviewed crate as non-SBOM")
    return record


def _cargo_purl_identity(value: object, source: str) -> tuple[str, str] | None:
    if not isinstance(value, str) or not value.startswith("pkg:cargo/"):
        return None
    package = value.removeprefix("pkg:cargo/").split("?", maxsplit=1)[0].split("#", maxsplit=1)[0]
    if "/" in package or "@" not in package:
        raise VerificationError(f"{source} has an invalid Cargo purl")
    raw_name, raw_version = package.rsplit("@", maxsplit=1)
    try:
        name = urllib.parse.unquote(raw_name, errors="strict")
        version = urllib.parse.unquote(raw_version, errors="strict")
    except UnicodeDecodeError as exc:
        raise VerificationError(f"{source} has an invalid Cargo purl") from exc
    if (
        CARGO_PACKAGE_NAME.fullmatch(name) is None
        or not version
        or _bounded_text(version, f"{source} Cargo version", maximum=512) != version
    ):
        raise VerificationError(f"{source} has an invalid Cargo purl")
    return name, version


def _verify_cargo_lock_bytes(
    raw: bytes,
    *,
    owner: str,
    lock_context: Mapping[str, Any],
    native_sources: Mapping[str, Any],
    owner_context: Mapping[str, Any],
) -> None:
    """Reconcile one retained Cargo.lock with reviewed registry and local packages."""

    document = _strict_toml_bytes(
        raw,
        f"retained {owner} Cargo.lock",
        maximum=8 * 1024 * 1024,
    )
    if set(document) != {"package", "version"}:
        raise VerificationError(f"retained {owner} Cargo.lock has an unexpected shape")
    if (
        not isinstance(document["version"], int)
        or isinstance(document["version"], bool)
        or document["version"] not in {3, 4}
    ):
        raise VerificationError(f"retained {owner} Cargo.lock has an invalid version")
    raw_packages = _bounded_list(
        document["package"],
        f"retained {owner} Cargo.lock packages",
        maximum=10_000,
        nonempty=True,
    )
    registry_packages: dict[tuple[str, str], tuple[str, str, str, str]] = {}
    local_packages: set[tuple[str, str]] = set()
    for index, raw_package in enumerate(raw_packages):
        source = f"retained {owner} Cargo.lock package {index}"
        if (
            not isinstance(raw_package, dict)
            or not {"name", "version"} <= set(raw_package)
            or set(raw_package) - {"checksum", "dependencies", "name", "source", "version"}
        ):
            raise VerificationError(f"{source} has unexpected fields")
        dependencies = _bounded_list(
            raw_package.get("dependencies", []),
            f"{source} dependencies",
            maximum=10_000,
        )
        if any(
            not isinstance(dependency, str)
            or _bounded_text(dependency, f"{source} dependency", maximum=4096) != dependency
            for dependency in dependencies
        ):
            raise VerificationError(f"{source} has invalid dependencies")
        name = _bounded_text(raw_package["name"], f"{source} name", maximum=512)
        version = _bounded_text(raw_package["version"], f"{source} version", maximum=512)
        if CARGO_PACKAGE_NAME.fullmatch(name) is None:
            raise VerificationError(f"{source} has an invalid name")
        identity = (name, version)
        registry = raw_package.get("source")
        checksum = raw_package.get("checksum")
        if registry is None:
            if checksum is not None or identity in local_packages or identity in registry_packages:
                raise VerificationError(f"{source} repeats or corrupts a local package")
            local_packages.add(identity)
            continue
        if registry != CARGO_CRATES_IO_SOURCE:
            raise VerificationError(f"{source} uses a foreign registry")
        canonical = (
            name,
            version,
            CARGO_CRATES_IO_SOURCE,
            _digest(checksum, f"{source} checksum"),
        )
        if identity in registry_packages or identity in local_packages:
            raise VerificationError(f"{source} repeats a package")
        registry_packages[identity] = canonical

    expected_registry: dict[tuple[str, str], tuple[str, str, str, str]] = {}
    for source_id in lock_context["source_ids"]:
        source_record = native_sources[source_id]
        identity = (str(source_record["name"]), str(source_record["version"]))
        expected_registry[identity] = (
            identity[0],
            identity[1],
            CARGO_CRATES_IO_SOURCE,
            str(source_record["crate"]["sha256"]),
        )
    for package in lock_context["non_sbom_packages"]:
        identity = (str(package["name"]), str(package["version"]))
        expected_registry[identity] = (
            identity[0],
            identity[1],
            CARGO_CRATES_IO_SOURCE,
            str(package["checksum"]),
        )
    if registry_packages != expected_registry:
        raise VerificationError(
            f"retained {owner} Cargo.lock registry packages differ from reviewed context"
        )

    expected_local: set[tuple[str, str]] = set()
    for source_record in native_sources.values():
        if (
            isinstance(source_record, dict)
            and source_record.get("kind") == "owner-sdist-subpath"
            and source_record.get("owner") == owner
        ):
            expected_local.update(
                (str(package["name"]), str(package["version"]))
                for package in source_record["cargo_packages"]
            )
    observations = owner_context["observations"]
    for reference in owner_context["owner_root_observations"]:
        cargo_identity = _cargo_purl_identity(
            observations[reference]["purl"],
            f"{owner} Cargo owner root",
        )
        if cargo_identity is not None:
            expected_local.add(cargo_identity)
    owner_record = owner_context["record"]
    for review in owner_record["component_reviews"]:
        source_record = native_sources[str(review["source"])]
        if source_record["kind"] != "owner-sdist-subpath":
            continue
        for reference in _validate_observation_references(
            review["observations"],
            f"{owner} local Cargo observations",
        ):
            cargo_identity = _cargo_purl_identity(
                observations[reference]["purl"],
                f"{owner} local Cargo observation",
            )
            if cargo_identity is not None:
                expected_local.add(cargo_identity)
    if local_packages != expected_local:
        raise VerificationError(
            f"retained {owner} Cargo.lock local packages differ from reviewed observations"
        )


def _validate_native_owner(
    value: object,
    source: str,
    native_sources: Mapping[str, Any],
    *,
    platform: str,
) -> tuple[str, set[str], set[str], Mapping[str, Any]]:
    if platform not in PLATFORMS:
        raise VerificationError(f"{source} has an unsupported platform")
    record = _exact_mapping(value, NATIVE_OWNER_FIELDS, source)
    owner = _bounded_text(record["owner"], f"{source} owner", maximum=1056)
    owner_match = re.fullmatch(r"python:([a-z0-9]+(?:-[a-z0-9]+)*)@([^/@#]+)", owner)
    if owner_match is None:
        raise VerificationError(f"{source} has an invalid owner")
    owner_name, owner_version = owner_match.groups()
    _validate_artifact_pin(record["owner_source"], f"{source} owner source")

    wheel = record["wheel"]
    if isinstance(wheel, dict) and "provider" in wheel:
        wheel_record = _exact_mapping(
            wheel,
            {"filename", "provider", "sha256", "size", "source"},
            f"{source} wheel",
        )
        filename = _bounded_text(wheel_record["filename"], f"{source} wheel filename")
        wheel_source = _bounded_text(
            wheel_record["source"],
            f"{source} wheel source",
            maximum=64,
        )
        normalized_filename = filename.replace("_", "-").lower()
        if (
            wheel_record["provider"] != "native-wheelhouse"
            or len(checked_path(filename).parts) != 1
            or re.fullmatch(r"[a-z][a-z0-9-]{0,63}", wheel_source) is None
            or not normalized_filename.startswith(f"{owner_name}-{owner_version}-")
        ):
            raise VerificationError(f"{source} has an invalid wheel provider")
        _digest(wheel_record["sha256"], f"{source} wheel digest")
        _integer(
            wheel_record["size"],
            f"{source} wheel size",
            minimum=1,
            maximum=MAX_LARGE_SOURCE_BYTES,
        )
    else:
        _validate_artifact_pin(wheel, f"{source} wheel")

    payload_roles: list[str] = []
    payloads: dict[str, Mapping[str, Any]] = {}
    for index, item in enumerate(
        _bounded_list(record["native_payloads"], f"{source} native payloads", nonempty=True)
    ):
        payload = _exact_mapping(
            item,
            {"path", "role", "sha256", "size"},
            f"{source} native payload {index}",
        )
        path = _bounded_text(payload["path"], f"{source} native payload {index} path")
        role = _bounded_text(payload["role"], f"{source} native payload {index} role")
        if (
            str(checked_path(path)) != path
            or str(checked_path(role)) != role
            or not path.startswith("opt/venv/lib/python3.14/site-packages/")
        ):
            raise VerificationError(f"{source} native payload {index} path is invalid")
        _digest(payload["sha256"], f"{source} native payload {index} digest")
        _integer(
            payload["size"],
            f"{source} native payload {index} size",
            minimum=1,
            maximum=MAX_MEMBER_BYTES,
        )
        payload_roles.append(role)
        payloads[role] = payload
    if payload_roles != sorted(payload_roles) or len(payload_roles) != len(set(payload_roles)):
        raise VerificationError(f"{source} native payload roles are not uniquely sorted")

    observation_paths: list[str] = []
    observations: dict[ObservationReference, Mapping[str, Any]] = {}
    owner_root_observations: set[ObservationReference] = set()
    omission_root_observations: dict[ObservationReference, str] = {}
    for index, item in enumerate(_bounded_list(record["sboms"], f"{source} SBOMs")):
        sbom = _exact_mapping(
            item,
            {"metadata_root", "observation", "path", "sha256"},
            f"{source} SBOM {index}",
        )
        path = _bounded_text(sbom["path"], f"{source} SBOM {index} path")
        if str(checked_path(path)) != path or ".dist-info/sboms/" not in path:
            raise VerificationError(f"{source} SBOM {index} path is invalid")
        _digest(sbom["sha256"], f"{source} SBOM {index} digest")
        observation = _exact_mapping(
            sbom["observation"],
            {
                "bom_format",
                "components",
                "metadata_component",
                "metadata_root_echo",
                "observation_sha256",
                "spec_version",
                "upstream_invalid_duplicate_bom_ref",
            },
            f"{source} SBOM {index} observation",
        )
        if observation["bom_format"] != "CycloneDX" or observation["spec_version"] not in {
            "1.4",
            "1.5",
            "1.6",
        }:
            raise VerificationError(f"{source} SBOM {index} has an invalid format")
        observation_sha256 = _digest(
            observation["observation_sha256"],
            f"{source} SBOM {index} observation digest",
        )
        upstream_duplicate = _boolean(
            observation["upstream_invalid_duplicate_bom_ref"],
            f"{source} SBOM {index} duplicate-bom-ref state",
        )
        raw_metadata = observation["metadata_component"]
        metadata_component = (
            None
            if raw_metadata is None
            else _validate_observation_component(
                raw_metadata,
                f"{source} SBOM {index} metadata component",
            )
        )
        components = [
            _validate_observation_component(
                component,
                f"{source} SBOM {index} component {component_index}",
            )
            for component_index, component in enumerate(
                _bounded_list(
                    observation["components"],
                    f"{source} SBOM {index} components",
                    maximum=10_000,
                )
            )
        ]
        if components != sorted(components, key=_observation_sort_key):
            raise VerificationError(f"{source} SBOM {index} components are not canonical")

        raw_echo = observation["metadata_root_echo"]
        metadata_root_echo = (
            None
            if raw_echo is None
            else _validate_observation_component(
                raw_echo,
                f"{source} SBOM {index} metadata root echo",
            )
        )
        if metadata_root_echo is None:
            if upstream_duplicate:
                raise VerificationError(f"{source} SBOM {index} has an invalid root echo state")
        elif (
            metadata_component is None
            or metadata_root_echo != metadata_component
            or not upstream_duplicate
        ):
            raise VerificationError(f"{source} SBOM {index} has an invalid metadata root echo")
        projected = {
            "components": observation["components"],
            "metadata_component": observation["metadata_component"],
            "metadata_root_echo": observation["metadata_root_echo"],
            "upstream_invalid_duplicate_bom_ref": upstream_duplicate,
        }
        if hashlib.sha256(canonical_json(projected)).hexdigest() != observation_sha256:
            raise VerificationError(f"{source} SBOM {index} observation digest is invalid")

        component_identities: list[tuple[str, str]] = []
        for component in components:
            identity_kind = "bom-ref" if component["bom_ref"] else "purl"
            component_identities.append(
                (identity_kind, str(component["bom_ref"] or component["purl"]))
            )
            if metadata_component is not None and component["purl"] == metadata_component["purl"]:
                raise VerificationError(f"{source} SBOM {index} repeats its metadata component")
        if len(component_identities) != len(set(component_identities)):
            raise VerificationError(f"{source} SBOM {index} has ambiguous component identities")

        raw_root = sbom["metadata_root"]
        if not isinstance(raw_root, dict):
            raise VerificationError(f"{source} SBOM {index} metadata root is invalid")
        root_kind = raw_root.get("kind")
        root_fields = {"anomaly_review", "kind"}
        if root_kind == "known-omission":
            root_fields.add("omission")
        elif root_kind not in {"embedded-component", "missing", "owner"}:
            raise VerificationError(f"{source} SBOM {index} metadata root is invalid")
        metadata_root = _exact_mapping(
            raw_root,
            root_fields,
            f"{source} SBOM {index} metadata root",
        )
        anomaly = metadata_root["anomaly_review"]
        if metadata_root_echo is None:
            if anomaly is not None:
                raise VerificationError(f"{source} SBOM {index} has a stale anomaly review")
        else:
            anomaly_record = _exact_mapping(
                anomaly,
                {"kind", "reason"},
                f"{source} SBOM {index} anomaly review",
            )
            if anomaly_record["kind"] != "metadata-root-echo":
                raise VerificationError(f"{source} SBOM {index} anomaly review is invalid")
            _bounded_text(
                anomaly_record["reason"],
                f"{source} SBOM {index} anomaly reason",
                maximum=16 * 1024,
            )

        if metadata_component is None:
            if root_kind != "missing":
                raise VerificationError(f"{source} SBOM {index} metadata root has no component")
        else:
            root_reference = _component_reference(
                sbom_path=path,
                observation_sha256=observation_sha256,
                component=metadata_component,
            )
            if root_kind == "owner":
                normalized_name = re.sub(r"[-_.]+", "-", str(metadata_component["name"])).lower()
                if normalized_name != owner_name or metadata_component["version"] != owner_version:
                    raise VerificationError(
                        f"{source} SBOM {index} owner root conflicts with its owner"
                    )
                owner_root_observations.add(root_reference)
            elif root_kind == "known-omission":
                omission_id = _bounded_text(
                    metadata_root["omission"],
                    f"{source} SBOM {index} root omission",
                    maximum=512,
                )
                omission_root_observations[root_reference] = omission_id

        for component in (
            [metadata_component] if metadata_component is not None else []
        ) + components:
            reference = _component_reference(
                sbom_path=path,
                observation_sha256=observation_sha256,
                component=component,
            )
            if reference in observations:
                raise VerificationError(f"{source} repeats an SBOM observation")
            observations[reference] = component
        observation_paths.append(path)
    if observation_paths != sorted(observation_paths) or len(observation_paths) != len(
        set(observation_paths)
    ):
        raise VerificationError(f"{source} SBOMs are not uniquely sorted")

    used_sources: set[str] = set()
    reviewed_expressions: set[str] = set()
    reviewed_observations: set[ObservationReference] = set()
    crate_source_ids: set[str] = set()
    review_order: list[tuple[ObservationReference, ...]] = []
    for index, item in enumerate(
        _bounded_list(record["component_reviews"], f"{source} component reviews")
    ):
        review = _exact_mapping(
            item,
            {"observations", "reviewed_license", "source"},
            f"{source} component review {index}",
        )
        source_id = _bounded_text(
            review["source"],
            f"{source} component review {index} source",
            maximum=1056,
        )
        if source_id not in native_sources:
            raise VerificationError(f"{source} component review names an unknown source")
        expression = _bounded_text(
            review["reviewed_license"],
            f"{source} component review {index} license",
            maximum=16 * 1024,
        )
        references = _validate_observation_references(
            review["observations"],
            f"{source} component review {index} observations",
        )
        if not set(references) <= set(observations):
            raise VerificationError(
                f"{source} component review {index} references an unknown observation"
            )
        if reviewed_observations & set(references):
            raise VerificationError(f"{source} reviews an observation more than once")
        native_source = native_sources[source_id]
        source_kind = native_source["kind"]
        expected_expression = {
            "checksummed-upstream-release": native_source.get("reviewed_license"),
            "crates-io": native_source.get("normalized_license"),
            "owner-sdist-subpath": native_source.get("reviewed_license"),
        }.get(str(source_kind))
        if expected_expression is not None and expression != expected_expression:
            raise VerificationError(
                f"{source} component review {index} license differs from its source"
            )
        for reference in references:
            observed = observations[reference]
            observed_purl = str(observed["purl"])
            if source_kind == "crates-io":
                expected_prefix = f"pkg:cargo/{native_source['name']}@{native_source['version']}"
                source_matches = (
                    re.fullmatch(rf"{re.escape(expected_prefix)}(?:[?#].*)?", observed_purl)
                    is not None
                )
            elif source_kind == "alpine-aports":
                source_matches = (
                    observed_purl.startswith("pkg:apk/alpine/")
                    and re.search(
                        rf"@{re.escape(str(native_source['version']))}(?:[?#]|$)",
                        observed_purl,
                    )
                    is not None
                )
            elif source_kind == "checksummed-upstream-release":
                source_matches = (
                    str(native_source["name"]).lower() in observed_purl.lower()
                    and re.search(
                        rf"@{re.escape(str(native_source['version']))}(?:[?#]|$)",
                        observed_purl,
                    )
                    is not None
                )
            else:
                package_identities = {
                    (
                        re.sub(r"[-_.]+", "-", str(package["name"])).lower(),
                        str(package["version"]),
                    )
                    for package in native_source["cargo_packages"]
                }
                source_matches = (
                    re.sub(r"[-_.]+", "-", str(observed["name"])).lower(),
                    str(observed["version"]),
                ) in package_identities
            if not source_matches:
                raise VerificationError(
                    f"{source} component review {index} observation differs from its source"
                )
        used_sources.add(source_id)
        reviewed_expressions.add(expression)
        reviewed_observations.update(references)
        if source_kind == "crates-io":
            crate_source_ids.add(source_id)
        review_order.append(tuple(references))
    if review_order != sorted(review_order):
        raise VerificationError(f"{source} component reviews are not canonical")

    wheelhouse_build = record["wheelhouse_build"]
    if wheelhouse_build is not None:
        if not isinstance(wheel, dict) or wheel.get("provider") != "native-wheelhouse":
            raise VerificationError(f"{source} has wheelhouse build policy for a lock wheel")
        used_sources.update(
            _validate_wheelhouse_build(
                wheelhouse_build,
                source=f"{source} wheelhouse build",
                wheel=wheel,
                native_sources=native_sources,
            )
        )
    elif isinstance(wheel, dict) and wheel.get("provider") == "native-wheelhouse":
        raise VerificationError(f"{source} wheelhouse wheel has no build policy")

    cargo_lock = _validate_cargo_lock(
        record["cargo_lock"],
        source=f"{source} Cargo lock",
        crate_source_ids=crate_source_ids,
        native_sources=native_sources,
    )

    omission_ids: set[str] = set()
    omitted_observations: set[ObservationReference] = set()
    omitted_payload_roles: set[str] = set()
    omission_observations: dict[str, set[ObservationReference]] = {}
    omission_payload_roles: dict[str, set[str]] = {}
    omissions = _bounded_list(
        record["known_omissions"],
        f"{source} known omissions",
        maximum=10_000,
    )
    for index, item in enumerate(omissions):
        omission = _exact_mapping(
            item,
            {
                "component",
                "id",
                "missing_evidence",
                "observations",
                "payload_roles",
                "reason",
            },
            f"{source} known omission {index}",
        )
        omission_id = _bounded_text(
            omission["id"],
            f"{source} known omission {index} identity",
            maximum=512,
        )
        if (
            re.fullmatch(r"[a-z0-9][a-z0-9._-]*", omission_id) is None
            or omission_id in omission_ids
        ):
            raise VerificationError(f"{source} known omission {index} has an invalid identity")
        omission_ids.add(omission_id)
        component = _exact_mapping(
            omission["component"],
            {"name", "purl", "type", "version"},
            f"{source} known omission {index} component",
        )
        for field in ("name", "type"):
            _bounded_text(
                component[field],
                f"{source} known omission {index} component {field}",
                maximum=512,
            )
        _bounded_optional_text(
            component["version"],
            f"{source} known omission {index} component version",
            maximum=512,
        )
        component_purl = _bounded_optional_text(
            component["purl"],
            f"{source} known omission {index} component purl",
            maximum=16 * 1024,
        )
        if component_purl and PACKAGE_URL.fullmatch(component_purl) is None:
            raise VerificationError(f"{source} known omission {index} component purl is invalid")
        references = _validate_observation_references(
            omission["observations"],
            f"{source} known omission {index} observations",
            allow_empty=True,
        )
        if not set(references) <= set(observations) or omitted_observations & set(references):
            raise VerificationError(f"{source} known omission {index} has invalid observations")
        omitted_observations.update(references)
        omission_observations[omission_id] = set(references)
        roles = _bounded_list(
            omission["payload_roles"],
            f"{source} known omission {index} payload roles",
            maximum=10_000,
        )
        if (
            not all(isinstance(role, str) for role in roles)
            or roles != sorted(roles)
            or len(roles) != len(set(roles))
            or not set(roles) <= set(payload_roles)
            or omitted_payload_roles & set(roles)
        ):
            raise VerificationError(f"{source} known omission {index} has invalid payload roles")
        omitted_payload_roles.update(roles)
        omission_payload_roles[omission_id] = set(roles)
        missing_evidence = _bounded_list(
            omission["missing_evidence"],
            f"{source} known omission {index} missing evidence",
            maximum=8,
            nonempty=True,
        )
        allowed_missing = {
            "build-material-attestation",
            "component-inventory",
            "exact-source",
            "license-evidence",
            "notice-evidence",
            "payload-provenance",
            "sbom-observation",
            "source-payload-relationship",
        }
        if (
            not all(isinstance(item, str) for item in missing_evidence)
            or missing_evidence != sorted(missing_evidence)
            or len(missing_evidence) != len(set(missing_evidence))
            or not set(missing_evidence) <= allowed_missing
        ):
            raise VerificationError(f"{source} known omission {index} has invalid missing evidence")
        _bounded_text(
            omission["reason"],
            f"{source} known omission {index} reason",
            maximum=16 * 1024,
        )
    if [item["id"] for item in omissions] != sorted(omission_ids):
        raise VerificationError(f"{source} known omissions are not canonical")
    if set(omission_root_observations.values()) - omission_ids:
        raise VerificationError(f"{source} metadata root cites an unknown omission")
    for reference, omission_id in omission_root_observations.items():
        if reference not in omission_observations[omission_id]:
            raise VerificationError(
                f"{source} metadata-root omission does not cite its observation"
            )

    relationship_observations: set[ObservationReference] = set()
    relationship_order: list[ObservationReference] = []
    relationships: list[Mapping[str, Any]] = []
    for index, item in enumerate(
        _bounded_list(
            record["canonical_relationships"],
            f"{source} canonical relationships",
            maximum=10_000,
        )
    ):
        relationship = _exact_mapping(
            item,
            {
                "kind",
                "observation",
                "payload_role",
                "reference_observation",
                "reference_owner",
                "reference_payload_role",
            },
            f"{source} canonical relationship {index}",
        )
        if relationship["kind"] != "same-component-by-payload-equivalence":
            raise VerificationError(f"{source} canonical relationship {index} is unsupported")
        observation_reference = _validate_observation_reference(
            relationship["observation"],
            f"{source} canonical relationship {index} observation",
        )
        if (
            observation_reference not in observations
            or observation_reference in relationship_observations
        ):
            raise VerificationError(
                f"{source} canonical relationship {index} has an invalid observation"
            )
        relationship_observations.add(observation_reference)
        reference_owner = _bounded_text(
            relationship["reference_owner"],
            f"{source} canonical relationship {index} reference owner",
            maximum=1056,
        )
        if (
            re.fullmatch(r"python:[a-z0-9]+(?:-[a-z0-9]+)*@[^/@#]+", reference_owner) is None
            or reference_owner == owner
        ):
            raise VerificationError(
                f"{source} canonical relationship {index} has an invalid reference owner"
            )
        _validate_observation_reference(
            relationship["reference_observation"],
            f"{source} canonical relationship {index} reference observation",
        )
        for field in ("payload_role", "reference_payload_role"):
            role = _bounded_text(
                relationship[field],
                f"{source} canonical relationship {index} {field}",
            )
            if str(checked_path(role)) != role:
                raise VerificationError(
                    f"{source} canonical relationship {index} {field} is invalid"
                )
        if relationship["payload_role"] not in payloads:
            raise VerificationError(
                f"{source} canonical relationship {index} has an unknown payload"
            )
        relationship_order.append(observation_reference)
        relationships.append(relationship)
    if relationship_order != sorted(relationship_order):
        raise VerificationError(f"{source} canonical relationships are not canonical")

    disposition_roles: set[str] = set()
    payload_observations: dict[str, set[ObservationReference]] = {}
    dispositions = _bounded_list(
        record["payload_dispositions"],
        f"{source} payload dispositions",
        maximum=10_000,
    )
    for index, item in enumerate(dispositions):
        if not isinstance(item, dict):
            raise VerificationError(f"{source} payload disposition {index} is not an object")
        kind = item.get("kind")
        fields = {"kind", "role"}
        if kind == "sbom-components":
            fields.add("observations")
        elif kind == "known-omission":
            fields.add("omission")
        elif kind != "owner":
            raise VerificationError(f"{source} payload disposition {index} is unsupported")
        disposition = _exact_mapping(
            item,
            fields,
            f"{source} payload disposition {index}",
        )
        role = _bounded_text(
            disposition["role"],
            f"{source} payload disposition {index} role",
        )
        if role not in payloads or role in disposition_roles:
            raise VerificationError(f"{source} payload disposition {index} has an invalid role")
        disposition_roles.add(role)
        if kind == "sbom-components":
            references = _validate_observation_references(
                disposition["observations"],
                f"{source} payload disposition {index} observations",
            )
            if not set(references) <= set(observations):
                raise VerificationError(
                    f"{source} payload disposition {index} has unknown observations"
                )
            payload_observations[role] = set(references)
        elif kind == "known-omission":
            omission_id = disposition["omission"]
            if (
                not isinstance(omission_id, str)
                or omission_id not in omission_payload_roles
                or role not in omission_payload_roles[omission_id]
            ):
                raise VerificationError(
                    f"{source} payload disposition {index} has an invalid omission"
                )
    if [item["role"] for item in dispositions] != sorted(disposition_roles):
        raise VerificationError(f"{source} payload dispositions are not canonical")
    if disposition_roles != set(payload_roles):
        raise VerificationError(f"{source} does not dispose every native payload")

    disposed_observations = (
        owner_root_observations
        | reviewed_observations
        | omitted_observations
        | relationship_observations
    )
    if len(disposed_observations) != (
        len(owner_root_observations)
        + len(reviewed_observations)
        + len(omitted_observations)
        + len(relationship_observations)
    ):
        raise VerificationError(f"{source} gives one observation multiple dispositions")
    if disposed_observations != set(observations):
        raise VerificationError(f"{source} does not dispose every SBOM observation")

    review = _exact_mapping(
        record["review"],
        {"reason", "state", "unresolved_items"},
        f"{source} review",
    )
    reason = _bounded_optional_text(
        review["reason"],
        f"{source} review reason",
        maximum=16 * 1024,
    )
    unresolved = _bounded_list(
        review["unresolved_items"],
        f"{source} unresolved items",
        maximum=10_000,
    )
    if (
        review["state"] not in {"closed", "open"}
        or any(not isinstance(item, str) or not item for item in unresolved)
        or unresolved != sorted(unresolved)
        or len(unresolved) != len(set(unresolved))
        or (review["state"] == "closed" and (reason or unresolved))
        or (review["state"] == "open" and (not reason or not unresolved))
        or (review["state"] == "closed" and omissions)
        or (review["state"] == "open" and set(unresolved) != omission_ids)
    ):
        raise VerificationError(f"{source} has an invalid review state")
    return (
        owner,
        used_sources,
        reviewed_expressions,
        {
            "observations": observations,
            "owner_root_observations": owner_root_observations,
            "payload_observations": payload_observations,
            "payloads": payloads,
            "record": record,
            "relationships": relationships,
            "relationship_observations": relationship_observations,
            "reviewed_observations": reviewed_observations,
            "cargo_lock": cargo_lock,
            "state": review["state"],
        },
    )


def _validate_native_relationships(
    contexts: Mapping[str, Mapping[str, Any]],
    *,
    platform: str,
) -> None:
    relationship_sources = {
        (owner, reference)
        for owner, context in contexts.items()
        for reference in context["relationship_observations"]
    }
    target_references: set[tuple[str, ObservationReference]] = set()
    for owner, context in contexts.items():
        for index, relationship in enumerate(context["relationships"]):
            source_reference = _validate_observation_reference(
                relationship["observation"],
                f"{platform} {owner} relationship {index} source",
            )
            reference_owner = str(relationship["reference_owner"])
            reference_context = contexts.get(reference_owner)
            if reference_context is None or reference_context["state"] != "closed":
                raise VerificationError(
                    f"{platform} {owner} relationship {index} target is not closed"
                )
            reference = _validate_observation_reference(
                relationship["reference_observation"],
                f"{platform} {owner} relationship {index} target",
            )
            if reference not in reference_context["reviewed_observations"]:
                raise VerificationError(
                    f"{platform} {owner} relationship {index} target is not directly reviewed"
                )
            payload_role = str(relationship["payload_role"])
            reference_payload_role = str(relationship["reference_payload_role"])
            if source_reference not in context["payload_observations"].get(payload_role, set()):
                raise VerificationError(
                    f"{platform} {owner} relationship {index} source payload "
                    "does not cite its observation"
                )
            if reference not in reference_context["payload_observations"].get(
                reference_payload_role, set()
            ):
                raise VerificationError(
                    f"{platform} {owner} relationship {index} target payload "
                    "does not cite its observation"
                )
            if (reference_owner, reference) in relationship_sources:
                raise VerificationError(
                    f"{platform} {owner} relationship {index} forms a relationship chain"
                )
            target_key = (reference_owner, reference)
            if target_key in target_references:
                raise VerificationError(
                    f"{platform} {owner} relationship {index} reuses its target"
                )
            target_references.add(target_key)
            observed = context["observations"][source_reference]
            reference_observed = reference_context["observations"][reference]
            if {field: observed[field] for field in ("name", "type", "version")} != {
                field: reference_observed[field] for field in ("name", "type", "version")
            }:
                raise VerificationError(
                    f"{platform} {owner} relationship {index} changes component identity"
                )
            payload = context["payloads"].get(payload_role)
            reference_payload = reference_context["payloads"].get(reference_payload_role)
            if (
                payload is None
                or reference_payload is None
                or {field: payload[field] for field in ("sha256", "size")}
                != {field: reference_payload[field] for field in ("sha256", "size")}
            ):
                raise VerificationError(
                    f"{platform} {owner} relationship {index} payloads are not byte-identical"
                )


def _verify_owner_subtree_manifest(
    raw: bytes,
    *,
    source_id: str,
    native_source: Mapping[str, Any],
    json_budget: JsonBudget | None = None,
) -> None:
    source = f"container policy native-component source {source_id} subtree manifest"
    subtree = _bounded_list(
        strict_json_value_bytes(raw, source, budget=json_budget),
        source,
        maximum=MAX_MEMBERS,
        nonempty=True,
    )
    identities: list[tuple[str, str]] = []
    records_by_path: dict[str, Mapping[str, Any]] = {}
    expanded_size = 0
    for index, item in enumerate(subtree):
        record = _exact_mapping(
            item,
            {"mode", "path", "sha256", "size", "type"},
            f"{source} member {index}",
        )
        path = _bounded_text(record["path"], f"{source} member {index} path")
        if str(checked_path(path)) != path:
            raise VerificationError(f"{source} member {index} path is invalid")
        _integer(
            record["mode"],
            f"{source} member {index} mode",
            minimum=0,
            maximum=0o777,
        )
        size = _integer(
            record["size"],
            f"{source} member {index} size",
            minimum=0,
            maximum=MAX_MEMBER_BYTES,
        )
        if record["type"] == "file":
            _digest(record["sha256"], f"{source} member {index} digest")
            expanded_size += size
        elif record["type"] == "directory":
            if record["sha256"] is not None or size != 0:
                raise VerificationError(f"{source} directory {index} has content")
        else:
            raise VerificationError(f"{source} member {index} has an invalid type")
        identities.append((path, str(record["type"])))
        records_by_path[path] = record
    if (
        identities != sorted(identities)
        or len(identities) != len(set(identities))
        or len(subtree) != native_source["member_count"]
        or expanded_size != native_source["expanded_size"]
        or hashlib.sha256(raw).hexdigest() != native_source["tree_sha256"]
    ):
        raise VerificationError(f"{source} differs from reviewed policy")

    configured_path = str(native_source["path"])
    configured_prefix = (
        PurePosixPath() if configured_path == "." else PurePosixPath(configured_path)
    )
    for package_index, package in enumerate(native_source["cargo_packages"]):
        package_path = str(package["path"])
        relative_manifest = (
            PurePosixPath("Cargo.toml")
            if package_path == "."
            else PurePosixPath(package_path) / "Cargo.toml"
        )
        retained_manifest = records_by_path.get(str(relative_manifest))
        manifest_pin = package["manifest"]
        archive_member = PurePosixPath(str(manifest_pin["member"]))
        expected_archive_member = configured_prefix / relative_manifest
        if (
            len(archive_member.parts) < 2
            or PurePosixPath(*archive_member.parts[1:]) != expected_archive_member
            or retained_manifest is None
            or retained_manifest["type"] != "file"
            or retained_manifest["sha256"] != manifest_pin["sha256"]
            or retained_manifest["size"] != manifest_pin["size"]
        ):
            raise VerificationError(
                f"{source} Cargo package {package_index} differs from its subtree"
            )


def _verify_policy_source_and_license_relationships(
    *,
    policy: Mapping[str, Any],
    components: Sequence[Mapping[str, Any]],
    source_records: object,
    license_records: object,
    members: Mapping[str, MemberRecord],
    runtime_version: str,
    native_source_pins: Mapping[str, Sequence[Mapping[str, Any]]],
    native_notice_pins: Mapping[str, Sequence[Mapping[str, Any]]],
    configured_owners: Sequence[Mapping[str, Any]],
    output: ExtractionRoot | None,
    json_budget: JsonBudget | None = None,
) -> set[str]:
    """Bind reviewed source and license pins to exact retained manifest records."""

    if not isinstance(source_records, list) or not all(
        isinstance(record, dict) for record in source_records
    ):
        raise VerificationError("manifest source records are invalid")
    if not isinstance(license_records, list) or not all(
        isinstance(record, dict) for record in license_records
    ):
        raise VerificationError("manifest license records are invalid")

    def matching_sources(
        *,
        component: str | None,
        url: object,
        sha256: object | None = None,
        sha512: object | None = None,
        size: object | None = None,
    ) -> list[Mapping[str, Any]]:
        return [
            record
            for record in source_records
            if (component is None or record.get("component") == component)
            and record.get("url") == url
            and (sha256 is None or record.get("sha256") == sha256)
            and (sha512 is None or record.get("sha512") == sha512)
            and (size is None or record.get("size") == size)
        ]

    def require_source(
        *,
        component: str | None,
        url: object,
        source: str,
        sha256: object | None = None,
        sha512: object | None = None,
        size: object | None = None,
        expected_path: str | None = None,
    ) -> Mapping[str, Any]:
        matches = matching_sources(
            component=component,
            url=url,
            sha256=sha256,
            sha512=sha512,
            size=size,
        )
        if len(matches) != 1:
            raise VerificationError(f"{source} does not bind one retained source record")
        record = matches[0]
        if expected_path is not None and record.get("path") != expected_path:
            raise VerificationError(f"{source} has the wrong retained source path")
        return record

    def require_license(
        *,
        component: str | None,
        path: str,
        digest: object,
        size: object | None = None,
        source: str,
    ) -> None:
        matches = [
            record
            for record in license_records
            if (component is None or record.get("component") == component)
            and record.get("path") == path
            and record.get("sha256") == digest
            and (size is None or record.get("size") == size)
        ]
        if not matches:
            raise VerificationError(f"{source} does not bind a retained license record")

    docker_recipe = policy["docker_python_recipe"]
    require_source(
        component="docker-python-recipe",
        url=docker_recipe["url"],
        sha256=docker_recipe["sha256"],
        source="container policy Docker Official Python recipe",
        expected_path="sources/base/docker-python-recipe/Dockerfile",
    )
    require_source(
        component="docker-python-recipe-license",
        url=docker_recipe["license_url"],
        sha256=docker_recipe["license_sha256"],
        source="container policy Docker Official Python recipe license",
        expected_path="licenses/from-source/docker-python-recipe/LICENSE",
    )
    require_license(
        component="docker-python-recipe",
        path="licenses/from-source/docker-python-recipe/LICENSE",
        digest=docker_recipe["license_sha256"],
        source="container policy Docker Official Python recipe license",
    )

    cpython = policy["cpython_source"]
    cpython_path = (
        f"sources/base/cpython/"
        f"{PurePosixPath(urllib.parse.urlparse(str(cpython['url'])).path).name}"
    )
    require_source(
        component=f"runtime:cpython@{runtime_version}",
        url=cpython["url"],
        sha256=cpython["sha256"],
        size=cpython["size"],
        source="container policy CPython source",
        expected_path=cpython_path,
    )
    cpython_license_path = (
        f"licenses/from-source/runtime-cpython-{runtime_version}/"
        f"{str(cpython['license_sha256'])[:12]}-LICENSE"
    )
    require_license(
        component=f"runtime:cpython@{runtime_version}",
        path=cpython_license_path,
        digest=cpython["license_sha256"],
        source="container policy CPython source license",
    )

    for index, source_record in enumerate(policy["python_sources"]):
        name = str(source_record["name"])
        version = str(source_record["version"])
        filename = PurePosixPath(urllib.parse.urlparse(str(source_record["url"])).path).name
        require_source(
            component=f"python-{name}-{version}",
            url=source_record["url"],
            sha256=source_record["sha256"],
            size=source_record["size"],
            source=f"container policy Python source fallback {index}",
            expected_path=f"sources/python/{name}/{version}/{filename}",
        )

    component_by_identity = {
        f"{component['ecosystem']}:{component['name']}@{component['version']}": component
        for component in components
    }
    for entry in policy["license_texts"]:
        identifier = str(entry["id"])
        path = f"licenses/standard/{identifier}.txt"
        require_source(
            component=f"license:{identifier}",
            url=entry["url"],
            sha256=entry["sha256"],
            source=f"container policy standard license text {identifier}",
            expected_path=path,
        )
        require_license(
            component=f"license:{identifier}",
            path=path,
            digest=entry["sha256"],
            source=f"container policy standard license text {identifier}",
        )

    for identifier, requirement in policy["custom_license_evidence"].items():
        for component_identity, pin in requirement["evidence"].items():
            component = component_by_identity[component_identity]
            if component["ecosystem"] == "alpine":
                manifest_component = f"alpine-{component['origin']}"
            elif component["ecosystem"] == "python":
                manifest_component = f"python-{component['name']}-{component['version']}"
            else:
                manifest_component = component_identity
            require_license(
                component=manifest_component,
                path=str(pin["path"]),
                digest=pin["sha256"],
                source=f"container policy custom-license evidence {identifier}/"
                f"{component_identity}",
            )

    for component in components:
        if component["ecosystem"] != "alpine":
            continue
        origin = str(component["origin"])
        commit = str(component["aports_commit"])
        recipe_key = f"{origin}@{commit}"
        recipe_url = (
            "https://gitlab.alpinelinux.org/alpine/aports/-/archive/"
            f"{commit}/aports-{commit}.tar.gz?path=main/{origin}"
        )
        require_source(
            component=f"alpine-{origin}-recipe",
            url=recipe_url,
            sha256=policy["alpine_recipe_archives"][recipe_key],
            source=f"container policy Alpine recipe {recipe_key}",
            expected_path=f"sources/alpine/{origin}/{commit}/recipe.tar.gz",
        )

    native_sources = policy["native_component_sources"]
    for source_id, pins in native_source_pins.items():
        native_source = native_sources[source_id]
        kind = native_source["kind"]
        source_directory = hashlib.sha256(source_id.encode()).hexdigest()[:20]
        for pin_index, pin in enumerate(pins):
            expected_path: str | None
            if "sha512" in pin:
                filename = str(pin["filename"])
                expected_path = f"sources/native-components/{source_directory}/distfiles/{filename}"
                require_source(
                    component=f"native-source:{source_id}",
                    url=pin["url"],
                    sha512=pin["sha512"],
                    size=pin["size"],
                    source=f"container policy native-component source {source_id} "
                    f"artifact {pin_index}",
                    expected_path=expected_path,
                )
                continue
            if kind == "alpine-aports":
                expected_path = f"sources/native-components/{source_directory}/recipe.tar.gz"
            elif kind == "crates-io":
                expected_path = (
                    f"sources/native-components/{source_directory}/"
                    f"{PurePosixPath(urllib.parse.urlparse(str(pin['url'])).path).name}"
                )
            elif kind == "checksummed-upstream-release":
                role = "archive" if pin is native_source["archive"] else "checksum"
                expected_path = (
                    f"sources/native-components/{source_directory}/{role}-"
                    f"{PurePosixPath(urllib.parse.urlparse(str(pin['url'])).path).name}"
                )
            else:
                expected_path = None
            require_source(
                component=f"native-source:{source_id}",
                url=pin["url"],
                sha256=pin["sha256"],
                size=pin["size"],
                source=f"container policy native-component source {source_id} artifact {pin_index}",
                expected_path=expected_path,
            )

        for notice in native_notice_pins[source_id]:
            basename = PurePosixPath(str(notice["member"])).name
            notice_path = (
                f"licenses/from-source/native-{source_directory}/"
                f"{str(notice['sha256'])[:12]}-{basename}"
            )
            require_license(
                component=None,
                path=notice_path,
                digest=notice["sha256"],
                size=notice["size"],
                source=f"container policy native-component source {source_id} notice",
            )

    policy_bound_paths: set[str] = set()
    for owner_record in configured_owners:
        owner = str(owner_record["owner"])
        owner_source = owner_record["owner_source"]
        owner_name, owner_version = owner.removeprefix("python:").rsplit("@", maxsplit=1)
        wheel = owner_record["wheel"]
        source_component = (
            f"native-wheelhouse-owner:{owner}"
            if isinstance(wheel, dict) and wheel.get("provider") == "native-wheelhouse"
            else f"python-{owner_name}-{owner_version}"
        )
        owner_matches = matching_sources(
            component=source_component,
            url=owner_source["url"],
            sha256=owner_source["sha256"],
            size=owner_source["size"],
        )
        if len(owner_matches) != 1:
            raise VerificationError(
                f"container policy native owner {owner} does not bind one retained source record"
            )
        cargo_lock = owner_record["cargo_lock"]
        if cargo_lock is not None:
            lock_path = (
                f"sources/cargo-locks/{hashlib.sha256(owner.encode()).hexdigest()[:20]}/Cargo.lock"
            )
            retained = members.get(lock_path)
            if (
                retained is None
                or retained.sha256 != cargo_lock["sha256"]
                or retained.size != cargo_lock["size"]
            ):
                raise VerificationError(
                    f"container policy native owner {owner} does not bind its retained Cargo.lock"
                )
            policy_bound_paths.add(lock_path)

    for source_id, native_source in native_sources.items():
        if native_source["kind"] != "owner-sdist-subpath":
            continue
        source_owner = str(native_source["owner"])
        owner_records = [
            owner_record
            for owner_record in configured_owners
            if owner_record["owner"] == source_owner
        ]
        if len(owner_records) != 1:
            raise VerificationError(
                f"container policy native-component source {source_id} "
                "does not name one reviewed owner"
            )
        owner_source = owner_records[0]["owner_source"]
        require_source(
            component=f"native-source:{source_id}",
            url=owner_source["url"],
            sha256=owner_source["sha256"],
            size=owner_source["size"],
            source=f"container policy native-component source {source_id}",
        )
        manifest_path = (
            "sources/native-components/"
            f"{hashlib.sha256(source_id.encode()).hexdigest()[:20]}/"
            "subtree-manifest.json"
        )
        if manifest_path not in members:
            raise VerificationError(
                f"container policy native-component source {source_id} "
                "has no retained subtree manifest"
            )
        if output is None:
            raise VerificationError(
                f"container policy native-component source {source_id} "
                "cannot read its retained subtree manifest"
            )
        _verify_owner_subtree_manifest(
            output.read(manifest_path, maximum=MAX_JSON_BYTES),
            source_id=source_id,
            native_source=native_source,
            json_budget=json_budget,
        )
        policy_bound_paths.add(manifest_path)

    return policy_bound_paths


def _verify_policy_and_coverage(
    policy: Mapping[str, Any],
    coverage: Mapping[str, Any],
    components: Mapping[str, Any],
    source_records: object,
    license_records: object,
    members: Mapping[str, MemberRecord],
    expected: ExpectedIdentity,
    base_image_index_digest: str,
    output: ExtractionRoot | None = None,
    json_budget: JsonBudget | None = None,
) -> set[str]:
    _exact_mapping(policy, POLICY_FIELDS, "container policy")
    if policy["schema_version"] != SCHEMA_VERSION:
        raise VerificationError("container policy has an unsupported schema")
    if policy["base_image_index_digest"] != base_image_index_digest:
        raise VerificationError("container policy and manifest disagree on the base image index")
    _oci_digest(policy["base_image_index_digest"], "container policy base image index")
    _digest(
        policy["native_wheelhouse_contract_sha256"],
        "container policy native wheelhouse contract digest",
    )

    base_image = _bounded_text(policy["base_image"], "container policy base image")
    base_match = re.fullmatch(
        r"python:((?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*))"
        r"-alpine([0-9]+\.[0-9]+)",
        base_image,
    )
    if base_match is None:
        raise VerificationError("container policy base image is not the reviewed CPython form")
    runtime_version, alpine_version = base_match.groups()

    base_platforms = _exact_mapping(
        policy["base_image_platforms"],
        set(PLATFORMS),
        "container policy base-image platforms",
    )
    base_layer_counts: dict[str, int] = {}
    for platform_name in PLATFORMS:
        platform_record = _exact_mapping(
            base_platforms[platform_name],
            {"layer_diff_ids"},
            f"container policy base-image platform {platform_name}",
        )
        layers = _bounded_list(
            platform_record["layer_diff_ids"],
            f"container policy base-image platform {platform_name} layers",
            nonempty=True,
        )
        if any(
            not isinstance(layer, str) or OCI_DIGEST.fullmatch(layer) is None for layer in layers
        ) or len(layers) != len(set(layers)):
            raise VerificationError(
                f"container policy base-image platform {platform_name} layers are invalid"
            )
        base_layer_counts[platform_name] = len(layers)

    platform_components = _exact_mapping(
        policy["platforms"],
        set(PLATFORMS),
        "container policy component platforms",
    )
    validated_platform_components: dict[str, list[Mapping[str, Any]]] = {}
    platform_identities: dict[str, set[str]] = {}
    for platform_name in PLATFORMS:
        validated, identities = _validate_component_list(
            platform_components[platform_name],
            f"container policy platform {platform_name}",
            platform=platform_name,
            runtime_version=runtime_version,
            base_layer_count=base_layer_counts[platform_name],
        )
        validated_platform_components[platform_name] = validated
        platform_identities[platform_name] = identities
    if platform_identities[PLATFORMS[0]] != platform_identities[PLATFORMS[1]]:
        raise VerificationError("container policy component identities differ across platforms")

    _exact_mapping(components, COMPONENT_INVENTORY_FIELDS, "component inventory")
    inventory_components, inventory_identities = _validate_component_list(
        components["components"],
        "component inventory",
        platform=expected.platform,
        runtime_version=runtime_version,
        base_layer_count=base_layer_counts[expected.platform],
    )
    if (
        inventory_components != validated_platform_components[expected.platform]
        or inventory_identities != platform_identities[expected.platform]
    ):
        raise VerificationError("component inventory differs from the reviewed platform policy")
    _digest(components["apk_database_sha256"], "component inventory APK database digest")
    for field in (
        "apk_database_occurrences",
        "apk_shared_libraries",
        "embedded_sboms",
        "native_payloads",
        "python_record_ownership",
        "wheel_identity_files",
        "wheel_installations",
    ):
        _bounded_list(components[field], f"component inventory {field}", maximum=250_000)

    approval = _exact_mapping(
        policy["distribution_approval"],
        {"approved", "approved_by", "approved_on", "rationale"},
        "container policy distribution approval",
    )
    if approval["approved"] is not True:
        raise VerificationError("container distribution does not have explicit approval")
    for field in ("approved_by", "approved_on", "rationale"):
        _bounded_text(approval[field], f"container distribution approval {field}")

    resolutions = policy["license_resolutions"]
    if not isinstance(resolutions, dict) or set(resolutions) != inventory_identities:
        raise VerificationError(
            "container policy license resolutions do not exactly cover the component inventory"
        )
    reviewed_expressions: list[str] = []
    custom_components: dict[str, set[str]] = {}
    for identity in sorted(inventory_identities):
        resolution = _exact_mapping(
            resolutions[identity],
            {"expression", "rationale"},
            f"container policy license resolution {identity}",
        )
        expression = _bounded_text(
            resolution["expression"],
            f"container policy license resolution {identity} expression",
            maximum=16 * 1024,
        )
        _standard, references = _validate_spdx_expression(
            expression,
            f"container policy license resolution {identity} expression",
        )
        _bounded_text(
            resolution["rationale"],
            f"container policy license resolution {identity} rationale",
            maximum=16 * 1024,
        )
        reviewed_expressions.append(expression)
        for identifier in references:
            custom_components.setdefault(identifier, set()).add(identity)

    native_sources = policy["native_component_sources"]
    if not isinstance(native_sources, dict) or len(native_sources) > 10_000:
        raise VerificationError("container policy native-component sources are invalid")
    native_source_pins: dict[str, list[Mapping[str, Any]]] = {}
    native_notice_pins: dict[str, list[Mapping[str, Any]]] = {}
    for source_id, native_source in native_sources.items():
        source_name = _bounded_text(
            source_id,
            "container policy native-component source identity",
            maximum=1056,
        )
        artifacts, notices = _validate_native_source(source_name, native_source)
        native_source_pins[source_name] = artifacts
        native_notice_pins[source_name] = notices

    configured_coverage = _exact_mapping(
        policy["native_component_coverage"],
        set(PLATFORMS),
        "container policy native-component coverage",
    )
    configured_owners: dict[str, list[Mapping[str, Any]]] = {}
    used_native_sources: set[str] = set()
    for platform_name in PLATFORMS:
        owner_records: list[Mapping[str, Any]] = []
        owner_names: list[str] = []
        platform_contexts: dict[str, Mapping[str, Any]] = {}
        for index, raw_owner in enumerate(
            _bounded_list(
                configured_coverage[platform_name],
                f"container policy native-component coverage {platform_name}",
                maximum=10_000,
            )
        ):
            owner, owner_sources, owner_expressions, owner_context = _validate_native_owner(
                raw_owner,
                f"container policy native-component coverage {platform_name} owner {index}",
                native_sources,
                platform=platform_name,
            )
            assert isinstance(raw_owner, dict)
            owner_records.append(raw_owner)
            owner_names.append(owner)
            platform_contexts[owner] = owner_context
            used_native_sources.update(owner_sources)
            reviewed_expressions.extend(owner_expressions)
            cargo_lock = owner_context["cargo_lock"]
            if platform_name == expected.platform and cargo_lock is not None and output is not None:
                lock_path = (
                    "sources/cargo-locks/"
                    f"{hashlib.sha256(owner.encode()).hexdigest()[:20]}/Cargo.lock"
                )
                retained = members.get(lock_path)
                if (
                    retained is None
                    or retained.sha256 != cargo_lock["sha256"]
                    or retained.size != cargo_lock["size"]
                ):
                    raise VerificationError(
                        f"container policy native owner {owner} does not bind "
                        "a readable retained Cargo.lock"
                    )
                _verify_cargo_lock_bytes(
                    output.read(lock_path, maximum=8 * 1024 * 1024),
                    owner=owner,
                    lock_context=cargo_lock,
                    native_sources=native_sources,
                    owner_context=owner_context,
                )
        if owner_names != sorted(owner_names) or len(owner_names) != len(set(owner_names)):
            raise VerificationError(
                f"container policy native-component owners for {platform_name} "
                "are not uniquely sorted"
            )
        configured_owners[platform_name] = owner_records
        _validate_native_relationships(platform_contexts, platform=platform_name)
    if used_native_sources != set(native_sources):
        raise VerificationError(
            "container policy native-component sources do not exactly cover reviewed consumers"
        )
    for source_id in used_native_sources:
        source_record = native_sources[source_id]
        if (
            isinstance(source_record, dict)
            and source_record.get("kind") == "crates-io"
            and isinstance(source_record.get("normalized_license"), str)
        ):
            reviewed_expressions.append(source_record["normalized_license"])

    standard_identifiers: set[str] = set()
    for index, expression in enumerate(reviewed_expressions):
        identifiers, _references = _validate_spdx_expression(
            expression,
            f"container policy reviewed license expression {index}",
        )
        standard_identifiers.update(identifiers)
    license_texts = _bounded_list(
        policy["license_texts"],
        "container policy standard license texts",
        maximum=10_000,
    )
    observed_license_ids: list[str] = []
    for index, item in enumerate(license_texts):
        license_text = _exact_mapping(
            item,
            {"id", "sha256", "url"},
            f"container policy standard license text {index}",
        )
        identifier = _bounded_text(
            license_text["id"],
            f"container policy standard license text {index} identifier",
            maximum=512,
        )
        if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.+-]*", identifier) is None:
            raise VerificationError(
                f"container policy standard license text {index} identifier is invalid"
            )
        _digest(
            license_text["sha256"],
            f"container policy standard license text {index} digest",
        )
        _https_url(
            license_text["url"],
            f"container policy standard license text {index} URL",
        )
        observed_license_ids.append(identifier)
    if (
        observed_license_ids != sorted(observed_license_ids)
        or len(observed_license_ids) != len(set(observed_license_ids))
        or set(observed_license_ids) != standard_identifiers
    ):
        raise VerificationError(
            "container policy standard license texts do not exactly cover reviewed expressions"
        )

    custom = policy["custom_license_evidence"]
    if not isinstance(custom, dict) or set(custom) != set(custom_components):
        raise VerificationError(
            "container policy custom-license evidence does not exactly cover LicenseRef use"
        )
    for identifier, expected_components in custom_components.items():
        requirement = _exact_mapping(
            custom[identifier],
            {"components", "evidence", "rationale", "require_source_notice"},
            f"container policy custom-license evidence {identifier}",
        )
        configured_components = _bounded_list(
            requirement["components"],
            f"container policy custom-license evidence {identifier} components",
            maximum=10_000,
        )
        evidence = requirement["evidence"]
        if (
            requirement["require_source_notice"] is not True
            or set(configured_components) != expected_components
            or len(configured_components) != len(set(configured_components))
            or not isinstance(evidence, dict)
            or set(evidence) != expected_components
        ):
            raise VerificationError(
                f"container policy custom-license evidence {identifier} "
                "does not match its component resolutions"
            )
        _bounded_text(
            requirement["rationale"],
            f"container policy custom-license evidence {identifier} rationale",
            maximum=16 * 1024,
        )
        for component_identity in expected_components:
            pinned = _exact_mapping(
                evidence[component_identity],
                {"path", "sha256"},
                f"container policy custom-license evidence {identifier}/{component_identity}",
            )
            path = _bounded_text(
                pinned["path"],
                f"container policy custom-license evidence {identifier}/{component_identity} path",
            )
            checked_path(path)
            _digest(
                pinned["sha256"],
                f"container policy custom-license evidence {identifier}/"
                f"{component_identity} digest",
            )

    unexpanded = _exact_mapping(
        policy["unexpanded_python_payloads"],
        set(PLATFORMS),
        "container policy unexpanded Python payloads",
    )
    for platform_name in PLATFORMS:
        categories = _exact_mapping(
            unexpanded[platform_name],
            {"embedded_sboms", "native_payloads", "wheel_identity_files"},
            f"container policy unexpanded Python payloads {platform_name}",
        )
        for category, raw_records in categories.items():
            for index, item in enumerate(
                _bounded_list(
                    raw_records,
                    f"container policy unexpanded Python payloads {platform_name} {category}",
                    maximum=250_000,
                )
            ):
                _validate_occurrence(
                    item,
                    f"container policy unexpanded Python payloads "
                    f"{platform_name} {category} {index}",
                )

    baselines = _exact_mapping(
        policy["filesystem_baselines"],
        set(PLATFORMS),
        "container policy filesystem baselines",
    )
    for platform_name in PLATFORMS:
        baseline = _exact_mapping(
            baselines[platform_name],
            FILESYSTEM_BASELINE_FIELDS,
            f"container policy filesystem baseline {platform_name}",
        )
        for category, raw_records in baseline.items():
            records = _bounded_list(
                raw_records,
                f"container policy filesystem baseline {platform_name} {category}",
                maximum=250_000,
            )
            for index, item in enumerate(records):
                item_source = (
                    f"container policy filesystem baseline {platform_name} {category} {index}"
                )
                if category in {
                    "apk_database_occurrences",
                    "post_base_apk_world_occurrences",
                    "post_base_system_regular_occurrences",
                }:
                    _validate_occurrence(item, item_source)
                elif category == "post_base_system_links":
                    link = _exact_mapping(
                        item,
                        {"gid", "kind", "layer", "mode", "path", "target", "uid"},
                        item_source,
                    )
                    if link["kind"] != "symlink":
                        raise VerificationError(f"{item_source} has an invalid kind")
                    path = _bounded_text(link["path"], f"{item_source} path")
                    checked_path(path)
                    _bounded_text(link["target"], f"{item_source} target")
                    _integer(
                        link["layer"],
                        f"{item_source} layer",
                        minimum=0,
                        maximum=MAX_MEMBERS,
                    )
                    _integer(link["mode"], f"{item_source} mode", minimum=0, maximum=0o7777)
                    _integer(
                        link["uid"],
                        f"{item_source} UID",
                        minimum=0,
                        maximum=2**31 - 1,
                    )
                    _integer(
                        link["gid"],
                        f"{item_source} GID",
                        minimum=0,
                        maximum=2**31 - 1,
                    )
                elif category == "post_base_directory_effects":
                    directory = _exact_mapping(
                        item,
                        {"gid", "layer", "mode", "path", "uid"},
                        item_source,
                    )
                    path = _bounded_text(directory["path"], f"{item_source} path")
                    checked_path(path)
                    for field, maximum in (
                        ("layer", MAX_MEMBERS),
                        ("mode", 0o7777),
                        ("uid", 2**31 - 1),
                        ("gid", 2**31 - 1),
                    ):
                        _integer(
                            directory[field],
                            f"{item_source} {field}",
                            minimum=0,
                            maximum=maximum,
                        )
                else:
                    removal = _exact_mapping(
                        item,
                        {"kind", "path", "target"},
                        item_source,
                    )
                    if removal["kind"] not in {"opaque", "whiteout"}:
                        raise VerificationError(f"{item_source} has an invalid kind")
                    checked_path(_bounded_text(removal["path"], f"{item_source} path"))
                    checked_path(_bounded_text(removal["target"], f"{item_source} target"))

    docker_recipe = _exact_mapping(
        policy["docker_python_recipe"],
        {"license_sha256", "license_url", "sha256", "url"},
        "container policy Docker Official Python recipe",
    )
    for field in ("sha256", "license_sha256"):
        _digest(
            docker_recipe[field],
            f"container policy Docker Official Python recipe {field}",
        )
    recipe_url = _https_url(
        docker_recipe["url"],
        "container policy Docker Official Python recipe URL",
    )
    recipe_license_url = _https_url(
        docker_recipe["license_url"],
        "container policy Docker Official Python recipe license URL",
    )
    recipe_match = re.fullmatch(
        rf"https://raw\.githubusercontent\.com/docker-library/python/"
        rf"([0-9a-f]{{40}})/{re.escape(runtime_version.rsplit('.', maxsplit=1)[0])}/"
        rf"alpine{re.escape(alpine_version)}/Dockerfile",
        recipe_url,
    )
    license_match = re.fullmatch(
        r"https://raw\.githubusercontent\.com/docker-library/python/"
        r"([0-9a-f]{40})/LICENSE",
        recipe_license_url,
    )
    if (
        recipe_match is None
        or license_match is None
        or recipe_match.group(1) != license_match.group(1)
    ):
        raise VerificationError(
            "container policy Docker Official Python recipe pins are inconsistent"
        )

    cpython = _exact_mapping(
        policy["cpython_source"],
        {
            "license_member",
            "license_sha256",
            "patchlevel_member",
            "patchlevel_sha256",
            "sha256",
            "size",
            "url",
        },
        "container policy CPython source",
    )
    expected_cpython_root = f"Python-{runtime_version}"
    expected_cpython_url = (
        f"https://www.python.org/ftp/python/{runtime_version}/{expected_cpython_root}.tar.xz"
    )
    if (
        cpython["url"] != expected_cpython_url
        or cpython["license_member"] != f"{expected_cpython_root}/LICENSE"
        or cpython["patchlevel_member"] != f"{expected_cpython_root}/Include/patchlevel.h"
    ):
        raise VerificationError("container policy CPython source identity is inconsistent")
    _https_url(cpython["url"], "container policy CPython source URL")
    for field in ("sha256", "license_sha256", "patchlevel_sha256"):
        _digest(cpython[field], f"container policy CPython source {field}")
    _integer(
        cpython["size"],
        "container policy CPython source size",
        minimum=1,
        maximum=MAX_MEMBER_BYTES,
    )
    for platform_name in PLATFORMS:
        runtime = next(
            component
            for component in validated_platform_components[platform_name]
            if component["ecosystem"] == "runtime"
        )
        if runtime["identity_files"]["version_header"]["sha256"] != cpython["patchlevel_sha256"]:
            raise VerificationError(
                f"container policy CPython source differs from {platform_name} runtime identity"
            )

    python_sources = _bounded_list(
        policy["python_sources"],
        "container policy Python source fallbacks",
        maximum=10_000,
    )
    python_source_identities: list[tuple[str, str]] = []
    for index, item in enumerate(python_sources):
        source = _exact_mapping(
            item,
            {"name", "sha256", "size", "url", "version"},
            f"container policy Python source fallback {index}",
        )
        name = _bounded_text(
            source["name"],
            f"container policy Python source fallback {index} name",
            maximum=512,
        )
        version = _bounded_text(
            source["version"],
            f"container policy Python source fallback {index} version",
            maximum=512,
        )
        _https_url(
            source["url"],
            f"container policy Python source fallback {index} URL",
        )
        _digest(
            source["sha256"],
            f"container policy Python source fallback {index} digest",
        )
        _integer(
            source["size"],
            f"container policy Python source fallback {index} size",
            minimum=0,
            maximum=MAX_MEMBER_BYTES,
        )
        python_source_identities.append((name, version))
    if python_source_identities != sorted(python_source_identities) or len(
        python_source_identities
    ) != len(set(python_source_identities)):
        raise VerificationError("container policy Python source fallbacks are not uniquely sorted")

    if policy["alpine_distfiles_release"] != f"v{alpine_version}":
        raise VerificationError(
            "container policy Alpine distfiles release disagrees with the base image"
        )
    recipe_archives = policy["alpine_recipe_archives"]
    if not isinstance(recipe_archives, dict) or len(recipe_archives) > 10_000:
        raise VerificationError("container policy Alpine recipe archive map is invalid")
    expected_recipe_keys = {
        f"{component['origin']}@{component['aports_commit']}"
        for component in inventory_components
        if component["ecosystem"] == "alpine"
    }
    if set(recipe_archives) != expected_recipe_keys:
        raise VerificationError(
            "container policy Alpine recipe archives do not exactly cover the inventory"
        )
    for recipe_key, digest in recipe_archives.items():
        _bounded_text(recipe_key, "container policy Alpine recipe identity", maximum=1056)
        _digest(digest, f"container policy Alpine recipe {recipe_key} digest")

    exceptions = policy["alpine_recipe_exceptions"]
    if not isinstance(exceptions, dict) or not set(exceptions) <= set(recipe_archives):
        raise VerificationError("container policy Alpine recipe exceptions are invalid")
    for recipe_key, raw_exception in exceptions.items():
        if (
            not isinstance(raw_exception, dict)
            or not raw_exception
            or not set(raw_exception) <= {"allow_dynamic_sources", "allowed_links", "rationale"}
        ):
            raise VerificationError(
                f"container policy Alpine recipe exception {recipe_key} is invalid"
            )
        dynamic = raw_exception.get("allow_dynamic_sources", False)
        links = raw_exception.get("allowed_links", [])
        if not isinstance(dynamic, bool) or not isinstance(links, list):
            raise VerificationError(
                f"container policy Alpine recipe exception {recipe_key} is invalid"
            )
        _bounded_text(
            raw_exception.get("rationale"),
            f"container policy Alpine recipe exception {recipe_key} rationale",
            maximum=16 * 1024,
        )
        if not dynamic and not links:
            raise VerificationError(
                f"container policy Alpine recipe exception {recipe_key} grants nothing"
            )
        for index, raw_link in enumerate(links):
            link = _exact_mapping(
                raw_link,
                {"path", "target", "type"},
                f"container policy Alpine recipe exception {recipe_key} link {index}",
            )
            path = _bounded_text(
                link["path"],
                f"container policy Alpine recipe exception {recipe_key} link {index} path",
            )
            target = _bounded_text(
                link["target"],
                f"container policy Alpine recipe exception {recipe_key} link {index} target",
            )
            if (
                str(checked_path(path)) != path
                or str(checked_path(target)) != target
                or PurePosixPath(path).parent != PurePosixPath(target).parent
                or path == target
                or link["type"] not in {"hardlink", "symlink"}
            ):
                raise VerificationError(
                    f"container policy Alpine recipe exception {recipe_key} link is invalid"
                )

    _exact_mapping(coverage, COVERAGE_FIELDS, "native-component coverage")
    remaining_owner_count = _integer(
        coverage["remaining_owner_count"],
        "native-component coverage remaining owner count",
        minimum=0,
        maximum=MAX_MEMBERS,
    )
    if (
        coverage["schema_version"] != SCHEMA_VERSION
        or coverage["platform"] != expected.platform
        or coverage["complete"] is not True
        or coverage["unresolved_owners"] != []
        or remaining_owner_count != 0
        or coverage["remaining_owner_names"] != []
        or not isinstance(coverage["resolved_owners"], list)
        or not isinstance(coverage["observed_sbom_anomalies"], list)
    ):
        raise VerificationError("native-component coverage is not completely closed")
    configured = policy.get("native_component_coverage")
    if (
        not isinstance(configured, dict)
        or configured_owners[expected.platform] != coverage["resolved_owners"]
    ):
        raise VerificationError("native-component coverage differs from reviewed policy")
    expected_anomalies: list[dict[str, Any]] = []
    for owner_record in configured_owners[expected.platform]:
        for sbom in owner_record["sboms"]:
            anomaly = sbom["metadata_root"]["anomaly_review"]
            if anomaly is not None:
                expected_anomalies.append(
                    {
                        "owner": owner_record["owner"],
                        "sbom_path": sbom["path"],
                        "observation_sha256": sbom["observation"]["observation_sha256"],
                        **anomaly,
                    }
                )
    if coverage["observed_sbom_anomalies"] != expected_anomalies:
        raise VerificationError(
            "native-component coverage anomaly ledger differs from reviewed policy"
        )
    return _verify_policy_source_and_license_relationships(
        policy=policy,
        components=inventory_components,
        source_records=source_records,
        license_records=license_records,
        members=members,
        runtime_version=runtime_version,
        native_source_pins=native_source_pins,
        native_notice_pins=native_notice_pins,
        configured_owners=configured_owners[expected.platform],
        output=output,
        json_budget=json_budget,
    )


def _markdown_cell(value: object) -> str:
    return str(value).replace("\\", "\\\\").replace("|", "\\|")


def _render_third_party_notices(
    components: Mapping[str, Any],
    policy: Mapping[str, Any],
    coverage: Mapping[str, Any],
    expected: ExpectedIdentity,
) -> bytes:
    """Reconstruct the deterministic human-readable notice from reviewed facts."""

    chunks: list[str] = []
    total = 0

    def append(value: str) -> None:
        nonlocal total
        try:
            encoded = value.encode("utf-8")
        except UnicodeEncodeError as exc:
            raise VerificationError("third-party notice data is not valid UTF-8") from exc
        total += len(encoded)
        if total > MAX_MEMBER_BYTES:
            raise VerificationError("third-party notice exceeds its size limit")
        chunks.append(value)

    append("# Third-party notices\n\n")
    append(
        "This inventory is evidence, not legal advice. License expressions are the reviewed "
        "project policy; the observed upstream metadata is retained separately.\n\n"
    )
    append("| Ecosystem | Component | Version | In effective filesystem | Observed | Reviewed |\n")
    append("| --- | --- | --- | --- | --- | --- |\n")
    inventory_components = sorted(
        components["components"],
        key=lambda component: (
            component["ecosystem"],
            component["name"],
            component["version"],
        ),
    )
    resolutions = policy["license_resolutions"]
    for component in inventory_components:
        identity = f"{component['ecosystem']}:{component['name']}@{component['version']}"
        observed = _markdown_cell(component["observed_license"]) or "Not declared"
        reviewed = _markdown_cell(resolutions[identity]["expression"])
        append(
            f"| {_markdown_cell(component['ecosystem'])} | "
            f"{_markdown_cell(component['name'])} | "
            f"{_markdown_cell(component['version'])} | "
            f"{'yes' if component['effective'] else 'no; retained in a lower layer'} | "
            f"{observed} | {reviewed} |\n"
        )

    native_sources = policy["native_component_sources"]
    configured = policy["native_component_coverage"][expected.platform]
    nested_components: set[tuple[str, ...]] = set()
    native_omissions: list[tuple[str, str, str, str]] = []
    for owner_index, owner_record in enumerate(configured):
        owner, _sources, _expressions, context = _validate_native_owner(
            owner_record,
            f"third-party notice owner {owner_index}",
            native_sources,
            platform=expected.platform,
        )
        for review_index, review in enumerate(owner_record["component_reviews"]):
            for reference_index, raw_reference in enumerate(review["observations"]):
                reference = _validate_observation_reference(
                    raw_reference,
                    f"third-party notice owner {owner_index} review {review_index} "
                    f"observation {reference_index}",
                )
                component = context["observations"][reference]
                nested_components.add(
                    (
                        owner,
                        str(component["name"]),
                        str(component["version"]),
                        str(component["purl"]),
                        str(component["bom_ref"]),
                        str(review["source"]),
                        canonical_json(component["licenses"]).decode("utf-8"),
                        str(review["reviewed_license"]),
                    )
                )
        native_omissions.extend(
            (
                owner,
                str(omission["id"]),
                ", ".join(omission["missing_evidence"]),
                str(omission["reason"]),
            )
            for omission in owner_record["known_omissions"]
        )
    if nested_components:
        append("\n## Native wheel components\n\n")
        append(
            "These occurrence identities and observed license fields come from the exact "
            "retained embedded SBOM bytes. Reviewed expressions are project policy.\n\n"
        )
        append(
            "| Owner | Component | Version | Package URL | bom-ref | Source | "
            "Observed licenses | Reviewed |\n"
        )
        append("| --- | --- | --- | --- | --- | --- | --- | --- |\n")
        for (
            owner,
            name,
            version,
            purl,
            bom_ref,
            source,
            observed_licenses,
            reviewed,
        ) in sorted(nested_components):
            append(
                f"| {_markdown_cell(owner)} | {_markdown_cell(name)} | "
                f"{_markdown_cell(version)} | {_markdown_cell(purl)} | "
                f"{_markdown_cell(bom_ref)} | {_markdown_cell(source)} | "
                f"{_markdown_cell(observed_licenses)} | {_markdown_cell(reviewed)} |\n"
            )
    if native_omissions:
        append("\n## Open native-component evidence\n\n")
        append(
            "These items are explicit gaps, not inferred approvals. Distribution remains "
            "incomplete while any item is open.\n\n"
        )
        append("| Owner | Item | Missing evidence | Exact reason |\n")
        append("| --- | --- | --- | --- |\n")
        for owner, omission_id, missing, reason in sorted(native_omissions):
            append(
                f"| {_markdown_cell(owner)} | {_markdown_cell(omission_id)} | "
                f"{_markdown_cell(missing)} | {_markdown_cell(reason)} |\n"
            )
    anomalies = coverage["observed_sbom_anomalies"]
    if anomalies:
        append("\n## Upstream SBOM anomalies\n\n")
        append("| Owner | SBOM | Observation digest | Anomaly | Review |\n")
        append("| --- | --- | --- | --- | --- |\n")
        for anomaly in anomalies:
            append(
                f"| {_markdown_cell(anomaly['owner'])} | "
                f"{_markdown_cell(anomaly['sbom_path'])} | "
                f"{_markdown_cell(anomaly['observation_sha256'])} | "
                f"{_markdown_cell(anomaly['kind'])} | "
                f"{_markdown_cell(anomaly['reason'])} |\n"
            )
    append(
        "\nThe archive includes the standard license texts named above, source-carried "
        "license and notice files, exact source archives, and commit-pinned Alpine "
        "recipes.\n"
    )
    return "".join(chunks).encode("utf-8")


def parse_checksums(
    raw: bytes,
    members: Mapping[str, MemberRecord],
) -> None:
    """Require canonical one-to-one checksum coverage for every other member."""

    if not raw.endswith(b"\n"):
        raise VerificationError("SHA256SUMS has no final line feed")
    expected_paths = set(members) - {"SHA256SUMS"}
    observed: list[str] = []
    for number, line in enumerate(raw[:-1].split(b"\n"), start=1):
        digest, separator, raw_path = line.partition(b"  ")
        if (
            len(digest) != 64
            or HEX64.fullmatch(digest.decode("ascii", "ignore")) is None
            or separator != b"  "
        ):
            raise VerificationError(f"SHA256SUMS line {number} is malformed")
        try:
            path = raw_path.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise VerificationError(f"SHA256SUMS line {number} path is not UTF-8") from exc
        checked_path(path)
        record = members.get(path)
        if record is None or record.sha256 != digest.decode("ascii"):
            raise VerificationError(f"SHA256SUMS line {number} does not match its member")
        observed.append(path)
    if (
        observed != sorted(observed, key=lambda path: path.encode("utf-8"))
        or len(observed) != len(set(observed))
        or set(observed) != expected_paths
    ):
        raise VerificationError("SHA256SUMS does not exactly and uniquely cover the archive")


def verify_content_contract(
    output: ExtractionRoot,
    archive: ArchiveResult,
    expected: ExpectedIdentity,
) -> tuple[str, str, str]:
    """Validate schema-9 relationships after raw bytes and checksums are trusted."""

    members = archive.members
    missing = REQUIRED_FILES - set(members)
    if missing:
        raise VerificationError(f"evidence archive is missing required files: {sorted(missing)}")
    for prefix in REQUIRED_PREFIXES:
        if not any(path.startswith(prefix) for path in members):
            raise VerificationError(f"evidence archive has no members below {prefix}")
    allowed = REQUIRED_FILES | {
        path for path in members if path.startswith(("artifacts/", "licenses/", "sources/"))
    }
    if set(members) != allowed:
        raise VerificationError("evidence archive contains an unsupported top-level path")

    checksums = output.read("SHA256SUMS", maximum=MAX_MEMBER_BYTES)
    parse_checksums(checksums, members)

    json_budget = JsonBudget()

    def load_json_member(path: str, source: str) -> tuple[Mapping[str, Any], str]:
        raw = output.read(path, maximum=MAX_JSON_BYTES)
        value = strict_json_bytes(raw, source, budget=json_budget)
        return value, hashlib.sha256(raw).hexdigest()

    manifest, manifest_sha256 = load_json_member("MANIFEST.json", "MANIFEST.json")
    policy, policy_sha256 = load_json_member(
        "policy/container-policy.json",
        "container policy",
    )
    components, _components_sha256 = load_json_member(
        "inventory/components.json",
        "component inventory",
    )
    files, _files_sha256 = load_json_member(
        "inventory/all-layer-files.json",
        "all-layer inventory",
    )
    coverage, _coverage_sha256 = load_json_member(
        "inventory/native-component-coverage.json",
        "native-component coverage",
    )
    contract, _contract_sha256 = load_json_member(
        "policy/native-wheelhouse-consumer.json",
        "native wheelhouse consumer contract",
    )
    consumer_store, _consumer_store_sha256 = load_json_member(
        "artifacts/native-wheelhouse/source.json",
        "native wheelhouse consumer store",
    )

    _exact_mapping(manifest, MANIFEST_FIELDS, "MANIFEST.json")
    if (
        manifest["schema_version"] != SCHEMA_VERSION
        or manifest["name"] != "extra-codeowners-container-distribution-evidence"
        or manifest["version"] != expected.version
        or manifest["platform"] != expected.platform
        or manifest["subject_digest"] != expected.subject_digest
    ):
        raise VerificationError("MANIFEST.json has the wrong release identity")
    base_image_index_digest = _oci_digest(
        manifest["base_image_index_digest"],
        "MANIFEST.json base image index digest",
    )
    if manifest["policy_sha256"] != policy_sha256:
        raise VerificationError("MANIFEST.json does not bind the retained policy")
    _bounded_text(manifest["legal_status"], "MANIFEST.json legal status", maximum=16 * 1024)

    _require_identity_record(components, "component inventory", expected)
    _require_identity_record(files, "all-layer inventory", expected)
    image_config_digest = _oci_digest(
        components.get("image_config_digest"),
        "component inventory image config digest",
    )
    if image_config_digest != files.get("image_config_digest"):
        raise VerificationError("component and all-layer inventories disagree on image config")
    if (
        components.get("image_revision") != expected.source_revision
        or components.get("image_version") != expected.version
    ):
        raise VerificationError("component inventory has the wrong application identity")
    if manifest["native_component_coverage"] != coverage:
        raise VerificationError("MANIFEST.json does not bind native-component coverage")
    completeness = _exact_mapping(
        manifest["source_completeness"],
        {"complete", "remaining_owner_count", "remaining_owner_names"},
        "MANIFEST.json source completeness",
    )
    remaining_owner_count = _integer(
        completeness["remaining_owner_count"],
        "MANIFEST.json remaining owner count",
        minimum=0,
        maximum=MAX_MEMBERS,
    )
    if (
        completeness["complete"] is not True
        or remaining_owner_count != 0
        or completeness["remaining_owner_names"] != []
    ):
        raise VerificationError("MANIFEST.json does not assert complete source coverage")

    source_paths = _verify_source_records(manifest["source_records"], members)
    _verify_application_source_record(manifest["source_records"], expected)
    license_paths = _verify_license_records(manifest["license_records"], members)
    policy_bound_source_paths = _verify_policy_and_coverage(
        policy,
        coverage,
        components,
        manifest["source_records"],
        manifest["license_records"],
        members,
        expected,
        base_image_index_digest,
        output,
        json_budget,
    )
    installations_by_owner = _validate_component_inventory_evidence(
        components,
        files,
        policy,
        expected,
    )
    _verify_application_source_archive(
        output.read(
            "sources/application/extra-codeowners.tar",
            maximum=MAX_MEMBER_BYTES,
        ),
        files,
        components,
        _application_license_member(manifest["license_records"], members),
        expected,
    )
    application_paths, wheel_sha256, selection_sha256 = _verify_application_artifacts(
        manifest["application_artifacts"],
        members,
        expected,
        installations_by_owner,
    )
    if (
        components.get("application_wheel_sha256") != wheel_sha256
        or components.get("application_selection_record_sha256") != selection_sha256
    ):
        raise VerificationError("component inventory does not bind selected application proof")
    wheelhouse_paths = _verify_wheelhouse_artifacts(
        manifest["native_wheelhouse_artifacts"],
        members,
        expected,
        policy,
        components,
        contract,
        consumer_store,
    )
    native_wheel_paths = _verify_native_wheels(
        manifest["native_wheel_artifacts"],
        members,
        expected,
        policy,
        installations_by_owner,
    )

    actual_sources = {path for path in members if path.startswith("sources/")}
    actual_licenses = {path for path in members if path.startswith("licenses/")}
    actual_artifacts = {path for path in members if path.startswith("artifacts/")}
    if not actual_sources <= source_paths | policy_bound_source_paths:
        raise VerificationError(
            "MANIFEST.json does not bind every retained source through its records "
            "or reviewed policy"
        )
    if not source_paths <= actual_sources | actual_licenses:
        raise VerificationError("MANIFEST.json source records point outside retained sources")
    if license_paths != actual_licenses:
        raise VerificationError("MANIFEST.json does not bind every retained license")
    wheelhouse_artifact_paths = wheelhouse_paths - {"policy/native-wheelhouse-consumer.json"}
    if application_paths | wheelhouse_artifact_paths | native_wheel_paths != actual_artifacts:
        raise VerificationError("MANIFEST.json does not bind every retained artifact")
    if wheelhouse_paths & {"policy/native-wheelhouse-consumer.json"} != {
        "policy/native-wheelhouse-consumer.json"
    }:
        raise VerificationError("native wheelhouse artifacts do not bind their policy contract")

    notices = output.read("THIRD_PARTY_NOTICES.md", maximum=MAX_MEMBER_BYTES)
    expected_notices = _render_third_party_notices(
        components,
        policy,
        coverage,
        expected,
    )
    if notices != expected_notices:
        raise VerificationError(
            "THIRD_PARTY_NOTICES.md differs from the validated inventory and policy"
        )
    return (
        manifest_sha256,
        policy_sha256,
        base_image_index_digest,
    )


def verify_predicate(
    raw: bytes,
    expected: ExpectedIdentity,
    archive: ArchiveResult,
    filename: str,
) -> str:
    predicate = strict_json_bytes(raw, "evidence predicate")
    _exact_mapping(predicate, PREDICATE_FIELDS, "evidence predicate")
    artifact = _exact_mapping(
        predicate["artifact"],
        {"filename", "sha256"},
        "evidence predicate artifact",
    )
    expected_url = f"https://github.com/{REPOSITORY}/releases/tag/v{expected.version}"
    if predicate != {
        "schema_version": SCHEMA_VERSION,
        "media_type": EVIDENCE_MEDIA_TYPE,
        "platform": expected.platform,
        "subject_digest": expected.subject_digest,
        "artifact": {"filename": filename, "sha256": archive.sha256},
        "release_url": expected_url,
    }:
        raise VerificationError("evidence predicate does not match the exact release artifact")
    if artifact["filename"] != filename or artifact["sha256"] != archive.sha256:
        raise VerificationError("evidence predicate artifact binding is invalid")
    return hashlib.sha256(raw).hexdigest()


def verify(
    *,
    archive_path: Path,
    checksum_path: Path,
    predicate_path: Path,
    output: Path,
    expected: ExpectedIdentity,
) -> dict[str, object]:
    """Verify all unsigned content relationships and materialize them safely."""

    validate_expected_identity(expected)
    filename = expected_archive_filename(expected)
    if archive_path.name != filename:
        raise VerificationError(f"archive filename must be exactly {filename}")
    if checksum_path.name != f"{filename}.sha256":
        raise VerificationError(f"checksum filename must be exactly {filename}.sha256")
    predicate_raw = read_stable_input(
        predicate_path,
        "evidence predicate",
        maximum=MAX_JSON_BYTES,
    )
    checksum_raw = read_stable_input(
        checksum_path,
        "archive checksum sidecar",
        maximum=1024,
    )
    with ExtractionRoot(output) as materialized:
        with open_stable_input(
            archive_path,
            "evidence archive",
            maximum=MAX_ARCHIVE_BYTES,
        ) as (descriptor, identity):
            archive = parse_archive(descriptor, identity.size, materialized, expected)
            expected_checksum = f"{archive.sha256}  {filename}\n".encode("ascii")
            if checksum_raw != expected_checksum:
                raise VerificationError("archive checksum sidecar does not match the exact archive")
            predicate_sha256 = verify_predicate(predicate_raw, expected, archive, filename)
            manifest_sha256, policy_sha256, base_image_index_digest = verify_content_contract(
                materialized,
                archive,
                expected,
            )
        materialized.commit()
    return {
        "archive": {
            "filename": filename,
            "sha256": archive.sha256,
            "size": archive.size,
        },
        "base_image_index_digest": base_image_index_digest,
        "kind": VERIFICATION_KIND,
        "manifest_sha256": manifest_sha256,
        "member_count": archive.member_count,
        "platform": expected.platform,
        "policy_sha256": policy_sha256,
        "predicate_sha256": predicate_sha256,
        "retained_bytes": archive.retained_bytes,
        "schema_version": VERIFIER_SCHEMA_VERSION,
        "source_date_epoch": expected.source_date_epoch,
        "source_revision": expected.source_revision,
        "subject_digest": expected.subject_digest,
        "version": expected.version,
    }


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(
        description=(
            "Verify the unsigned schema-9 structure and content bindings for one "
            "Extra CODEOWNERS container evidence archive."
        )
    )
    result.add_argument("--archive", required=True, type=Path)
    result.add_argument("--checksum", required=True, type=Path)
    result.add_argument("--predicate", required=True, type=Path)
    result.add_argument("--output", required=True, type=Path)
    result.add_argument("--version", required=True)
    result.add_argument("--platform", required=True, choices=("linux/amd64", "linux/arm64"))
    result.add_argument("--subject-digest", required=True)
    result.add_argument("--source-revision", required=True)
    result.add_argument("--source-date-epoch", required=True, type=int)
    return result


def main(argv: Sequence[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        result = verify(
            archive_path=args.archive,
            checksum_path=args.checksum,
            predicate_path=args.predicate,
            output=args.output,
            expected=ExpectedIdentity(
                version=args.version,
                platform=args.platform,
                subject_digest=args.subject_digest,
                source_revision=args.source_revision,
                source_date_epoch=args.source_date_epoch,
            ),
        )
    except VerificationError as exc:
        sys.stderr.write(f"recipient evidence verification failed: {exc}\n")
        return 1
    sys.stdout.buffer.write(canonical_json(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
