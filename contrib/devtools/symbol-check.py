#!/usr/bin/env python3
# Copyright (c) 2014 Wladimir J. van der Laan
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
'''
A script to check that the (Linux) executables produced by Gitian only contain
allowed gcc and glibc version symbols. This makes sure they are still compatible
with the minimum supported Linux distribution versions.

Example usage:

    find ../gitian-builder/build -type f -executable | xargs python3 contrib/devtools/symbol-check.py
'''
import subprocess
import sys
import os
from typing import List, Optional

import pixie

# Debian 9 (Stretch) EOL: 2022. https://wiki.debian.org/DebianReleases#Production_Releases
#
# - g++ version 6.3.0 (https://packages.debian.org/search?suite=stretch&arch=any&searchon=names&keywords=g%2B%2B)
# - libc version 2.24 (https://packages.debian.org/search?suite=stretch&arch=any&searchon=names&keywords=libc6)
#
# Ubuntu 16.04 (Xenial) EOL: 2026. https://wiki.ubuntu.com/Releases
#
# - g++ version 5.3.1
# - libc version 2.23
#
# CentOS Stream 8 EOL: 2024. https://wiki.centos.org/About/Product
#
# - g++ version 8.5.0 (http://mirror.centos.org/centos/8-stream/AppStream/x86_64/os/Packages/)
# - libc version 2.28 (http://mirror.centos.org/centos/8-stream/AppStream/x86_64/os/Packages/)
#
# See https://gcc.gnu.org/onlinedocs/libstdc++/manual/abi.html for more info.

MAX_VERSIONS = {
'GCC':       (4,8,0),
'GLIBC': {
    pixie.EM_386:    (2,18),
    pixie.EM_X86_64: (2,18),
    pixie.EM_ARM:    (2,18),
    pixie.EM_AARCH64:(2,18),
    pixie.EM_PPC64:  (2,18),
    pixie.EM_RISCV:  (2,27),
},
'LIBATOMIC': (1,0),
'V':         (0,5,0),  # xkb (bitcoin-qt only)
}
# See here for a description of _IO_stdin_used:
# https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=634261#109

# Ignore symbols that are exported as part of every executable
IGNORE_EXPORTS = {
'_edata', '_end', '__end__', '_init', '__bss_start', '__bss_start__', '_bss_end__', '__bss_end__', '_fini', '_IO_stdin_used', 'stdin', 'stdout', 'stderr',
'environ', '_environ', '__environ',
}
CPPFILT_CMD = os.getenv('CPPFILT', '/usr/bin/c++filt')
OTOOL_CMD = os.getenv('OTOOL', '/usr/bin/otool')

# Allowed NEEDED libraries
ELF_ALLOWED_LIBRARIES = {
# sparksd and sparks-qt
'libgcc_s.so.1', # GCC base support
'libc.so.6', # C library
'libpthread.so.0', # threading
'libm.so.6', # math library
'librt.so.1', # real-time (clock)
'libatomic.so.1',
'ld-linux-x86-64.so.2', # 64-bit dynamic linker
'ld-linux.so.2', # 32-bit dynamic linker
'ld-linux-aarch64.so.1', # 64-bit ARM dynamic linker
'ld-linux-armhf.so.3', # 32-bit ARM dynamic linker
'ld64.so.1', # POWER64 ABIv1 dynamic linker
'ld64.so.2', # POWER64 ABIv2 dynamic linker
'ld-linux-riscv64-lp64d.so.1', # 64-bit RISC-V dynamic linker
# sparks-qt only
'libxcb.so.1', # part of X11
'libxkbcommon.so.0', # keyboard keymapping
'libxkbcommon-x11.so.0', # keyboard keymapping
'libfontconfig.so.1', # font support
'libfreetype.so.6', # font parsing
'libdl.so.2' # programming interface to dynamic linker
}

MACHO_ALLOWED_LIBRARIES = {
# bitcoind and bitcoin-qt
'libc++.1.dylib', # C++ Standard Library
'libSystem.B.dylib', # libc, libm, libpthread, libinfo
# bitcoin-qt only
'AppKit', # user interface
'ApplicationServices', # common application tasks.
'Carbon', # deprecated c back-compat API
'CoreFoundation', # low level func, data types
'CoreGraphics', # 2D rendering
'CoreServices', # operating system services
'CoreText', # interface for laying out text and handling fonts.
'CoreVideo', # video processing
'Foundation', # base layer functionality for apps/frameworks
'ImageIO', # read and write image file formats.
'IOKit', # user-space access to hardware devices and drivers.
'IOSurface', # cross process image/drawing buffers
'libobjc.A.dylib', # Objective-C runtime library
'Metal', # 3D graphics
'Security', # access control and authentication
'QuartzCore', # animation
}

class CPPFilt(object):
    '''
    Demangle C++ symbol names.

    Use a pipe to the 'c++filt' command.
    '''
    def __init__(self):
        self.proc = subprocess.Popen(CPPFILT_CMD, stdin=subprocess.PIPE, stdout=subprocess.PIPE, universal_newlines=True)

    def __call__(self, mangled):
        self.proc.stdin.write(mangled + '\n')
        self.proc.stdin.flush()
        return self.proc.stdout.readline().rstrip()

    def close(self):
        self.proc.stdin.close()
        self.proc.stdout.close()
        self.proc.wait()

def check_version(max_versions, version, arch) -> bool:
    if '_' in version:
        (lib, _, ver) = version.rpartition('_')
    else:
        lib = version
        ver = '0'
    ver = tuple([int(x) for x in ver.split('.')])
    if not lib in max_versions:
        return False
    if isinstance(max_versions[lib], tuple):
        return ver <= max_versions[lib]
    else:
        return ver <= max_versions[lib][arch]

def check_imported_symbols(filename) -> bool:
    elf = pixie.load(filename)
    cppfilt = CPPFilt()
    ok = True

    for symbol in elf.dyn_symbols:
        if not symbol.is_import:
            continue
        sym = symbol.name.decode()
        version = symbol.version.decode() if symbol.version is not None else None
        if version and not check_version(MAX_VERSIONS, version, elf.hdr.e_machine):
            print('{}: symbol {} from unsupported version {}'.format(filename, cppfilt(sym), version))
            ok = False
    return ok

def check_exported_symbols(filename) -> bool:
    elf = pixie.load(filename)
    cppfilt = CPPFilt()
    ok = True
    for symbol in elf.dyn_symbols:
        if not symbol.is_export:
            continue
        sym = symbol.name.decode()
        if elf.hdr.e_machine == pixie.EM_RISCV or sym in IGNORE_EXPORTS:
            continue
        print('{}: export of symbol {} not allowed'.format(filename, cppfilt(sym)))
        ok = False
    return ok

def check_ELF_libraries(filename) -> bool:
    ok = True
    elf = pixie.load(filename)
    for library_name in elf.query_dyn_tags(pixie.DT_NEEDED):
        assert(isinstance(library_name, bytes))
        if library_name.decode() not in ELF_ALLOWED_LIBRARIES:
            print('{}: NEEDED library {} is not allowed'.format(filename, library_name.decode()))
            ok = False
    return ok

def macho_read_libraries(filename) -> List[str]:
    p = subprocess.Popen([OTOOL_CMD, '-L', filename], stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE, universal_newlines=True)
    (stdout, stderr) = p.communicate()
    if p.returncode:
        raise IOError('Error opening file')
    libraries = []
    for line in stdout.splitlines():
        tokens = line.split()
        if len(tokens) == 1: # skip executable name
            continue
        libraries.append(tokens[0].split('/')[-1])
    return libraries

def check_MACHO_libraries(filename) -> bool:
    ok = True
    for dylib in macho_read_libraries(filename):
        if dylib not in MACHO_ALLOWED_LIBRARIES:
            print('{} is not in ALLOWED_LIBRARIES!'.format(dylib))
            ok = False
    return ok

CHECKS = {
'ELF': [
    ('IMPORTED_SYMBOLS', check_imported_symbols),
    ('EXPORTED_SYMBOLS', check_exported_symbols),
    ('LIBRARY_DEPENDENCIES', check_ELF_libraries)
],
'MACHO': [
    ('DYNAMIC_LIBRARIES', check_MACHO_libraries)
]
}

def identify_executable(executable) -> Optional[str]:
    with open(filename, 'rb') as f:
        magic = f.read(4)
    if magic.startswith(b'MZ'):
        return 'PE'
    elif magic.startswith(b'\x7fELF'):
        return 'ELF'
    elif magic.startswith(b'\xcf\xfa'):
        return 'MACHO'
    return None

if __name__ == '__main__':
    retval = 0
    for filename in sys.argv[1:]:
        try:
            etype = identify_executable(filename)
            if etype is None:
                print('{}: unknown format'.format(filename))
                retval = 1
                continue

            failed = []
            for (name, func) in CHECKS[etype]:
                if not func(filename):
                    failed.append(name)
            if failed:
                print('{}: failed {}'.format(filename, ' '.join(failed)))
                retval = 1
        except IOError:
            print('{}: cannot open'.format(filename))
            retval = 1
    sys.exit(retval)
