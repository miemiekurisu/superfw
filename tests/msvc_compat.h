/*
 * Compiler compatibility shims for building the native host tests with MSVC.
 *
 * This is force-included (cl /FI) by tests/msvc_build.py and is never used by
 * the arm-none-eabi firmware build.  It lets the same test sources compile
 * with a plain Visual Studio install without touching any firmware source.
 */
#ifndef SUPERFW_TESTS_MSVC_COMPAT_H
#define SUPERFW_TESTS_MSVC_COMPAT_H

#if defined(_MSC_VER)

#include <stdlib.h>

/* The firmware uses the GCC byte-swap builtins. */
#define __builtin_bswap16  _byteswap_ushort
#define __builtin_bswap32  _byteswap_ulong
#define __builtin_bswap64  _byteswap_uint64
#endif /* _MSC_VER */
#endif /* SUPERFW_TESTS_MSVC_COMPAT_H */
