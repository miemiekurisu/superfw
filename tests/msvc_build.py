"""Build the native host tests with MSVC (or any cl.exe on PATH).

The Makefile "host-tests" target is written for gcc/MinGW.  This script does
the same thing with cl.exe so the suite is runnable from a plain Visual Studio
install.  It locates the compiler with vswhere, imports the vcvars64
environment, then compiles and runs each test.

Usage (from the repo root):  python tests/msvc_build.py [test ...]
"""
import os
import subprocess as sp
import sys

HERE = os.path.abspath(os.path.dirname(__file__))
VSWHERE = r"C:\Program Files (x86)\Microsoft Visual Studio\Installer\vswhere.exe"

TESTS = {
    "cimpl": ["cimpl_test.c", "../src/cimpl.c"],
    "util": ["util_test.c", "../src/util.c", "../src/nanoprintf.c", "../src/fileutil.c"],
    "utf": ["utf_util_test.c", "../src/utf_util.c"],
    "crc": ["crc_test.c", "../src/crc.c"],
    "cheats": ["cheats_test.c", "../src/cheats.c", "../src/util.c", "../src/nanoprintf.c"],
    "patch-hardening": ["hardening_test.c", "../src/cheats.c", "../src/util.c",
                        "../src/nanoprintf.c"],
    "directsave": ["directsave_test.c"],
    "patchengine": ["patchengine_test.c", "../src/util.c", "../src/nanoprintf.c"],
}

# Mirrors the per-target switches of the gcc "host-tests" Makefile rules.
EXTRA_FLAGS = {
    "cimpl": ["/DBUILTIN_PREFIX=superfw_"],
}

FLAGS = [
    "/std:c17", "/Od", "/Zi", "/W3", "/nologo", "/I../src/", "/I../",
    # The sources and the tests are UTF-8 but contain no BOM; without this,
    # cl reads them in the system codepage and string literals break.
    "/utf-8",
    # The host tests deliberately use strcpy/sprintf on small buffers.
    "/D_CRT_SECURE_NO_WARNINGS",
    # size_t -> UINT narrowing is harmless on a 64-bit host test.
    "/wd4267", "/wd4244", "/wd4018",
    # GCC byte-swap builtins used by src/cheats.c and the hardening tests.
    "/FI" + os.path.join(HERE, "msvc_compat.h"),
]


def vcvars_env():
    """Return an environment block plus the absolute cl.exe path."""
    env = dict(os.environ)

    def merge(updates):
        for k, v in updates.items():
            for existing in [e for e in env if e.upper() == k.upper()]:
                del env[existing]
            env[k] = v

    bat = None
    if os.path.isfile(VSWHERE):
        probe = sp.run([VSWHERE, "-latest", "-products", "*",
                        "-property", "installationPath"],
                       capture_output=True, text=True)
        if probe.returncode == 0 and probe.stdout.strip():
            cand = os.path.join(probe.stdout.strip(), "VC", "Auxiliary", "Build",
                                "vcvars64.bat")
            if os.path.isfile(cand):
                bat = cand
    if bat is None:
        sys.exit("no Visual Studio found -- run this from a "
                 "Developer Command Prompt instead")

    out = sp.run('call "%s" >nul 2>&1 && set' % bat, shell=True,
                 capture_output=True, text=True).stdout
    update = {}
    for line in out.splitlines():
        if "=" in line:
            k, _, v = line.partition("=")
            update[k] = v
    merge(update)
    root = update.get("VCToolsInstallDir", "")
    cl = os.path.join(root, "bin", "Hostx64", "x64", "cl.exe")
    if not os.path.isfile(cl):
        sys.exit("cl.exe not found at " + cl)
    return env, cl


def main(argv):
    env, cl = vcvars_env()
    print("cl", env.get("VCToolsVersion", "?"), "at", os.path.dirname(cl))
    want = argv or list(TESTS)
    failed = []
    for name in want:
        srcs = TESTS[name]
        outdir = os.path.join(HERE, "msvc-build")
        if not os.path.isdir(outdir):
            os.mkdir(outdir)
        exe = os.path.join(outdir, "test-%s.exe" % name)
        for stale in (exe, exe.replace(".exe", ".ilk"),
                      os.path.join(outdir, "test-%s.pdb" % name)):
            if os.path.isfile(stale):
                os.remove(stale)
        cmd = ([cl] + FLAGS + EXTRA_FLAGS.get(name, []) +
               ["/Fe:" + exe, "/Fo:" + outdir + os.sep,
                "/Fd:" + os.path.join(outdir, "test-%s.pdb" % name)] + srcs)
        r = sp.run(cmd, env=env, capture_output=True, text=True, cwd=HERE)
        if r.returncode != 0:
            failed.append(name)
            print("== %s: COMPILE FAILED" % name)
            print(r.stdout.strip()[:1500])
            print(r.stderr.strip()[:1500])
            continue
        r = sp.run([exe], env=env, capture_output=True, text=True, cwd=HERE)
        if r.returncode != 0:
            print("== %s: FAILED (exit %d)" % (name, r.returncode))
            print("\n".join(r.stdout.strip().splitlines()[-25:]))
            print("\n".join(r.stderr.strip().splitlines()[-10:]))
            failed.append(name)
        else:
            summary = [l for l in r.stdout.splitlines() if l.strip()]
            print("== %s: ok%s" %
                  (name, " | " + summary[-1] if summary else ""))
    print("MSVC host tests: %d/%d passed" % (len(want) - len(failed), len(want)))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
