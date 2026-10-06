#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Summarises the gcov JSON output produced by "make host-coverage" for the
# hardened firmware sources.  Several test binaries touch the same file, so the
# per-line counts of every JSON file get merged before anything is computed.

import argparse
import collections
import glob
import gzip
import json
import os
import sys

HARDENED = [
    "src/patcher.c",
    "src/patchengine.c",
    "src/directsave_emu.c",
    "src/cheats.c",
]

# line number -> [executions, branch outcomes, branch outcomes taken]
Coverage = collections.defaultdict(dict)


def normalise(name):
    name = name.replace("\\", "/")
    while name.startswith("../"):
        name = name[3:]
    return name.lstrip("./")


def load(pattern):
    paths = sorted(glob.glob(pattern))
    if not paths:
        sys.exit("no gcov JSON files matching %r -- run 'make host-coverage'"
                 % pattern)
    for path in paths:
        with gzip.open(path, "rb") as f:
            data = json.load(f)
        for node in data.get("files", []):
            lines = Coverage[normalise(node["file"])]
            for line in node["lines"]:
                entry = lines.setdefault(line["line_number"], [0, 0, 0])
                entry[0] += line["count"]
                entry[1] += len(line.get("branches", []))
                entry[2] += sum(1 for b in line.get("branches", [])
                                if b["count"] > 0)
    return paths


def source(path):
    for candidate in (os.path.join("..", path), path,
                      os.path.join("tests", path)):
        if os.path.isfile(candidate):
            with open(candidate, "r", encoding="utf-8", errors="replace") as f:
                return f.read().splitlines()
    return []


def main():
    ap = argparse.ArgumentParser(description="gcov summary for host-coverage")
    ap.add_argument("--json", default="*.gcov.json.gz", help="gcov JSON glob")
    ap.add_argument("--strict", action="store_true",
                    help="fail unless every hardened source has full line"
                         " and branch coverage")
    ap.add_argument("-v", "--verbose", action="store_true",
                    help="list the lines with untaken branch outcomes")
    args = ap.parse_args()

    paths = load(args.json)
    print("merged %d gcov data file(s)" % len(paths))
    print("%-26s %14s %16s" % ("file", "lines", "branches"))

    ok = True
    tot = [0, 0, 0, 0]
    for name in HARDENED:
        lines = Coverage.get(name)
        if lines is None:
            print("%-26s NOT INSTRUMENTED" % name)
            ok = False
            continue
        ltot = len(lines)
        lexec = sum(1 for e in lines.values() if e[0] > 0)
        btot = sum(e[1] for e in lines.values())
        btaken = sum(e[2] for e in lines.values())
        tot[0] += lexec
        tot[1] += ltot
        tot[2] += btaken
        tot[3] += btot
        print("%-26s %6d/%-6d %5.1f%% %6d/%-6d %5.1f%%" %
              (name, lexec, ltot, 100.0 * lexec / max(ltot, 1),
               btaken, btot, 100.0 * btaken / max(btot, 1)))
        if lexec != ltot or (args.strict and btaken != btot):
            ok = False
        if args.verbose:
            src = source(name)
            for num in sorted(lines):
                taken = lines[num][1] - lines[num][2]
                if taken > 0 and lines[num][0] > 0:
                    text = src[num - 1].strip() if num <= len(src) else "?"
                    print("    %s:%d  %d/%d untaken | %s" %
                          (name, num, taken, lines[num][1], text[:88]))

    print("%-26s %6d/%-6d %5.1f%% %6d/%-6d %5.1f%%" %
          ("TOTAL", tot[0], tot[1], 100.0 * tot[0] / max(tot[1], 1),
           tot[2], tot[3], 100.0 * tot[2] / max(tot[3], 1)))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
