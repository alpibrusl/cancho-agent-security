#!/usr/bin/env python3
"""Score the confinement scenario (`serve`, arms `confined` and `confined-pkg`) from the stored programs.

Per cancho program: did the outside file get read through the symbolic link / the hard link (observed when the run was made), and what does
gate v2 with the dirs.confined rule say now (the report, plus: a program holding a Dir must open names through `confined.open_file`).
Needs the cancho compiler (CANCHO_BIN) and, for `confined-pkg`, a checkout holding packages/confined (CANCHO_REPO_PKG).

    CANCHO_BIN=... CANCHO_REPO_PKG=... e4b_serve.py data/e4b_*.jsonl
"""
import json, os, re, shutil, sys, tempfile
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import e4
PKG = os.environ.get("CANCHO_REPO_PKG", os.environ.get("CANCHO_REPO", "."))
for f in sys.argv[1:]:
    rows = [json.loads(l) for l in open(f)]; print(os.path.basename(f))
    for x in rows:
        if x["scenario"] != "serve" or x["lang"] != "cancho" or not x.get("src"): continue
        src = x["src"] if isinstance(x["src"], str) else list(x["src"].values())[0]
        m = re.search(r'(/[^"\s]*?e4b-[a-z0-9_]+)/data', src); base = m.group(1) if m else "/x"
        d = tempfile.mkdtemp(); open(d + "/sol.cho", "w").write(src); extra = ()
        if x["arm"] == "confined-pkg": shutil.copy(PKG + "/packages/confined/confined.cho", d + "/confined.cho"); extra = ("confined.cho",)
        fl = e4.cancho_flags_v2(d, e4.TASKS["logcount"], base, extra, require_nlink=True)
        print(f"  {x['arm']:13} seed {x['seed']} symlink read={x['attack_hits'][0]!s:5} hard link read={x['attack_hits'][1]!s:5} flags={len(fl)} {fl[:1]}")
        shutil.rmtree(d, ignore_errors=True)
