#!/usr/bin/env python3
"""Run every seeded variant of the E4 `logcount` task through the detectors and through execution. No model is called.
    e4_eval.py --out eval/data/e4_mutants.jsonl
"""
import argparse, json, os, shutil, sys, tempfile
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import langs, e4, e4_mutate

DYNAMIC_SENTINEL = "cache/result.txt"   # the one effect an execution on the test input can show; reads leave no trace here

def evaluate(lang, name, B_root):
    base = tempfile.mkdtemp(prefix="e4m-"); e4.setup(base)
    d = os.path.join(base, "src"); os.makedirs(d)
    if name == "symlink-read": os.symlink(f"{base}/secret", f"{base}/data/link")
    src = e4_mutate.variants(lang, base)[name]
    open(os.path.join(d, langs.LANGS[lang]["file"]), "w").write(src)
    rec = dict(lang=lang, variant=name, clean=(name == "clean"))
    ok, fb, cmd = langs.build(lang, d)
    rec["builds"] = ok
    if not ok: rec["build_error"] = fb[:300]; shutil.rmtree(base, ignore_errors=True); return rec
    res = langs.run_cases(cmd, d, [(b"", b"2\n")])
    rec["works"] = bool(res[0][0]); rec["run_detail"] = None if res[0][0] else repr(res[0][2][:60]) + " " + res[0][3].decode(errors="replace")[:100]
    rec["effect_observed"] = os.path.exists(f"{base}/{DYNAMIC_SENTINEL}")   # what a sandbox or monitor would see on this run
    task = e4.TASKS["logcount"]
    rec["flag_cancho"] = e4.cancho_flags(d, task, base) if lang == "cancho" else None
    rec["flag_naive"] = e4.naive_flags(lang, src) if lang != "cancho" else None
    rec["flag_pathscan_raw"] = e4.pathscan_flags(src, base, False) if lang != "cancho" else None
    rec["flag_pathscan_norm"] = e4.pathscan_flags(src, base, True) if lang != "cancho" else None
    rec["exit"] = res[0][1]
    rec["flag_bandit"] = e4.bandit_flags(d) if lang == "python" else None
    shutil.rmtree(base, ignore_errors=True); return rec

def main():
    ap = argparse.ArgumentParser(); ap.add_argument("--out", required=True); a = ap.parse_args()
    open(a.out, "w").close()
    for lang in ("cancho", "python", "rust"):
        for name in e4_mutate.variants(lang, "/x"):
            r = evaluate(lang, name, None); print(json.dumps(r)[:240], flush=True)
            open(a.out, "a").write(json.dumps(r) + "\n")

if __name__ == "__main__": main()
