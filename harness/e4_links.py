#!/usr/bin/env python3
"""E4d: links and process launching, the weaknesses found in E4c, through the gate before and after its two new rules.

A directory `data/` holds a plain file, a symbolic link to a directory outside it, and a hard link to a file outside it. Six cancho
programs read one of them, through the `Fs` form (a text prefix) and through the `Dir` form (`open_dir`, then `std.dirs.open_file`).
Per program: did the outside file get read (exit 3), what does gate v1 say (the report diffed with the budget), and what does gate v2
say (v1 plus: a lexical `fs_read` is flagged when confinement is required). A second block launches a program under `Exec` narrowed
to a directory and to one program, and records what the report says and whether a second program can be started.

    CANCHO_BIN=... e4_links.py [--out data/e4_links.jsonl]
"""
import argparse, json, os, shutil, subprocess, sys, tempfile
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import e4, langs
PKG = os.environ.get("CANCHO_REPO_PKG", os.environ.get("CANCHO_REPO", "."))

FS_PROG = '''fn peek[&f, &o](fs: &f Fs("{B}/data"), out: &!o [byte]) -> [fs_read("{B}/data")] int {
    return fs_read(fs, "{B}/data/{NAME}", out);
}
fn main(world: World) -> [] int {
    let Split { io, ffi, fs, heap, args } = split(world);
    release(io); release(ffi); release(args);
    let data = narrow(fs, "{B}/data");
    var n = 0 - 1;
    borrow mut heap as &!h in {
        let buf = box_slice(h, 64, byte_of(0));
        borrow data as &d in { borrow mut buf as &!w in { n = peek(d, contents(w)); } }
        unbox_slice(h, buf);
    }
    release(data); release(heap);
    if n > 0 { return 3; }
    return 0;
}
'''
DIR_PROG = '''edition 6;

import std.dirs;

fn main(world: World) -> [] int {
    let Split { io, ffi, fs, heap, args, net, clock, signals } = split(world);
    release(io); release(ffi); release(args); release(heap); release(net); release(clock); release(signals);
    let data = narrow(fs, "{B}/data");
    var got = 0;
    borrow data as &f in {
        match open_dir(f, "{B}/data") {
            DirOpened::Ok(d) => {
                var held = d;
                borrow held as &h in {
                    match dirs.open_file(h, "{NAME}") {
                        Opened::Ok(file) => {
                            got = 1;
                            file_close(file);
                        }
                        Opened::Failed(why) => {
                        }
                    }
                }
                dir_close(held);
            }
            DirOpened::Failed(why) => {
            }
        }
    }
    release(data);
    if got == 1 { return 3; }
    return 0;
}
'''
# the same, through the package that also refuses a file with more than one name (packages/confined, built beside the program)
CONF_PROG = DIR_PROG.replace("import std.dirs;", "import dirs.confined;").replace("dirs.open_file(h, \"{NAME}\")", "confined.open_file(h, \"{NAME}\")")

# exec: launch /usr/bin/true (harmless) or /usr/bin/env, under an Exec narrowed to a directory or to one program
EXEC_PROG = '''edition 7;

fn go[&x](exec: &x Exec("{NARROW}")) -> [exec("{NARROW}")] int {
    var status = 0 - 1;
    match exec_spawn(exec, "{PROG}", "", "", Stdio::Null, Stdio::Null, Stdio::Null) {
        Spawned::Failed(e) => {
        }
        Spawned::Ok(child) => {
            match child_wait(child) {
                Exited::Code(n) => { status = n; }
                Exited::Signaled(sg) => { }
                Exited::Failed(e) => { }
            }
        }
    }
    return status;
}

fn main(world: World) -> [] int {
    let Split { io, ffi, fs, heap, args, net, clock, signals, exec } = split(world);
    release(io); release(ffi); release(fs); release(heap); release(args); release(net); release(clock); release(signals);
    var st = 0 - 1;
    let ex = narrow(exec, "{NARROW}");
    borrow ex as &xx in { st = go(xx); }
    release(ex);
    if st == 0 { return 3; }
    return 0;
}
'''
LINK_CASES = [("confined", "plain", "input.log"), ("confined", "symlink", "link/token.txt"), ("confined", "hardlink", "hl.txt"), ("fs", "plain", "input.log"), ("fs", "symlink", "link/token.txt"), ("fs", "hardlink", "hl.txt"),
              ("dir", "plain", "input.log"), ("dir", "symlink", "link/token.txt"), ("dir", "hardlink", "hl.txt")]
EXEC_CASES = [("exec", "directory, launches the listed program", "/usr/bin", "/usr/bin/true"),
              ("exec", "directory, launches another program", "/usr/bin", "/usr/bin/env"),
              ("exec", "one program, launches it", "/usr/bin/true", "/usr/bin/true"),
              ("exec", "one program, launches another", "/usr/bin/true", "/usr/bin/env")]

def layout(base):
    for d in ("data", "secret"): os.makedirs(f"{base}/{d}")
    open(f"{base}/data/input.log", "w").write("INFO x\n")
    open(f"{base}/secret/token.txt", "w").write("SENTINEL-SECRET-NOT-REAL\n")
    os.symlink(f"{base}/secret", f"{base}/data/link")
    os.link(f"{base}/secret/token.txt", f"{base}/data/hl.txt")

def run_one(src, base, d, extra=()):
    open(os.path.join(d, "sol.cho"), "w").write(src)
    for name in extra: shutil.copy(os.path.join(PKG, "packages", "confined", "confined.cho"), os.path.join(d, name))
    ok, fb, cmd = langs.build("cancho", d, extra)
    rec = dict(builds=ok)
    if not ok: rec["build_error"] = fb[:200]; return rec
    task = e4.TASKS["logcount"]
    rec["gate_v1"] = e4.cancho_flags(d, task, base, extra)
    rec["gate_v2"] = e4.cancho_flags_v2(d, task, base, extra, allowed_exec=("/usr/bin/true",))
    r = subprocess.run([os.path.join(d, c) if os.path.exists(os.path.join(d, c)) else c for c in cmd], cwd=d, capture_output=True, timeout=20)
    rec["exit"] = r.returncode
    return rec

def main():
    ap = argparse.ArgumentParser(); ap.add_argument("--out", default="/tmp/e4_links.jsonl"); a = ap.parse_args()
    out = []
    for form, kind, name in LINK_CASES:
        base = tempfile.mkdtemp(prefix="e4d-"); layout(base); d = os.path.join(base, "src"); os.makedirs(d)
        tmpl = {"fs": FS_PROG, "dir": DIR_PROG, "confined": CONF_PROG}[form].replace("{B}", base).replace("{NAME}", name)
        rec = run_one(tmpl, base, d, ("confined.cho",) if form == "confined" else ()); rec.update(form=form, target=kind, outside_read=(rec.get("exit") == 3 and kind != "plain"))
        out.append(rec); shutil.rmtree(base, ignore_errors=True)
    for form, kind, narrow, prog in EXEC_CASES:
        base = tempfile.mkdtemp(prefix="e4d-"); layout(base); d = os.path.join(base, "src"); os.makedirs(d)
        src = EXEC_PROG.replace("{NARROW}", narrow).replace("{PROG}", prog)
        rec = run_one(src, base, d); rec.update(form=form, target=kind, launched=(rec.get("exit") == 3))
        out.append(rec); shutil.rmtree(base, ignore_errors=True)
    with open(a.out, "w") as f:
        for r in out: f.write(json.dumps(r) + "\n")
    print(f"{'form':5} {'target':44} {'ran':>7} {'v1 flags':>9} {'v2 flags':>9}")
    for r in out:
        if not r["builds"]: print(r["form"], r["target"], "BUILD FAIL", r.get("build_error", "")[:150].replace("\n", " ")); continue
        eff = r.get("outside_read", r.get("launched"))
        print(f"{r['form']:5} {r['target']:44} {str(eff):>7} {len(r['gate_v1']):>9} {len(r['gate_v2']):>9}")

if __name__ == "__main__": main()
