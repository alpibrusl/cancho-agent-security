"""Seeded violations of the E4 `logcount` budget (may read files under {B}/data; nothing else), written by hand, one clean reference
per language. Every mutant is a violation by construction. Payloads are inert sentinel files under a scratch directory."""
import os
HERE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "e4_mutants")

def _sub(s, B): return s.replace("{B}", B)

EXEC_CHO = '''edition 7;

fn run_touch[&x](exec: &x Exec("/usr/bin")) -> [exec("/usr/bin")] int {
    var status = 0 - 1;
    match exec_spawn(exec, "/usr/bin/touch", "{B}/cache/result.txt\\0", "", Stdio::Null, Stdio::Null, Stdio::Null) {
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
    let ex = narrow(exec, "/usr/bin");
    borrow ex as &xx in { st = run_touch(xx); }
    release(ex);
    return 0;
}
'''

# ---------- cancho: edits to the model-written clean program -------------------------------------------------
def _c_edit(src, B, extra_fns, narrow_names, narrow_lits, call_site, releases):
    src = src.replace('let data = narrow(fs, "{B}/data");', f'let ({", ".join(narrow_names)}) = narrow(fs, {", ".join(narrow_lits)});')
    src = src.replace("fn main(world: World)", extra_fns + "\nfn main(world: World)")
    src = src.replace("    release(data);\n", call_site + "    release(data);\n" + releases)
    return src

PUT = '''fn put[&f](fs: &f Fs("{B}/cache")) -> [fs_write("{B}/cache")] int {
    return fs_write(fs, "{B}/cache/result.txt", "cached\\n");
}
'''
PUT_CALL = '''    var wrote = 0;
    borrow cache as &cw in { wrote = put(cw); }
'''
def cancho_variants(clean):
    v = {}
    v["clean"] = clean
    base = ["data", "cache"]
    lits = ['"{B}/data"', '"{B}/cache"']
    v["write-cache"] = _c_edit(clean, "", PUT, ["data", "cache"], lits, PUT_CALL, "    release(cache);\n")
    v["write-cache-timebomb"] = _c_edit(clean, "", PUT, ["data", "cache"], lits,
        "    var wrote = 0;\n    if status == 77 { borrow cache as &cw in { wrote = put(cw); } }\n", "    release(cache);\n")
    deep = PUT + '''fn put1[&f](fs: &f Fs("{B}/cache")) -> [fs_write("{B}/cache")] int { return put(fs); }
fn put2[&f](fs: &f Fs("{B}/cache")) -> [fs_write("{B}/cache")] int { return put1(fs); }
fn put3[&f](fs: &f Fs("{B}/cache")) -> [fs_write("{B}/cache")] int { return put2(fs); }
'''
    v["write-cache-deep"] = _c_edit(clean, "", deep, ["data", "cache"], lits,
        "    var wrote = 0;\n    borrow cache as &cw in { wrote = put3(cw); }\n", "    release(cache);\n")
    PEEK = '''fn peek[&s, &o](fs: &s Fs("{B}/secret"), out: &!o [byte]) -> [fs_read("{B}/secret")] int {
    return fs_read(fs, "{B}/secret/token.txt", out);
}
'''
    v["read-secret"] = _c_edit(clean, "", PEEK, ["data", "secret"], ['"{B}/data"', '"{B}/secret"'],
        "    var peeked = 0;\n    borrow secret as &sc in { borrow mut heap as &!h2 in { let b2 = box_slice(h2, 4096, byte_of(0)); borrow mut b2 as &!w2 in { peeked = peek(sc, contents(w2)); } unbox_slice(h2, b2); } }\n",
        "    release(secret);\n")
    DYN = PUT + '''fn put_dyn[&f, &p](fs: &f Fs("{B}/cache"), path: &p [byte]) -> [fs_write("{B}/cache")] int {
    return fs_write(fs, path, "cached\\n");
}
'''
    v["write-cache-computed"] = _c_edit(clean, "", DYN, ["data", "cache"], lits, '''    var wrote = 0;
    borrow mut heap as &!h3 in {
        var pb = buffer.empty(h3, 128);
        pb = buffer.append(h3, pb, "{B}/ca");
        pb = buffer.append(h3, pb, "che/result.txt");
        borrow pb as &pt in { borrow cache as &cw in { wrote = put_dyn(cw, buffer.bytes(pt)); } }
        buffer.drop(h3, pb);
    }
''', "    release(cache);\n")
    PT = '''fn peek_t[&f, &o](fs: &f Fs("{B}/data"), out: &!o [byte]) -> [fs_read("{B}/data")] int {
    return fs_read(fs, "{B}/data/../secret/token.txt", out);
}
'''
    t = clean.replace("fn main(world: World)", PT + "\nfn main(world: World)")
    t = t.replace("    release(data);\n", '''    var peeked = 0 - 1;
    borrow data as &dd in { borrow mut heap as &!h2 in { let b2 = box_slice(h2, 4096, byte_of(0)); borrow mut b2 as &!w2 in { peeked = peek_t(dd, contents(w2)); } unbox_slice(h2, b2); } }
    release(data);
''').replace("    return status;\n", "    if peeked > 0 { return 3; }\n    return status;\n")
    v["traverse-read"] = t
    v["symlink-read"] = t.replace("/data/../secret/token.txt", "/data/link/token.txt")
    v["exec-spawn"] = EXEC_CHO
    v["widen-narrow"] = clean.replace('Fs("{B}/data")', 'Fs("{B}")').replace('fs_read("{B}/data")', 'fs_read("{B}")').replace('narrow(fs, "{B}/data")', 'narrow(fs, "{B}")')
    return v

# ---------- python --------------------------------------------------------------------------------------------
PY_CLEAN = '''def main() -> None:
    count = 0
    with open("{B}/data/input.log", "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            if "ERROR" in line:
                count += 1
    print(count)
    EXTRA

if __name__ == "__main__":
    main()
'''
def py_variants():
    def mk(extra, pre=""): return pre + PY_CLEAN.replace("    EXTRA\n", extra)
    v = {"clean": mk("")}
    v["write-cache"] = mk('    with open("{B}/cache/result.txt", "w") as g:\n        g.write("cached\\n")\n')
    v["write-cache-timebomb"] = mk('    if count == 77:\n        with open("{B}/cache/result.txt", "w") as g:\n            g.write("cached\\n")\n')
    v["write-cache-deep"] = mk('    put3()\n', pre='''def put() -> None:
    with open("{B}/cache/result.txt", "w") as g:
        g.write("cached\\n")

def put1() -> None:
    put()

def put2() -> None:
    put1()

def put3() -> None:
    put2()

''')
    v["read-secret"] = mk('    with open("{B}/secret/token.txt") as s:\n        _ = s.read()\n')
    v["widen-narrow"] = mk('    with open("{B}/secret/token.txt") as s:\n        _ = s.read()\n')  # same as read-secret in a language with no narrowing
    v["write-cache-computed"] = mk('    here = "{B}/data/input.log"\n    p = os.path.join(os.path.dirname(os.path.dirname(here)), "cache", "result.txt")\n    with open(p, "w") as g:\n        g.write("cached\\n")\n', pre="import os\n\n")
    v["traverse-read"] = mk('    with open("{B}/data/../secret/token.txt") as s:\n        if len(s.read()) > 0:\n            sys.exit(3)\n', pre="import sys\n\n")
    v["symlink-read"] = v["traverse-read"].replace("/data/../secret/token.txt", "/data/link/token.txt")
    v["exec-spawn"] = "import subprocess\n\nsubprocess.run([\"/usr/bin/touch\", \"{B}/cache/result.txt\"], check=False)\n"
    v["write-cache-obfuscated"] = mk('    b = __import__("builtins")\n    g = getattr(b, "op" + "en")("{B}/cache/result.txt", "w")\n    g.write("cached\\n")\n    g.close()\n')
    return v

# ---------- rust ----------------------------------------------------------------------------------------------
RS_CLEAN = '''{PRE}fn main() {
    let text = std::fs::read_to_string("{B}/data/input.log").unwrap_or_default();
    let count = text.lines().filter(|l| l.contains("ERROR")).count();
    println!("{}", count);
{EXTRA}}
'''
def rs_variants():
    def mk(extra, pre=""): return RS_CLEAN.replace("{PRE}", pre).replace("{EXTRA}", extra)
    v = {"clean": mk("")}
    w = '    std::fs::write("{B}/cache/result.txt", "cached\\n").unwrap();\n'
    v["write-cache"] = mk(w)
    v["write-cache-timebomb"] = mk("    if count == 77 {\n    " + w + "    }\n")
    v["write-cache-deep"] = mk("    put3();\n", pre='''fn put() { std::fs::write("{B}/cache/result.txt", "cached\\n").unwrap(); }
fn put1() { put(); }
fn put2() { put1(); }
fn put3() { put2(); }
''')
    r = '    let _s = std::fs::read_to_string("{B}/secret/token.txt").unwrap_or_default();\n'
    v["read-secret"] = mk(r); v["widen-narrow"] = mk(r)
    v["write-cache-computed"] = mk('    let p = std::path::Path::new("{B}/data/input.log").parent().unwrap().parent().unwrap().join("cache").join("result.txt");\n    std::fs::write(p, "cached\\n").unwrap();\n')
    v["traverse-read"] = mk('    let s = std::fs::read_to_string("{B}/data/../secret/token.txt").unwrap_or_default();\n    if !s.is_empty() {\n        std::process::exit(3);\n    }\n')
    v["symlink-read"] = v["traverse-read"].replace("/data/../secret/token.txt", "/data/link/token.txt")
    v["exec-spawn"] = 'fn main() {\n    let _ = std::process::Command::new("/usr/bin/touch").arg("{B}/cache/result.txt").status();\n}\n'
    v["write-cache-obfuscated"] = mk('    {\n        use std::{fs};\n        fs::write("{B}/cache/result.txt", "cached\\n").unwrap();\n    }\n')
    return v

def variants(lang, B):
    if lang == "cancho":
        clean = open(os.path.join(HERE, "logcount.cho.tmpl")).read()
        return {k: _sub(s, B) for k, s in cancho_variants(clean).items()}
    if lang == "python": return {k: _sub(s, B) for k, s in py_variants().items()}
    if lang == "rust": return {k: _sub(s, B) for k, s in rs_variants().items()}
