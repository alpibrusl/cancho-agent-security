#!/usr/bin/env python3
"""Run one (task, language, model, context condition, seed) to the end and append a JSON line to the results file.

    run.py --task crc32 --lang cancho --model anthropic:claude-... --context A --iterations 10 --seed 1 --out results.jsonl

Context conditions (cancho only): A = `cancho agent-guidelines`; B = A plus five fixed examples; C = A plus a read-only copy of
the repository's docs and examples directory (ceiling). Other languages get no extra context: the model's own knowledge.
"""
import argparse, json, os, re, shutil, subprocess, sys, tempfile, time
sys.path.insert(0, os.path.dirname(__file__))
import tasks, langs, models

EXAMPLES_B = ["examples/hello.cho", "examples/sort/sort.cho", "examples/lines.cho", "examples/base64/base64.cho", "examples/cut/cut.cho"]

def context(lang, cond, repo):
    if lang != "cancho": return ""
    guide = subprocess.run([langs.CANCHO, "agent-guidelines"], capture_output=True, text=True).stdout
    if cond == "A": return guide
    if cond == "B":
        ex = ""
        for p in EXAMPLES_B:
            f = os.path.join(repo, p)
            if os.path.exists(f): ex += f"\n\n--- {p} ---\n" + open(f).read()
        return guide + "\n\n# Five examples" + ex
    if cond == "C": return guide + "\n\n(You may ask for any file of the repository by path in your reply as `READ <path>`; not implemented in the pilot.)"
    raise SystemExit("unknown context " + cond)

def extract(text):
    blocks = re.findall(r"```[a-zA-Z0-9_+-]*\n(.*?)```", text, re.S)
    return (blocks[-1] if blocks else text).strip() + "\n"

def prompt(task, lang, visible):
    ex = "\n".join(f"Example {i+1}\nstdin: {repr(s.decode(errors='replace'))}\nexpected stdout: {repr(o.decode(errors='replace'))}" for i, (s, o) in enumerate(visible))
    return (f"Write a complete {langs.LANGS[lang]['name']} program in a single file.\n\nTask: {task['prompt']}\n\n{ex}\n\n"
            "Reply with the whole file in one fenced code block and nothing else that matters.")

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--task", required=True); ap.add_argument("--lang", required=True); ap.add_argument("--model", required=True)
    ap.add_argument("--context", default="A"); ap.add_argument("--iterations", type=int, default=10)
    ap.add_argument("--seed", type=int, default=1); ap.add_argument("--out", required=True)
    ap.add_argument("--repo", default=os.environ.get("CANCHO_REPO", "."))
    a = ap.parse_args()
    task = tasks.TASKS[a.task]
    visible, hidden = tasks.visible_hidden(a.task)
    system = context(a.lang, a.context, a.repo) or "You are a careful programmer."
    messages = [dict(role="user", content=prompt(task, a.lang, visible))]
    d = tempfile.mkdtemp(prefix="eval-"); rec = dict(task=a.task, group=task["group"], lang=a.lang, model=a.model, context=a.context,
        seed=a.seed, iterations=0, tokens_in=0, tokens_out=0, status="gave-up", first_try=False, t0=time.time())
    green = False
    for i in range(1, a.iterations + 1):
        try: text, use = models.chat(a.model, system, messages)
        except Exception as e:
            rec["status"] = "provider-error: " + str(e)[:200]; break
        rec["iterations"] = i; rec["tokens_in"] += use["input"]; rec["tokens_out"] += use["output"]
        code = extract(text)
        open(os.path.join(d, langs.LANGS[a.lang]["file"]), "w").write(code)
        ok, feedback, cmd = langs.build(a.lang, d)
        if ok:
            res = langs.run_cases(cmd, d, visible)
            if all(r[0] for r in res):
                green = True; rec["first_try"] = (i == 1); break
            feedback = "The program builds but fails these examples:\n" + "\n".join(
                f"- stdin {repr(s[:80])}: got {repr(r[2][:80])} (exit {r[1]}) {r[3].decode(errors='replace')[:200]}, expected {repr(o[:80])}"
                for (s, o), r in zip(visible, res) if not r[0])
        messages += [dict(role="assistant", content=text), dict(role="user", content="The checker said:\n" + feedback + "\n\nFix it and send the whole file again.")]
    if green:
        res = langs.run_cases(cmd, d, hidden)
        rec["status"] = "green"; rec["hidden_pass"] = sum(r[0] for r in res); rec["hidden_total"] = len(res)
        rec["survived"] = len(res) - sum(r[0] for r in res)
    rec["seconds"] = round(time.time() - rec.pop("t0"), 1)
    open(a.out, "a").write(json.dumps(rec) + "\n"); print(json.dumps(rec))
    shutil.rmtree(d, ignore_errors=True)

if __name__ == "__main__": main()
