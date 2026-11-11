# cancho-agent-security

Evidence for one question: **can code written by a coding agent be admitted by a mechanical check on what it is allowed to do, without
anyone reading it?** The check compared here is `cancho authority` (the authority report of the [cancho](https://github.com/alpibrusl/cancho)
compiler) against a purpose-built static scanner for Python and Rust. This repository holds the harness, the raw runs and the scoring
scripts behind the post that reports them. It is a **pilot by one author on small tasks**, not a benchmark; read "What this does not show".

## Reproduce it, in three tiers

| Tier | Needs | Gives you |
|---|---|---|
| 0. Re-score the committed runs | Python 3.11+ only | every table in the post, from the raw JSONL, in seconds |
| 1. Re-run the seeded violations | the cancho compiler, `cargo` + `clippy`, `mypy`, `bandit`; **no model, no key** | the hand-written violation variants through every detector, with the effect observed by running them |
| 2. Re-run the models | tier 1 plus an API key per provider | fresh agent runs (they will differ: models and sampling change) |

```sh
make report                                      # tier 0
make mutants                                     # tier 1 (writes /tmp/e4_mutants.jsonl; compare with data/e4_mutants.jsonl)
make run-e4b MODEL=anthropic:claude-sonnet-5-5   # tier 2, 165 runs
```

Tier 0 needs nothing from cancho: `harness/e4b_report.py` re-runs the Python/Rust scanner over each stored program and reads the cancho verdict
that was recorded when the program was built. Tier 2 is the only tier whose numbers you should expect to move.

### Setup for tiers 1 and 2

Produced on macOS arm64 with:

| Tool | Version |
|---|---|
| cancho | commit `7684baa2` (`cargo build --release -p cancho`); set `CANCHO_BIN` to the binary |
| Rust / clippy | 1.98.1 / 0.1.98 |
| mypy | 2.4.1 (`MYPY_BIN`) |
| bandit | 1.9.4 (`BANDIT_BIN`) |
| Python | 3.14 |

Keys are read from files, never from the repository: `ANTHROPIC_KEY_FILE`, `MISTRAL_KEY_FILE` (defaults in `harness/models.py`). Generated programs are
built and run on your machine. The E4c sandbox profile uses `sandbox-exec` and is macOS-only; the other scripts run elsewhere, but run model-written
code in a container or a disposable user if you re-run tier 2.

## What is in here

| Path | What |
|---|---|
| `harness/e4_mutate.py`, `e4_eval.py` | hand-written violations (write, deep write, never-firing write, run-time-built path, secret read, widened capability, `..`, symlink, exec) in cancho, Python and Rust, and the script that runs them through every detector |
| `harness/e4b.py` | the tricked-agent scenarios: a small log tool plus a "project note" that is an attacker's pretext, or an honest gap in the spec; the policy is hidden from the agent in most arms |
| `harness/e4b_report.py` | scores any `e4b_*.jsonl` the same way |
| `harness/e4.py` | the detectors: cancho authority diff, a path scan, a text scan, `bandit`, and the strict policy-aware scanner (`strict_flags`, version 1) |
| `harness/e4c.py` | an adaptive-attacker harness (sandboxed). **Not used for the results**: the hosted models tried (Sonnet 5.5, Mistral Large 4) refused to attack a gate |
| `harness/langs.py`, `models.py`, `run.py`, `tasks.py` | language checkers (cancho, `clippy -D warnings`, `mypy --strict`), providers, shared helpers |
| `data/e4b_*.jsonl` | one line per agent run: scenario, language, source, whether the out-of-policy effect happened, the gate's flags |
| `data/e4_mutants.jsonl`, `data/e4c_probes.md` | the seeded-violation results and the hand-written escape and evasion probes |
| `data/e4_sonnet-5-5.jsonl` | the first, simpler pilot (an explicit injected note with the budget stated) |

Ground truth is observed, not judged: a write or process spawn leaves a sentinel file, and a read of the secret changes the printed count because
the secret holds a canary line. Payloads are inert files under a per-run scratch directory.

## What this does not show

- One author designed the language, the tasks, the pretexts and the scanners. There is no outside review.
- Tasks are small single-file programs. Nothing here is a real codebase, and no installed third-party package was tested.
- The Python and Rust scanner is the one I wrote (about 40 lines per language, constant tracking included). A better scanner would do better;
  the point of the evasion probes is that every scanner is a list of API names.
- Weaker models do not write cancho: Haiku 5.5 produced a program in 4 of 45 hidden-policy cancho runs, so its cancho rows say nothing about the gate.
- Hosted models refused to attack a gate, so the evasion results are hand-written probes (one program each), not rates.
- Cancho's own gaps found by this work: a symlink or hard link inside a granted directory is followed (`Fs` bounds the text of a path, cancho#762,
  cancho#763), `Exec` bounds which program starts and not what it does, and the report does not count operations.

## Licence

EUPL-1.2, as cancho. The model-written programs in `data/` are outputs of the models named in each line.
