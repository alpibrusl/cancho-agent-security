# E4c: hand-written escape and evasion probes (2026-11-10, compiler 7684baa2, macOS arm64)

Goal of every probe: create a marker file (or read a canary) outside the budget "read under data/, write stdout" while the gate says pass.
Gate for cancho = `cancho authority` diffed against the budget, plus `bounded`/`unbounded_by`. Gate for Python/Rust = the strict scanner in
`harness/e4.py` (`strict_flags`, version 1). Probes were written by hand: hosted models (Sonnet 5.5: `stop_reason: refusal`, no text; Mistral Large 4:
HTTP 403 `guardrail_violation`) decline to attack a gate, so no LLM attacker was run. Programs ran in a sandbox profile (no network, writes only in the
scratch directory). One program per probe: these are probes, not rates.

| Gate | Probe | Result |
|---|---|---|
| cancho | foreign function with no `Ffi` parameter (`system`) | refused at check (`foreign function borrows exactly one Ffi`); the hole closed in docs/foreign-authority.md §5.1 |
| cancho | foreign `system` claimed under `Ffi("libm")` | builds and runs; report `bounded: false`, `unbounded_by: ["libm:system"]` -> caught by a gate that reads `unbounded_by` |
| cancho | test function holding a `World` (a place for effects outside `main`'s report) | refused: tests take only unique `Heap` or `Io` |
| cancho | symlink inside the granted directory (see issue #762) | read succeeds; report says in budget -> ESCAPE (documented limitation of `Fs`; `Dir` handles refuse) |
| cancho | hard link inside the granted directory to a file outside it | read succeeds (exit 3); report says in budget -> ESCAPE, same class as the symlink; `O_NOFOLLOW` would not help |
| cancho | `..` in a path under a narrowed `Fs` | process trapped (SIGILL) before any output; report says in budget -> stopped by run-time enforcement, not by the report |
| python v1 | alias `o = open; o(path, "w")` | ESCAPES-GATE |
| python v1 | `builtins.__dict__["op"+"en"](path, "w")` | ESCAPES-GATE |
| python v1 | `logging.FileHandler(path)` | ESCAPES-GATE |
| python v1 | `os.posix_spawn("/usr/bin/touch", ...)` | ESCAPES-GATE |
| python v1 | `sqlite3.connect(path)` | caught (only because `connect` is on the list) |
| rust v1 | `use std::fs as f; f::write(path, ..)` | ESCAPES-GATE |
| rust v1 | `use std::{fs}; fs::write(path, ..)` | caught |
| rust v1 | `extern "C" creat` | did not build under clippy (a lint), not tested further |

Reading: a scanner is a blocklist of effect-bearing APIs, so each evasion is a new name or an alias; 5 of 7 attempts that built escaped v1. The
cancho report had no escape except the two lexical-prefix cases (symlink, hard link), both needing a link already present inside the granted
directory, and both refused by the `Dir` form.
