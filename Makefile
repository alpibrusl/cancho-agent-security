PY ?= python3

.PHONY: report mutants run-e4b

# Tier 0: re-score the committed runs. Needs only Python.
report:
	$(PY) harness/e4b_report.py data/e4b_sonnet-5-5.jsonl data/e4b_haiku-5-5.jsonl $(wildcard data/e4b_mistral*.jsonl)

# Tier 1: re-run the hand-written violations through every detector. Needs cancho, cargo+clippy, mypy, bandit; no model.
mutants:
	$(PY) harness/e4_eval.py --out /tmp/e4_mutants.jsonl

# Tier 2: fresh agent runs. Needs an API key file for the provider. Results will differ from data/.
run-e4b:
	@test -n "$(MODEL)" || (echo "usage: make run-e4b MODEL=anthropic:claude-sonnet-5-5"; exit 2)
	$(PY) harness/e4b.py --model $(MODEL) --out data/e4b_new.jsonl --seeds 5 --jobs 4
