# E Browser/Tor pilot V2.2 runbook

The continuation root was created from V2.1 and freeze-checked. At migration it contained one inherited successful sample, two inherited attempts, and 3,394.1996 seconds already spent from the original four-hour online budget. V2.1 remains the immutable source record.

## Current pause (2026-10-21)

The V2.2 doctor passed at 08:50:43 UTC. The next `run --resume` stopped at runtime preflight at 08:51:28 UTC because HTTPS CONNECT through `127.0.0.1:17897` timed out during TLS handshake; the collector did not start and no sample attempt was added. Docker, frozen inputs, and StarryNet resource checks passed. A later read-only inspection found the local port still listening but did not identify its process owner. The proxy failure remains unresolved, so the run stays paused. Current accounting is 3,410.914953 seconds used and 10,989.085047 seconds remaining. See `artifacts/e_browser_tor_pilot_v2_2_20261021/diagnostics/run_stop_analysis_20261021.json`.

## Manual collection procedure

Use the existing `starrynet` tmux session and its `starrynet` conda environment with Python 3.6.15. Before starting, verify that no collection process is active and the prior attempt cleanup is complete. The continuation runner repeats its frozen-input, process, Docker, image, and proxy checks.

From `/home/shy/Project/StarryNet`, first run the runtime and HTTPS CONNECT check:

```bash
python tools/run_e_browser_pilot_v2_2.py \
  --output-root artifacts/e_browser_tor_pilot_v2_2_20261021 \
  doctor \
  --config artifacts/e_browser_tor_pilot_v2_2_20261021/protocol/runtime_config.json
```

Continue only if the command returns success and reports `"passed": true`. Doctor time is charged to the inherited four-hour budget.

Resume the frozen sample order:

```bash
python tools/run_e_browser_pilot_v2_2.py \
  --output-root artifacts/e_browser_tor_pilot_v2_2_20261021 \
  run --resume
```

The inherited Amazon r001 success is retained; the next sample is Facebook r001. The runner continues through the manifest without automatic 5/10-sample checkpoints.

After the runner stops, produce the pilot audit:

```bash
python tools/run_e_browser_pilot_v2_2.py \
  --output-root artifacts/e_browser_tor_pilot_v2_2_20261021 \
  audit
```

## Stop and resume

- A normal page or sample-quality failure can use the frozen one-retry allowance. Once exhausted, collection advances to the next sample.
- Any collector or coordinator timeout, return code 124, proxy or Docker failure, changed frozen input, interruption, unverified cleanup, or three consecutive failed attempts stops the scheduler.
- Do not start a sample with less than 22 minutes remaining. A sample has a 20-minute deadline and up to 110 seconds for cleanup.
- Before a manual resume, record the cause and remedy, verify cleanup and input hashes, then rerun `doctor`. Continue with `run --resume` only after that check passes. The ledger and accrued budget carry forward.
- Keep raw timestamp/direction traces unchanged. Pilot profile similarity remains diagnostic and does not reject an otherwise accepted sample.

## Outputs

- `execution_summary.json`: inherited and new sample/attempt counts, budget, and stop reason.
- `attempts.jsonl`: continuation ledger; `continuation/source_attempts.jsonl` preserves the original V2.1 ledger bytes.
- `final_audit/pilot_audit.json` and `final_audit/continuation_audit.json`: sample gates and continuation accounting.
- `continuation/migration.json`: source/freeze/ledger and per-file source-to-copy hashes.
- `continuation/migration_revalidation_20261021.json`: post-migration recheck of all copied sample hashes, archived ledger, source freeze, and inherited diagnostics.

The pilot is complete only when all 15 frozen independent sample IDs pass their acceptance gates, with three successes per site. Otherwise retain and report the partial count and stop reason.
