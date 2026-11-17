# Research Content 2: TCP Feature-Drift Trace Execution

## Locked protocol

This batch produces TCP client-application-event traces from `dataset/tor_fiber` for four controlled link conditions, followed by a small dynamic-handover validation. The implementation is based on `main` (`0bc5687`) and selectively imports replay support; it does not replace the repository tree or modify earlier experiment outputs.

| Condition | Satellite topology | Background random loss | Added GS satellite-egress impairment |
|---|---|---:|---|
| `base` | One frozen snapshot shared by every condition and session | 0% | none |
| `delay25` | Same shared snapshot | 0% | +25 ms on each GS egress |
| `jitter25_10` | Same shared snapshot | 0% | +25 ms center delay and 10 ms normal jitter on each GS egress |
| `loss0p1` | Same shared snapshot | 0% | 0.1% random loss on each GS egress |

Use the same source IDs, source event order, TCP framing, topology snapshot, and replay seed across conditions. The impairment is applied only at the two ground-station satellite-facing egress interfaces. Record the effective `tc -s qdisc` settings before and after each run. Replace the complete qdisc profile between conditions and fail closed if a stale profile remains.

The TCP agent completion window is 120 seconds after the final scheduled source event. The coordinator allows a further 15 seconds to collect both endpoint completion records. Keep connect/handshake timeout separate. Preserve the 120-second and 15-second values in each frozen manifest.

## Execution stages and acceptance gates

1. **Resource safety and port:** establish unique batch ownership for the Swarm service and every StarryNet network; scope every cleanup path to those exact labels. Keep unrelated resources and unowned historical resources untouched. Selectively bring in the TCP replay coordinator, endpoint agent, local execution support, relevant runtime fixes, and their tests.
2. **Offline checks:** audit all 6,000 source IDs, labels, directions, timestamps, per-class coverage, and hashes. Test planning, source-ID grouping, qdisc profile replacement, TCP framing, event completeness, deadline handling, owner-scoped cleanup, and compression/decompression. Store the 150 pilot IDs once and reuse that exact frozen list in all four conditions.
3. **Real preflight:** run only after the Docker inventory confirms a clean owner scope. Verify that the fixed topology remains unchanged for the session, both GS satellite routes work, both endpoint agents exchange complete TCP frames, impairment settings match the frozen condition, packet capture starts, and cleanup removes only this batch's resources. Separately verify a dynamic handover with the same scoped cleanup.
4. **Pilot:** replay 150 sources in each of the four conditions (600 samples total). Finalize only when every planned ID has one valid exported trace, source/client event sequence checks pass, both-direction delivery evidence is present, and source, code, configuration, event-log, PCAP, and output hashes reconcile. Measure wall time and compressed storage before authorizing the full schedule.
5. **Dynamic switching check:** choose five source IDs and replay each once in a stable interval and once across a handover (10 replays total). Retain route snapshots, handover events, endpoint records, TCP state, PCAP, and scoped cleanup evidence. This is a separate diagnostic batch and is not mixed into the four fixed-topology datasets.
6. **Full run:** after pilot gates pass, run all 6,000 sources in each fixed condition (24,000 outputs), reusing one frozen source manifest and preserving each condition in its own directory. No earlier run records are rewritten. Final acceptance requires exact planned/success/export ID coverage, per-event source/client checks, `verification.json` with `passed=true` and no errors, and a hashed `dataset_manifest.json` for each condition.

Keep raw evidence logically complete. Compress endpoint JSONL logs and PCAPs only after their session checks pass; record original and compressed hashes and sizes, and provide readers that transparently open compressed files. Avoid copying large per-event arrays into multiple JSON artifacts. Do not delete failures, attempts, or earlier datasets.

All batch outputs belong under `artifacts/research2_tcp_drift/<batch_id>/`, with separate `pilot/<condition>`, `dynamic_handover`, and `full/<condition>` subdirectories. The batch document records commands, hashes, stage transitions, resource inventory, and measured capacity. A started process, passing unit tests, or passing preflight is not a completed trace dataset.

## Current progress — 2026-11-17

- Active branch: `codex/feature-drift-traces`, based on `main@0bc5687`. Active batch: `artifacts/research2_tcp_drift/r2-drift-20261117-0745/`. Earlier failed attempts and diagnostic batches remain intact.
- Baseline pilot has 150/150 first-attempt successes and now passes the complete offline verifier (`passed=true`, `errors=[]`). Both endpoints account for 589,616 application events: 52,273 outbound and 537,343 inbound, with no send failures, missing events, or retries. Other conditions and all 24,000 formal outputs remain incomplete.
- The false route failure came from comparing observed `forward/reverse` dictionary keys with the baseline's `forward_nodes/reverse_nodes` keys. The verifier now canonicalizes these schemas; changed or missing routes still fail. Verification and published dataset manifests identify the acquisition generator and current verifier separately.
- Verifier revision receipt: `artifacts/research2_tcp_drift/r2-drift-20261117-0745/audit/verifier_route_keys_v1/amendment.json`. It preserves the old replay source, all 12 original child manifests, original batch manifest, failed verification report, prior driver log/exit code, and SHA256 inventories. An AST comparison proves all acquisition/scheduling/transport code is unchanged by this revision; 19,281 original acquisition files retain their hashes. Active manifests record the old plan/acquisition hash and amended verifier hash explicitly; all frozen input/config/runtime checks remain enabled.
- The prior Luna scheduling correction is retained: a prepared but unsent sample that no longer fits the wall-clock session window moves through the existing recovery-session path without a transport retry. The 0745 baseline exercised these recovery sessions successfully. The older 0707 failure and its traces are preserved.
- Validation for this repair: 12 Research 2 integration tests and 31 TCP tests passed, including all real loopback cases under the permitted host context. The route regression checks unchanged paths, a changed reverse path, and a missing reverse path.
- Batch resumed in tmux `starrynet`, window 5 `r2-drift-0745-resume`, pane `%87` (launch shell PID 230731). It uses the existing `start_driver.sh` and the original batch's `--resume` interface. The driver finalizes baseline before starting delay, then jitter/loss, dynamic validation, paired deadline diagnostics, the capacity gate and formal production. Check the live ledger for the current stage; this document is a startup snapshot.
- Source cohort: 6,000 files, 75 classes × 80. Four complete conditions need at least 69.4 hours of native-speed event playback, plus setup/recovery. The measured pilot capacity gate requires 1.5× estimated remaining output plus 20 GiB free before full runs. Available workspace space before resume was 264 GiB.
- The unrelated untracked `starrynet.egg-info/` is preserved. A started driver or a finalized baseline pilot is not a completed four-condition dataset.

Monitor with `tmux attach -t starrynet` and select `r2-drift-0745-resume`. Driver log: `/home/shy/Project/StarryNet/artifacts/research2_tcp_drift/r2-drift-20261117-0745/driver.log`. The previous exit code was archived with the revision; `driver_exit_code.txt` is only updated when the resumed driver exits.

```bash
/home/shy/anaconda3/envs/starrynet/bin/python /home/shy/Project/StarryNet/tools/research2_batch.py status --batch /home/shy/Project/StarryNet/artifacts/research2_tcp_drift/r2-drift-20261117-0745/batch_manifest.json
```

If the driver exits, inspect its log, latest command report, `events.jsonl` and `driver_exit_code.txt` before resuming in a persistent tmux window:

```bash
/home/shy/anaconda3/envs/starrynet/bin/python -u /home/shy/Project/StarryNet/tools/research2_batch.py run --batch /home/shy/Project/StarryNet/artifacts/research2_tcp_drift/r2-drift-20261117-0745/batch_manifest.json --resume
```
