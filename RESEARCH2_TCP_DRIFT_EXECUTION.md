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

- Active branch: `codex/feature-drift-traces`, created at `main` commit `0bc5687`; implementation snapshot committed as `f83ddb5`.
- Fresh preflight startup inventory is saved in `artifacts/research2_tcp_drift/r2-drift-20261117-2232/startup_inventory.txt`. It recorded an attached `starrynet` tmux session, no Docker containers or Swarm services, and only the five built-in Docker networks. A post-failure inventory is saved beside it; no resources remained and none were removed.
- Source corpus is present: 6,000 files and about 565 MiB. The main agent's audit found 27,341,951 events and 17.36 hours of source duration. At native replay speed, four full conditions require at least about 69.4 hours of event playback before setup and recovery overhead.
- The checkout has an unrelated untracked `starrynet.egg-info/`; preserve it.
- Latest startup inventory: 264 GiB free on the workspace filesystem and 185 GiB on `/mnt/HDD4T`; the measured-capacity gate rechecks free space before each full condition.
- The batch driver, replay coordinator/agent, evidence and report helpers, owner-scoped runtime cleanup, fixed-topology snapshot/route controls, four qdisc profiles, dynamic-pair route checks, gzip storage, measured-capacity gate, and stage/heartbeat ledger are implemented. The driver owns the durable pilot-to-full sequence; individual preflight commands are not the terminal workflow.
- Current offline validation: the consolidated suite passed 159 tests, including real loopback TCP checks. The components were 89 replay/TCP tests, 26 runtime tests, 12 resource-scope tests, and 32 Research 2 evidence/report/batch/integration tests. The targeted `test_tcp_replay.py` run also passed all 30 tests; its five loopback cases required per-command socket permission escalation.
- TCP trace verification now reopens each session's compressed client/remote event log once, validates per-event identities and exact source coverage, rebuilds the client trace from send-completion/receive timestamps, and compares the compressed row mapping and hashes. PCAP validation streams packet records and verifies the gzip round trip. UDP remains on its legacy observed-packet export path and is not treated as strict TCP evidence.
- A fixed pilot must establish a common frozen topology and observed bidirectional satellite route chain before the capacity gate can pass. Capacity is recomputed from the four pilot measurements and the four immutable full manifests; each run retains at least 1.5x estimated remaining output plus 20 GiB free.
- The actual production plan at `artifacts/research2_tcp_drift/r2-drift-20261117-2232/` contains all 12 child manifests: four 150-source pilot plans, four 6,000-source formal plans, two five-source dynamic diagnostics, and paired three-source 30/120-second deadline diagnostics. All manifests were checked against cohort digests, transport/topology modes, and the frozen generator, agent, and eight runtime-helper hashes.
- One Docker-backed startup attempt was made in tmux `starrynet:1` (pane PID `3835642`). The driver's log is `artifacts/research2_tcp_drift/r2-drift-20261117-2232/driver.log`; the failed core command evidence is `pilot/base/runs/20261116T223423_328960Z/preflight/commands.jsonl` and `command_logs/0001_pilot_base_preflight.json`. It stopped before creating a service or emulated network: `docker service inspect` on the absent service returned exit code 1 with a single newline, which the runtime treated as a truthy unowned-service result. The driver marked the batch failed; there are no successful traces or completed simulation sessions. Preserve this failed attempt as evidence.
- The runtime absence/unowned-service handling must be fixed, tested, and included in a new frozen code hash before resuming emulation. Then run an isolated three-source fixed-baseline preflight diagnostic under its own batch identity; it is not part of pilot/full coverage. After it reaches complete client and remote TCP event evidence, create a new full batch plan using the corrected code hash and start its durable driver in `tmux starrynet`. Do not resume the failed old-code batch.
- Do not edit this plan to claim a pilot or trajectory is complete until the artifacts pass their strict verification and final coverage gates. Historical experiment records remain untouched.
