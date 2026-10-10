# Offline validation - 2026-10-10

This pass performed static file analysis and temporary-file tests only. It did
not load/modify a driver, open the adapter control device, send an OID, install a
scheduled task, alter signing/boot policy, or change adapter state. Historical
live-query/recovery evidence in this directory refers to earlier runs.

## Static driver checks

- `verify_mt7925_txd.py`: PASS for `mtkwecx.sys` 5.7.0.5115, SHA-256
  `6232dbfd53c2e9824eb4d193980f7db378b88dd155cb8d4e64ab56696e057161`.
- Verified function bounds, TXD2 type/subtype instructions, two table initializers,
  seven queue/submit direct calls, prepared-frame-control projection, the explicit
  `0x7925` selector, table-copy parameters, and callback member arithmetic.
- Independently reviewed the copy helper and its overlap-safe byte-copy target.
- Wrong image (`README.md`) rejected with exit 1 before PE analysis.
- String xref scan with zero context: six references to the descriptor-builder
  name. Address scan with zero context: two initializer references to its address.
- Both xref helpers reject negative context with exit 2.
- All research Python scripts compile. Full queue-creation disassembly succeeds
  under Windows output encoding after escaping Unicode annotations.

This verifies a static ordinary-TX chain, not external raw-frame acceptance or
over-the-air transmission. See [the queue map](../research/mt7925-wificx-queue-map.md).

## Watchdog regression

Command:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\tests\Run-Tests.ps1
```

Final result: **PASS: 50 assertions**, exit 0.

The suite exercises the actual production supervisor with a fixed 30-second
deadline, but substitutes a temporary-file operation and fake health/recovery
module. It never calls real adapter/recovery commands or network probes.

Covered cases:

- Existing harmless file-state drill and adapter identity validation.
- Rejection of a shortened production timeout before operation or restoration.
- Hung operation with a writing child process: deadline triggers; all job members
  exit before recovery; the child heartbeat stops and restored state stays healthy.
- Hung connectivity probe: deadline remains responsive and the probe exits before
  recovery.
- Concurrent supervisor rejection without touching the owner's state.
- Abandoned mutex rejection without starting another operation or restoring under
  an assumed recovery authorization.
- Operation exit 7 and a thrown probe error trigger prompt recovery.
- Healthy initial connectivity cannot bypass an operation that is still running.
- Test supervisors and temporary directories are cleaned up on success/failure.

Both timeout regressions assert a trigger between 29.5 and 33 seconds. The final
hung-operation trigger was 30.136 seconds; the earlier complete run measured
30.059 seconds for the operation and 30.081 seconds for the probe.

PowerShell parser checks pass for the watchdog, guarded runner, and test suite;
`git diff --check` passes. The guarded runner's scheduled-task lifecycle was
reviewed statically only: tasks are on-demand, the watchdog owns the lock, missing
reports preserve the task, and recovered rollback returns a nonzero result.

## Remaining safety gate

The revised watchdog has **not** been deployed or retested on the physical MT7925.
Earlier live recovery evidence does not validate this revision. Fresh approval
and the required recovery setup precede any physical retest or driver experiment.
Thirty seconds is the recovery trigger, not a guarantee of restored connectivity
by that instant. Userspace cannot recover a hung kernel, boot failure, or DMA
corruption, and restoration commands themselves may take longer.
