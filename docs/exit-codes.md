# Exit codes

CLI help and version exit 0. Unknown commands, missing arguments and invalid option
values exit 2 through argparse. Runtime meanings depend on the command:

| Command | 0 | 1 | 2 | 3 |
| --- | --- | --- | --- | --- |
| diagnose | Account model permits | Denied | Invalid user/path/input | Metadata/system error |
| audit --explain | Subject permitted | Subject denied | Invalid subject/path/input | Incomplete diagnosis |
| audit | Inventory completed (denials allowed) | Not emitted | Invalid target/input | Incomplete inventory/diagnostics |
| process | Process model permits | Denied | Invalid PID/path/input | Indeterminate or inspection error |
| audit-processes | Inventory completed (denials allowed) | Not emitted | Invalid target/input | Indeterminate/error/nontransient unavailable |
| graph | Underlying diagnosis permits | Underlying diagnosis denies | Invalid input | Underlying uncertainty/error |
| policy-check | All comparisons match | Missing/unexpected access | Invalid policy/input | Indeterminate comparisons |
| snapshot | Complete capture | Not emitted | Invalid input/output | Partial capture or write/system error |
| diff | No meaningful change | Meaningful changes | Invalid/incompatible snapshots | Incomplete evidence/comparison |
| monitor-init | Complete baseline created | Not emitted | Invalid path/input or overwrite refused | Incomplete capture/write/system error |
| monitor-check | No meaningful change | Meaningful changes | Invalid/incompatible baseline/input | Incomplete/current capture/update error |

An ordinary audit's successful completion is not a claim that every subject is
permitted. Audit `--explain` instead returns the single subject's diagnosis status.
Process-audit confirmed exits/identity changes are retained as transient unavailable
entries and alone need not change exit 0; unknown visibility failures do return 3.
Snapshots and policy comparisons treat missing process observations more strictly.

Policy-check gives invalid input (2) precedence over indeterminate (3), then drift
(1), then match (0). Diff gives incompleteness (3) precedence over changes (1).
Process uncertainty and malformed required LSM data both use 3, distinguished by
the structured verdict/reason.

Snapshot may save a partial file and return 3. Monitor-init deliberately does not
write an incomplete baseline. Monitor-check never updates on 2 or 3. A successful
explicit update retains the original 0/1 comparison signal; an update failure
returns 3 with `baseline_updated: false`. Churn filtering is presentation-only and
does not suppress exit 1. A missing current target after baseline validation is a
capture failure (3), not evidence of lost access for every subject.

Treat exit 1 deliberately in cron/CI scripts. Do not use a blanket success-only
shell assumption when a change or denial is an expected diagnostic result.
