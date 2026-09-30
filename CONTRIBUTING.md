# Contributing

Use Linux or WSL and Python 3.10+. Create a virtual environment and install
`python -m pip install '.[dev]'`. Runtime code has no third-party dependencies;
pytest and build are optional development tools. Tests remain stdlib unittest
compatible, with pytest used by CI.

```bash
python -m pytest -q
python -m unittest discover -s tests -q
python scripts/release_check.py
```

Work on a focused feature/fix branch and review the diff before requesting review.
Use small descriptive commits when commits are requested by your workflow; do not
commit generated build artifacts, baselines containing private data or credentials.
Do not automatically commit, merge, tag or publish on another contributor's behalf.

Follow the existing readable Python style, dataclasses and type annotations. Keep
analysis independent of rendering. Reuse existing evaluators in higher-level
features; do not introduce a second authorization engine. Avoid broad formatting
or dependency churn. Run `git diff --check` and the complete suite.

Behavior changes need tests demonstrating the intended behavior and preserving
prior security semantics. Permission-class precedence, uncertainty, PID identity,
ACL masking and namespace mapping deserve deterministic fixtures. Integrations
must use temporary resources without root, and skip only when their required
kernel interfaces are unavailable. Do not weaken semantic assertions to pass CI.

The pytest environment adapter skips only two legacy live-permit integration tests
when the current host's LSM state cannot establish a permit. It does not skip their
mocked semantic coverage. Existing unittest skips remain in effect. See
[release testing](docs/releasing.md) for installed-vs-checkout coverage.

Keep the read-only/security philosophy: no automatic fixes, credential changes,
namespace entry, scheduling or external reporting. Document visibility limitations
and privacy exposure. See [threat model](docs/threat-model.md) and [SECURITY.md](SECURITY.md).

The repository currently has no LICENSE. Do not introduce legal terms, contributor
agreements or a license grant without the owner's explicit decision.
