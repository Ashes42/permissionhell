# Release procedure

This procedure verifies local artifacts. Nothing here publishes, uploads, creates
a GitHub release or pushes a tag.

## Prerequisites and checks

Use Linux, CPython 3.10–3.14, a virtual environment, pip 22.3+ (for `--python`) and
Git when checking a checkout. Install `python -m pip install '.[dev]'`. Pytest/build
are development dependencies; runtime dependencies are empty. The supported ranges
are bounded for pytest/build but not a fully locked build environment: record exact
tool versions with release evidence. Bit-for-bit reproducible artifacts are not
claimed.

```bash
python -m pytest -q
python -m build
python scripts/release_check.py
```

The script compiles runtime/tests/tooling, checks Git whitespace, runs the full
checkout suite, builds an sdist and a wheel (the build frontend builds the wheel
from the sdist), checks their contents, then installs the wheel and pytest in a
fresh temporary environment. Pip downloads may require network access. Artifacts
remain under a unique `dist/release-check-*` directory for manual review.

It verifies every runtime module imports from the isolated environment, installed
metadata matches the canonical version, and the console entry point loads and runs.
It copies tests into a temporary directory and runs them with isolated Python,
outside the checkout and without relying on PYTHONPATH. One legacy assertion
(`test_package_metadata_uses_canonical_attribute`) requires pyproject.toml beside
the source module, so only that test is deselected in the installed run; it runs
in the full checkout suite. New installed-metadata assertions cover the wheel.

Tests do not need root. Kernel-specific tests already skip missing interfaces.
The pytest adapter also skips two legacy integration tests requiring a complete
live permit when the host LSM layer is unresolved/enforcing. Mocked permission
tests are never excluded. CI does not change host LSM policies to make tests pass.

On minimal Debian/WSL without ensurepip, an alternative bootstrap is:

```bash
python3 -m venv --without-pip .venv
python3 -m pip --python .venv/bin/python install pip '.[dev]'
. .venv/bin/activate
```

The installed command can also be smoke-tested manually from outside the checkout:

```bash
python -m pip install --force-reinstall dist/permissionhell-*.whl
cd /tmp
permissionhell --version
permissionhell --help
```

The Ubuntu GitHub Actions matrix runs CPython 3.10, 3.11, 3.12, 3.13 and 3.14 on
push/pull_request with read-only repository permissions. It installs the project,
runs pytest, then the compile/build/installed checks. There is no upload/publish job.
CI configuration is preparation, not proof that hosted matrix runs have completed.

## Packaging decisions

The existing flat modules and `python3 permissionhell.py` entry point are retained.
This avoids a risky import refactor but exposes generic top-level module names such
as `lsm`; use pipx/a dedicated venv to avoid collisions with unrelated packages.
The wheel includes only explicit runtime modules and distribution metadata. The
sdist deliberately includes tests, docs and the release checker so source consumers
can reproduce verification. Temporary data, environments and bytecode are excluded.

Canonical version: `permissionhell.__version__`. Change it once and update release
assertions/history. Setuptools derives distribution metadata from it; banners and
JSON use that runtime value. [Schema versions](schemas.md) change only for reviewed
format changes, not each release.

## Manual publication readiness

Before an owner chooses to tag or publish:

1. Resolve the missing LICENSE. No license has been selected by this milestone.
2. Confirm repository identity, private security-reporting availability and support
   policy. Metadata intentionally does not invent an author/contact/project URL.
3. Confirm the entire hosted Python matrix passes and review skips/tool versions.
4. Review wheel/sdist contents, changelog, CLI help, schema compatibility and privacy.
5. Decide independently whether and where to publish. Tag/release/upload actions
   require separate authorization and are not part of the checker.

Shell completion and an installable man page are deferred; argparse help and the
reference document remain the dependency-free interfaces.
