#!/usr/bin/env python3
"""Local verification only: no publishing, tags, releases or artifact uploads."""
import argparse
import ast
from pathlib import Path
import py_compile
import shutil
import subprocess
import sys
import tarfile
import tempfile
import venv
import zipfile


def run(*args, cwd):
    print("+ " + " ".join(map(str, args)), flush=True)
    subprocess.run(list(map(str, args)), cwd=cwd, check=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--skip-checkout-tests", action="store_true", help="For CI that already ran the full checkout suite")
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    if not sys.platform.startswith("linux"):
        parser.error("Run release verification on Linux (WSL is supported)")
    modules = sorted(path.stem for path in root.glob("*.py"))
    for path in [*root.glob("*.py"), *root.glob("scripts/*.py"), *root.glob("tests/*.py")]:
        py_compile.compile(str(path), doraise=True)
    # Read the canonical literal without importing from the source checkout.
    tree = ast.parse((root / "permissionhell.py").read_text())
    version = next(ast.literal_eval(node.value) for node in tree.body if isinstance(node, ast.Assign)
                   and any(isinstance(t, ast.Name) and t.id == "__version__" for t in node.targets))
    if (root / ".git").exists():
        run("git", "diff", "--check", cwd=root)
    if not args.skip_checkout_tests:
        run(sys.executable, "-m", "pytest", "-q", cwd=root)
    (root / "dist").mkdir(exist_ok=True)
    output = Path(tempfile.mkdtemp(prefix="release-check-", dir=root / "dist"))
    run(sys.executable, "-m", "build", "--outdir", output, cwd=root)
    wheel, = output.glob("*.whl")
    source, = output.glob("*.tar.gz")
    with zipfile.ZipFile(wheel) as archive:
        names = archive.namelist()
        actual = {name for name in names if name.endswith(".py")}
        assert actual == {name + ".py" for name in modules}, actual
        assert all("tests/" not in name and "__pycache__" not in name for name in names)
    with tarfile.open(source) as archive:
        names = archive.getnames()
        assert any(name.endswith("/tests/test_permissionhell.py") for name in names)
        assert any(name.endswith("/docs/schemas.md") for name in names)
        assert not any("/.venv/" in name or "__pycache__" in name or name.endswith(".pyc") for name in names)
    with tempfile.TemporaryDirectory(prefix="permissionhell-installed-") as directory:
        isolated = Path(directory)
        env = isolated / "env"
        # --python supports creating a pip-less venv on minimal Debian/WSL hosts.
        venv.EnvBuilder(with_pip=False).create(env)
        python = env / "bin/python"
        run(sys.executable, "-m", "pip", "--python", python, "install", wheel, "pytest>=8,<10", cwd=isolated)
        smoke = (
            "import importlib, importlib.metadata as m, pathlib, sys; "
            f"modules = {modules!r}; "
            "loaded = [importlib.import_module(name) for name in modules]; "
            "assert all(pathlib.Path(v.__file__).is_relative_to(sys.prefix) for v in loaded); "
            f"assert m.version('permissionhell') == importlib.import_module('permissionhell').__version__ == {version!r}; "
            "entry = next(e for e in m.distribution('permissionhell').entry_points if e.name == 'permissionhell'); "
            "assert entry.value == 'permissionhell:main' and callable(entry.load()); "
            "print('Installed modules, metadata and entry point verified')"
        )
        run(python, "-I", "-c", smoke, cwd=isolated)
        command = env / "bin/permissionhell"
        run(command, "--version", cwd=isolated)
        run(command, "--help", cwd=isolated)
        shutil.copytree(root / "tests", isolated / "tests", ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
        shutil.copy2(root / "pyproject.toml", isolated / "pyproject.toml")
        shutil.copytree(root / "docs", isolated / "docs")
        # One legacy test inspects pyproject.toml next to permissionhell.__file__;
        # it is a checkout-only assertion, already exercised above. Do not put
        # build config in site-packages merely to satisfy that assertion.
        run(python, "-I", "-m", "pytest", "-q", "tests", "-k",
            "not test_package_metadata_uses_canonical_attribute", cwd=isolated)
    print(f"Release checks passed for {version}. Local artifacts: {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
