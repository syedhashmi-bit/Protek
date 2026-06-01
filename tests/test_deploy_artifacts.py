"""Guards against the class of bug where install docs reference a file that
doesn't exist (broken `cp deploy/...` steps, wrong service-unit paths). A
fresh deploy follows these docs literally, so a missing artifact = broken
install. Cheap to keep green; expensive to debug on a customer's VPS."""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# Artifacts the install path (README / docs/INSTALL.md / install.sh / packaging)
# tells an operator to copy. If any goes missing, a documented install breaks.
REQUIRED_ARTIFACTS = [
    "deploy/protek.service",
    "deploy/nginx.conf",
    "deploy/protek-wal-truncate.sh",
    "deploy/protek-wal-truncate.service",
    "deploy/protek-wal-truncate.timer",
    "install.sh",
    ".env.example",
    "requirements.txt",
    "packaging/debian/protek.service",
]

# Docs that hand operators literal `cp <path>` / `git clone` steps.
DEPLOY_DOCS = [
    "README.md",
    "docs/INSTALL.md",
    "deploy/README.md",
    "deploy/terraform/cloud-init.yaml",
]

# A deploy/ or scripts/ artifact (unit / nginx / shell / timer) named in a doc.
REF_RE = re.compile(r"(?:deploy|scripts)/[\w./-]+\.(?:service|conf|sh|timer)")


def test_required_deploy_artifacts_exist():
    missing = [p for p in REQUIRED_ARTIFACTS if not (ROOT / p).exists()]
    assert not missing, f"referenced deploy artifacts missing: {missing}"


def test_no_doc_references_to_missing_deploy_files():
    broken: dict[str, set[str]] = {}
    for doc in DEPLOY_DOCS:
        text = (ROOT / doc).read_text()
        for ref in REF_RE.findall(text):
            if not (ROOT / ref).exists():
                broken.setdefault(doc, set()).add(ref)
    assert not broken, f"docs reference nonexistent deploy files: {broken}"


def test_repo_url_org_is_consistent():
    """Catch the wrong-GitHub-org regression (syedhashmi vs syedhashmi-bit)."""
    wrong = re.compile(r"github(?:usercontent)?\.com/syedhashmi/Protek")
    offenders: list[str] = []
    for path in ROOT.rglob("*"):
        if not path.is_file():
            continue
        if any(part in {".git", "venv", ".venv", "__pycache__"} for part in path.parts):
            continue
        if path.suffix in {".png", ".svg", ".ico", ".db", ".bundle"}:
            continue
        try:
            text = path.read_text()
        except (UnicodeDecodeError, OSError):
            continue
        if wrong.search(text):
            offenders.append(str(path.relative_to(ROOT)))
    assert not offenders, f"wrong GitHub org (use syedhashmi-bit): {offenders}"
