from __future__ import annotations

import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

SOURCE = Path(__file__).with_name("strict_source_manifest.py")


def run(
    root: Path,
    *command: str,
    check: bool = True,
) -> subprocess.CompletedProcess[str]:
    completed = subprocess.run(
        list(command),
        cwd=root,
        text=True,
        capture_output=True,
        check=False,
    )
    if check and completed.returncode != 0:
        raise RuntimeError(
            f"Command failed: {command}\nSTDOUT:\n{completed.stdout}\nSTDERR:\n{completed.stderr}"
        )
    return completed


def expect_failure(root: Path, *command: str, label: str) -> None:
    completed = run(root, *command, check=False)
    if completed.returncode == 0:
        raise RuntimeError(f"Expected failure did not occur: {label}")
    print(f"EXPECTED_FAILURE {label} exit={completed.returncode}")


def main() -> None:
    git = shutil.which("git")
    if git is None:
        raise RuntimeError("Git is required.")

    with tempfile.TemporaryDirectory(prefix="strict-manifest-") as temporary:
        root = Path(temporary)
        scripts = root / "scripts"
        scripts.mkdir()
        shutil.copy2(SOURCE, scripts / "generate_source_manifest.py")
        (root / "nested").mkdir()
        (root / "a.txt").write_text("alpha\n", encoding="utf-8")
        (root / "nested" / "b.txt").write_text("bravo\n", encoding="utf-8")
        (root / "IMPLEMENTATION_SOURCE_MANIFEST.json").write_text("{}\n", encoding="utf-8")

        run(root, git, "init")
        run(root, git, "config", "user.name", "Strict Manifest Test")
        run(root, git, "config", "user.email", "strict-manifest@example.invalid")
        run(root, git, "config", "core.autocrlf", "false")
        run(root, git, "add", ".")
        run(root, git, "commit", "-m", "Freeze content")
        content_commit = run(root, git, "rev-parse", "HEAD").stdout.strip()

        generator = scripts / "generate_source_manifest.py"
        run(root, sys.executable, str(generator), "--state", "STRICT_BINDING_TEST")
        manifest = json.loads(
            (root / "IMPLEMENTATION_SOURCE_MANIFEST.json").read_text(encoding="utf-8")
        )
        if manifest["content_commit"] != content_commit:
            raise RuntimeError("Generated manifest did not bind to the frozen content commit.")

        run(root, git, "add", "IMPLEMENTATION_SOURCE_MANIFEST.json")
        run(root, git, "commit", "-m", "Record manifest")
        run(root, sys.executable, str(generator), "--check")
        print("STRICT_BINDING_BASELINE PASS")

        (root / "a.txt").write_text("worktree mutation\n", encoding="utf-8")
        expect_failure(
            root,
            sys.executable,
            str(generator),
            "--check",
            label="uncommitted-tracked-file-mutation",
        )
        run(root, git, "checkout", "--", "a.txt")

        (root / "a.txt").write_text("committed mutation\n", encoding="utf-8")
        run(root, git, "add", "a.txt")
        run(root, git, "commit", "-m", "Change content after manifest")
        expect_failure(
            root,
            sys.executable,
            str(generator),
            "--check",
            label="post-content-commit-change",
        )

        run(root, sys.executable, str(generator), "--state", "STRICT_BINDING_TEST")
        stale = json.loads(
            (root / "IMPLEMENTATION_SOURCE_MANIFEST.json").read_text(encoding="utf-8")
        )
        stale["content_commit"] = content_commit
        (root / "IMPLEMENTATION_SOURCE_MANIFEST.json").write_text(
            json.dumps(stale, indent=2) + "\n",
            encoding="utf-8",
        )
        run(root, git, "add", "IMPLEMENTATION_SOURCE_MANIFEST.json")
        run(root, git, "commit", "-m", "Attempt stale manifest identity")
        expect_failure(
            root,
            sys.executable,
            str(generator),
            "--check",
            label="stale-content-commit-identity",
        )

    print("STRICT_SOURCE_MANIFEST_EFFECTIVENESS PASS")


if __name__ == "__main__":
    main()
