from __future__ import annotations

from pathlib import Path
import shlex
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parent
INSTALLER = ROOT / "install.sh"


def _between(source: str, start: str, end: str) -> str:
    begin = source.index(start)
    finish = source.index(end, begin)
    return source[begin:finish]


class InstallerStageCleanupTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        source = INSTALLER.read_text(encoding="utf-8")
        cls.cleanup_function = _between(
            source,
            "\ncleanup() {",
            "\ntrap cleanup EXIT",
        )

    def _run_cleanup(
        self,
        *,
        stage: Path,
        stage_device: int,
        stage_inode: int,
    ) -> subprocess.CompletedProcess[str]:
        script = f"""
set -u
STAGE_DIR={shlex.quote(str(stage))}
STAGE_DIR_DEVICE={stage_device}
STAGE_DIR_INODE={stage_inode}
UV_INSTALLER=
IN_EXIT_CLEANUP=false
ACTIVATION_TRANSACTION_ID=
ACTIVATION_TRANSACTION_PHASE=
TEAM_HUB_RECOVERY_ATTEMPTED=false
TEAM_HUB_OPERATION_PENDING=false
TEAM_HUB_OPERATION_FINALIZED=false
TEAM_HUB_REACTIVATION_FENCE_PENDING=false
TEAM_HUB_REACTIVATION_FINALIZED=false
TEAM_HUB_COLD_GUARD_PENDING=false
SERVICE_STOPPED_FOR_COLD_HANDOFF=false
CANDIDATE_SERVICE_MAY_HAVE_STARTED=false
mask_install_signals() {{ :; }}
stop_active_stage() {{ :; }}
release_install_lock() {{ :; }}
{self.cleanup_function}
true
cleanup
"""
        return subprocess.run(
            ["/bin/bash", "-c", script],
            text=True,
            capture_output=True,
            check=False,
        )

    def test_cleanup_removes_the_exact_owned_stage_directory(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            stage = root / "stage"
            stage.mkdir()
            (stage / "candidate-marker").write_text("candidate\n", encoding="ascii")
            identity = stage.stat(follow_symlinks=False)

            result = self._run_cleanup(
                stage=stage,
                stage_device=identity.st_dev,
                stage_inode=identity.st_ino,
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertFalse(stage.exists())

    def test_cleanup_never_removes_a_replacement_at_the_old_stage_path(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            stage = root / "stage"
            release = root / "release"
            stage.mkdir()
            candidate = stage / "candidate-marker"
            candidate.write_text("candidate\n", encoding="ascii")
            identity = stage.stat(follow_symlinks=False)

            # Activation consumes the exact staged directory by renaming it to
            # the release path. A different owner can then claim the now-free,
            # predictable staging pathname before EXIT cleanup runs.
            stage.rename(release)
            stage.mkdir()
            sentinel = stage / "replacement-sentinel"
            sentinel.write_text("do not delete\n", encoding="ascii")

            result = self._run_cleanup(
                stage=stage,
                stage_device=identity.st_dev,
                stage_inode=identity.st_ino,
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertTrue(
                sentinel.exists(),
                "EXIT cleanup removed a replacement that did not match the captured "
                "staging-directory identity",
            )
            self.assertEqual(sentinel.read_text(encoding="ascii"), "do not delete\n")
            self.assertEqual(
                (
                    release.stat(follow_symlinks=False).st_dev,
                    release.stat(follow_symlinks=False).st_ino,
                ),
                (identity.st_dev, identity.st_ino),
            )
            self.assertEqual(
                (release / candidate.name).read_text(encoding="ascii"),
                "candidate\n",
            )


if __name__ == "__main__":
    unittest.main()
