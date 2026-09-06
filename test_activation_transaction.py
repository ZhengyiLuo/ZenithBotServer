from __future__ import annotations

from contextlib import redirect_stdout
import hashlib
import io
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

import activation_transaction as activation


class SimulatedCrash(RuntimeError):
    pass


class ActivationLayout:
    def __init__(
        self,
        base: Path,
        *,
        release_version: str = "2.0.0",
        same_version: bool = False,
        legacy_current: bool = False,
        fresh_install: bool = False,
        previous: bool = True,
        env_exists: bool = True,
        env_mode: int = 0o600,
        service_exists: bool = True,
        service_mode: int = 0o644,
        intent: str = "ordinary",
    ) -> None:
        self.base = base
        self.root = base / "install"
        self.releases = self.root / "releases"
        self.config_root = base / "config"
        self.service_root = base / "service"
        self.current = self.root / "current"
        self.previous = self.root / "previous"
        self.env = self.config_root / "env"
        self.service = self.service_root / "agents-server.service"
        self.release_version = release_version
        self.release_dir = self.releases / release_version
        self.candidate_source = self.releases / f".staging-{release_version}-1234"
        self.intent = intent

        self.releases.mkdir(parents=True)
        self.config_root.mkdir()
        self.service_root.mkdir()
        os.chmod(self.root, 0o700)
        self.create_release(
            self.candidate_source,
            release_version,
            marker="candidate\n",
        )

        self.old_source: Path | None
        self.old_target: Path | None
        if fresh_install:
            self.old_source = None
            self.old_target = None
        elif legacy_current:
            self.old_source = self.current
            self.old_target = self.releases / "legacy-original"
            self.create_release(self.current, "1.0.0", marker="old\n")
        elif same_version:
            self.old_source = self.release_dir
            self.old_target = self.releases / f"{release_version}-replaced-test"
            self.create_release(
                self.old_source,
                release_version,
                marker="old\n",
            )
            self.current.symlink_to(self.old_source, target_is_directory=True)
        else:
            self.old_source = self.releases / "1.0.0"
            self.old_target = self.old_source
            self.create_release(self.old_source, "1.0.0", marker="old\n")
            self.current.symlink_to(self.old_source, target_is_directory=True)

        self.previous_release: Path | None = None
        if previous:
            self.previous_release = self.releases / "0.9.0"
            self.create_release(
                self.previous_release,
                "0.9.0",
                marker="previous\n",
            )
            self.previous.symlink_to(self.previous_release, target_is_directory=True)

        self.original_env = b"TOKEN=old\nSETTING=preserved\n"
        self.original_service = b"[Service]\nExecStart=/old\n"
        if env_exists:
            self.write_file(self.env, self.original_env, env_mode)
        if service_exists:
            self.write_file(self.service, self.original_service, service_mode)

        self.old_inode = (
            self.old_source.stat().st_ino if self.old_source is not None else None
        )
        self.candidate_inode = self.candidate_source.stat().st_ino
        self.previous_raw = (
            os.readlink(self.previous) if self.previous.is_symlink() else None
        )
        self.current_was_directory = legacy_current

    @staticmethod
    def write_file(path: Path, value: bytes, mode: int) -> None:
        path.write_bytes(value)
        os.chmod(path, mode)

    @staticmethod
    def create_release(path: Path, version: str, *, marker: str) -> None:
        path.mkdir(parents=True)
        (path / "VERSION").write_text(version + "\n")
        (path / "runtime-marker").write_text(marker)


class ActivationTransactionTests(unittest.TestCase):
    maxDiff = None

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name)
        self.layout_index = 0

    def layout(self, **kwargs: object) -> ActivationLayout:
        self.layout_index += 1
        return ActivationLayout(self.base / f"case-{self.layout_index}", **kwargs)

    @staticmethod
    def invoke(*arguments: str) -> str:
        output = io.StringIO()
        with redirect_stdout(output):
            result = activation.main(list(arguments))
        if result != 0:
            raise AssertionError(f"activation helper returned {result}")
        return output.getvalue()

    @staticmethod
    def invoke_subprocess(*arguments: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, str(Path(activation.__file__)), *arguments],
            capture_output=True,
            text=True,
            check=False,
            timeout=2,
        )

    @staticmethod
    def layout_args(item: ActivationLayout) -> list[str]:
        return [
            "--root",
            str(item.root),
            "--current",
            str(item.current),
            "--previous",
            str(item.previous),
            "--env",
            str(item.env),
            "--service",
            str(item.service),
        ]

    def begin(self, item: ActivationLayout) -> str:
        output = self.invoke(
            "begin",
            *self.layout_args(item),
            "--release-dir",
            str(item.release_dir),
            "--release-version",
            item.release_version,
            "--old-source",
            str(item.old_source or ""),
            "--old-target",
            str(item.old_target or ""),
            "--candidate-source",
            str(item.candidate_source),
            "--service-state",
            "running",
            "--service-enabled",
            "true",
            "--legacy-service-state",
            "absent",
            "--legacy-service-enabled",
            "false",
            "--prior-port",
            "7850",
            "--prior-bind-address",
            "127.0.0.1",
            "--intent",
            item.intent,
            "--client-binding",
            "bound-client" if item.intent != "ordinary" else "",
        )
        transaction_id = output.strip()
        self.assertRegex(transaction_id, r"^activation-[0-9a-f]{24}$")
        return transaction_id

    @staticmethod
    def owned_args(item: ActivationLayout, transaction_id: str) -> list[str]:
        return [
            *ActivationTransactionTests.layout_args(item),
            "--release-dir",
            str(item.release_dir),
            "--release-version",
            item.release_version,
            "--transaction-id",
            transaction_id,
        ]

    def record(
        self,
        item: ActivationLayout,
        transaction_id: str,
        phase: str,
        *extra: str,
    ) -> str:
        return self.invoke(
            "record",
            *self.owned_args(item, transaction_id),
            "--phase",
            phase,
            *extra,
        )

    def load(self, item: ActivationLayout) -> list[str]:
        fields = self.invoke("load", *self.layout_args(item)).splitlines()
        self.assertEqual(fields[-1], "activation-end")
        self.assertEqual(len(fields), 38)
        return fields

    @staticmethod
    def manifest_path(item: ActivationLayout) -> Path:
        return item.root / ".activation-transaction" / "manifest.json"

    def manifest(self, item: ActivationLayout) -> dict[str, object]:
        return json.loads(self.manifest_path(item).read_text())

    def rewrite_manifest(self, item: ActivationLayout, mutate) -> None:
        path = self.manifest_path(item)
        value = json.loads(path.read_text())
        mutate(value)
        path.write_text(json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n")
        os.chmod(path, 0o600)

    def activate_to_linked(self, item: ActivationLayout, transaction_id: str) -> None:
        self.record(item, transaction_id, "linking")
        self.invoke("activate-files", *self.owned_args(item, transaction_id))
        self.record(item, transaction_id, "linked")

    def replace_config(
        self,
        item: ActivationLayout,
        transaction_id: str,
        *,
        kind: str,
        value: bytes,
        mode: int,
        name: str | None = None,
    ) -> Path:
        destination = item.env if kind == "env" else item.service
        source = destination.parent / (
            f".{destination.name}.activation-{transaction_id}-{kind}.source"
        )
        ActivationLayout.write_file(source, value, mode)
        self.invoke(
            "replace-config",
            *self.owned_args(item, transaction_id),
            "--kind",
            kind,
            "--source",
            str(source),
            "--mode",
            format(mode, "o"),
        )
        return source

    def replace_both_configs(
        self, item: ActivationLayout, transaction_id: str
    ) -> tuple[bytes, bytes]:
        env = b"TOKEN=new\nSETTING=candidate\n"
        service = b"[Service]\nExecStart=/candidate\n"
        self.replace_config(
            item,
            transaction_id,
            kind="env",
            value=env,
            mode=0o600,
        )
        self.replace_config(
            item,
            transaction_id,
            kind="service",
            value=service,
            mode=0o644,
        )
        return env, service

    def advance_to_commit(self, item: ActivationLayout, transaction_id: str) -> None:
        self.activate_to_linked(item, transaction_id)
        self.replace_both_configs(item, transaction_id)
        for phase in (
            "candidate-starting",
            "candidate-healthy",
            "committing",
            "committed",
        ):
            self.record(item, transaction_id, phase)

    def rollback(self, item: ActivationLayout, transaction_id: str) -> None:
        self.record(item, transaction_id, "rolling-back")
        self.invoke("restore-files", *self.owned_args(item, transaction_id))
        self.record(item, transaction_id, "rolled-back")
        self.record(item, transaction_id, "rollback-healthy")

    def assert_original_configuration(self, item: ActivationLayout) -> None:
        self.assertEqual(item.env.read_bytes(), item.original_env)
        self.assertEqual(stat.S_IMODE(item.env.stat().st_mode), 0o600)
        self.assertEqual(item.service.read_bytes(), item.original_service)
        self.assertIn(stat.S_IMODE(item.service.stat().st_mode), {0o600, 0o640, 0o644})

    def test_begin_persists_private_exact_provenance(self) -> None:
        item = self.layout(service_mode=0o640, intent="server-update")
        transaction_id = self.begin(item)

        directory = item.root / ".activation-transaction"
        self.assertEqual(stat.S_IMODE(directory.stat().st_mode), 0o700)
        for name in ("manifest.json", "env.backup", "service.backup"):
            path = directory / name
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            self.assertEqual(path.stat().st_nlink, 1)
        value = self.manifest(item)
        self.assertEqual(value["transaction_id"], transaction_id)
        self.assertEqual(value["phase"], "prepared")
        self.assertEqual(value["intent"], "server-update")
        self.assertEqual(value["env"]["mode"], 0o600)
        self.assertEqual(value["service"]["mode"], 0o640)
        self.assertEqual(value["old_release"]["inode"], item.old_inode)
        self.assertEqual(value["candidate_release"]["inode"], item.candidate_inode)
        self.assertEqual(value["prior_port"], 7850)
        self.assertEqual(value["prior_bind_address"], "127.0.0.1")
        self.assertEqual((directory / "env.backup").read_bytes(), item.original_env)
        self.assertEqual(
            (directory / "service.backup").read_bytes(), item.original_service
        )
        fields = self.load(item)
        self.assertEqual(fields[0], transaction_id)
        self.assertEqual(fields[1], item.release_version)
        self.assertEqual(fields[3], "prepared")

    def test_begin_accepts_supported_original_service_modes(self) -> None:
        for mode in (0o600, 0o640, 0o644):
            with self.subTest(mode=oct(mode)):
                item = self.layout(service_mode=mode)
                self.begin(item)
                self.assertEqual(self.manifest(item)["service"]["mode"], mode)

    def test_begin_rejects_config_modes_that_cannot_be_reloaded_or_activated(
        self,
    ) -> None:
        cases = (
            ("env", 0o400),
            ("env", 0o640),
            ("env", 0o644),
            ("env", 0o660),
            ("service", 0o400),
            ("service", 0o440),
            ("service", 0o444),
            ("service", 0o660),
        )
        for kind, mode in cases:
            with self.subTest(kind=kind, mode=oct(mode)):
                options = (
                    {"env_mode": mode}
                    if kind == "env"
                    else {"service_mode": mode}
                )
                item = self.layout(**options)
                with self.assertRaises((RuntimeError, PermissionError)):
                    self.begin(item)
                self.assertFalse((item.root / ".activation-transaction").exists())

    def test_begin_rejects_existing_current_without_rollback_identity(self) -> None:
        item = self.layout()
        arguments = [
            "begin",
            *self.layout_args(item),
            "--release-dir",
            str(item.release_dir),
            "--release-version",
            item.release_version,
            "--old-source",
            "",
            "--old-target",
            "",
            "--candidate-source",
            str(item.candidate_source),
            "--service-state",
            "running",
            "--service-enabled",
            "true",
            "--legacy-service-state",
            "absent",
            "--legacy-service-enabled",
            "false",
            "--prior-port",
            "7850",
            "--prior-bind-address",
            "127.0.0.1",
            "--intent",
            "ordinary",
        ]
        with self.assertRaisesRegex(RuntimeError, "rollback|current|identity"):
            self.invoke(*arguments)
        self.assertFalse((item.root / ".activation-transaction").exists())

    def test_begin_is_resumable_when_root_fsync_fails_after_directory_rename(
        self,
    ) -> None:
        item = self.layout()
        real_fsync = activation._fsync_directory
        crashed = False

        def crash_after_publish(path: Path) -> None:
            nonlocal crashed
            if Path(path) == item.root and not crashed:
                crashed = True
                raise SimulatedCrash("transaction published before root fsync ack")
            real_fsync(path)

        with mock.patch.object(
            activation, "_fsync_directory", side_effect=crash_after_publish
        ):
            with self.assertRaises(SimulatedCrash):
                self.begin(item)

        self.assertTrue((item.root / ".activation-transaction").is_dir())
        transaction_id = str(self.manifest(item)["transaction_id"])
        self.assertEqual(self.load(item)[0], transaction_id)
        with self.assertRaisesRegex(RuntimeError, "already pending"):
            self.begin(item)

    def test_begin_rejects_snapshot_inputs_changed_before_publish(self) -> None:
        for changed in ("candidate", "current", "previous", "env"):
            with self.subTest(changed=changed):
                item = self.layout()
                if changed == "candidate":
                    real_identity = activation._release_identity
                    swapped = False

                    def swap_candidate(source: Path | None, target: Path | None):
                        nonlocal swapped
                        identity = real_identity(source, target)
                        if source == item.candidate_source and not swapped:
                            swapped = True
                            source.rename(item.base / "original-candidate")
                            ActivationLayout.create_release(
                                source,
                                item.release_version,
                                marker="substituted-candidate\n",
                            )
                        return identity

                    patcher = mock.patch.object(
                        activation,
                        "_release_identity",
                        side_effect=swap_candidate,
                    )
                elif changed in {"current", "previous"}:
                    real_previous_identity = activation._linked_release_identity
                    swapped = False

                    def swap_link_input(path: Path):
                        nonlocal swapped
                        identity = real_previous_identity(path)
                        if not swapped:
                            swapped = True
                            if changed == "current":
                                wrong = item.releases / "wrong-current-late"
                                ActivationLayout.create_release(
                                    wrong, "7.7.7", marker="wrong-current\n"
                                )
                                item.current.unlink()
                                item.current.symlink_to(
                                    wrong, target_is_directory=True
                                )
                            else:
                                item.previous_release.rename(
                                    item.base / "original-previous"
                                )
                                ActivationLayout.create_release(
                                    item.previous_release,
                                    "0.9.0",
                                    marker="substituted-previous\n",
                                )
                        return identity

                    patcher = mock.patch.object(
                        activation,
                        "_linked_release_identity",
                        side_effect=swap_link_input,
                    )
                else:
                    real_configuration = activation._configuration
                    swapped = False

                    def swap_env(path: Path, backup: Path, **kwargs):
                        nonlocal swapped
                        metadata = real_configuration(path, backup, **kwargs)
                        if Path(path) == item.env and not swapped:
                            swapped = True
                            ActivationLayout.write_file(
                                item.env, b"TOKEN=changed-during-begin\n", 0o600
                            )
                        return metadata

                    patcher = mock.patch.object(
                        activation,
                        "_configuration",
                        side_effect=swap_env,
                    )

                with patcher:
                    with self.assertRaises((RuntimeError, PermissionError)):
                        self.begin(item)
                self.assertFalse((item.root / ".activation-transaction").exists())

    def test_begin_rejects_second_pending_transaction(self) -> None:
        item = self.layout()
        self.begin(item)
        with self.assertRaisesRegex(RuntimeError, "already pending"):
            self.begin(item)

    def test_load_is_cross_version_but_owned_operations_bind_id_and_version(
        self,
    ) -> None:
        item = self.layout()
        transaction_id = self.begin(item)
        self.assertEqual(self.load(item)[1], "2.0.0")

        wrong_id = "activation-" + "0" * 24
        with self.assertRaisesRegex(RuntimeError, "ownership changed"):
            self.invoke(
                "record",
                *self.owned_args(item, wrong_id),
                "--phase",
                "linking",
            )
        wrong = self.owned_args(item, transaction_id)
        wrong[wrong.index("--release-version") + 1] = "3.0.0"
        with self.assertRaisesRegex(RuntimeError, "release version changed"):
            self.invoke("record", *wrong, "--phase", "linking")

    def test_begin_cleans_safe_orphan_begin_and_retired_directories(self) -> None:
        item = self.layout()
        orphan = item.root / (".activation-transaction." + "a" * 24 + ".tmp")
        orphan.mkdir(mode=0o700)
        retired = item.root / (
            ".activation-transaction-gc-activation-" + "b" * 24
        )
        retired.mkdir(mode=0o700)
        stale_manifest = retired / "manifest.json"
        ActivationLayout.write_file(stale_manifest, b"{}\n", 0o600)

        self.begin(item)

        self.assertFalse(orphan.exists())
        self.assertFalse(retired.exists())

    def test_load_cleans_orphan_manifest_temp(self) -> None:
        item = self.layout()
        self.begin(item)
        temporary = (
            item.root
            / ".activation-transaction"
            / (".manifest.json." + "c" * 24 + ".tmp")
        )
        ActivationLayout.write_file(temporary, b"partial", 0o600)

        self.load(item)

        self.assertFalse(temporary.exists())

    def test_load_rejects_unsafe_transaction_directory_types(self) -> None:
        for control_type in ("mode", "symlink", "fifo"):
            with self.subTest(control_type=control_type):
                item = self.layout()
                self.begin(item)
                directory = item.root / ".activation-transaction"
                if control_type == "mode":
                    os.chmod(directory, 0o755)
                else:
                    parked = item.base / "parked-transaction"
                    directory.rename(parked)
                    if control_type == "symlink":
                        directory.symlink_to(parked, target_is_directory=True)
                    else:
                        os.mkfifo(directory, 0o600)

                with self.assertRaises((RuntimeError, PermissionError, OSError)):
                    self.load(item)

    def test_begin_rejects_symlink_root(self) -> None:
        item = self.layout()
        real_root = item.root
        alias = item.base / "install-alias"
        alias.symlink_to(real_root, target_is_directory=True)
        args = [
            "begin",
            "--root",
            str(alias),
            "--current",
            str(alias / "current"),
            "--previous",
            str(alias / "previous"),
            "--env",
            str(item.env),
            "--service",
            str(item.service),
            "--release-dir",
            str(alias / "releases" / item.release_version),
            "--release-version",
            item.release_version,
            "--old-source",
            str(alias / "releases" / "1.0.0"),
            "--old-target",
            str(alias / "releases" / "1.0.0"),
            "--candidate-source",
            str(alias / "releases" / item.candidate_source.name),
            "--service-state",
            "running",
            "--service-enabled",
            "true",
            "--legacy-service-state",
            "absent",
            "--legacy-service-enabled",
            "false",
            "--prior-port",
            "7850",
            "--prior-bind-address",
            "127.0.0.1",
            "--intent",
            "ordinary",
        ]
        with self.assertRaises(PermissionError):
            self.invoke(*args)

    def test_load_and_owned_commands_reject_root_swapped_to_symlink(self) -> None:
        for operation in ("load", "record"):
            with self.subTest(operation=operation):
                item = self.layout()
                transaction_id = self.begin(item)
                real_root = item.base / "install-real"
                item.root.rename(real_root)
                item.root.symlink_to(real_root, target_is_directory=True)
                if operation == "load":
                    arguments = ["load", *self.layout_args(item)]
                else:
                    arguments = [
                        "record",
                        *self.owned_args(item, transaction_id),
                        "--phase",
                        "prepared",
                    ]
                with self.assertRaises(PermissionError):
                    self.invoke(*arguments)

    def test_activate_different_version_preserves_exact_release_inodes(self) -> None:
        item = self.layout()
        transaction_id = self.begin(item)

        self.activate_to_linked(item, transaction_id)

        self.assertEqual(item.release_dir.stat().st_ino, item.candidate_inode)
        self.assertEqual(item.current.resolve().stat().st_ino, item.candidate_inode)
        self.assertEqual(item.previous.resolve().stat().st_ino, item.old_inode)
        self.assertEqual(os.readlink(item.previous), str(item.old_target))

    def test_fresh_install_activate_rollback_and_finish_are_exact(self) -> None:
        item = self.layout(fresh_install=True, previous=False)
        transaction_id = self.begin(item)

        self.activate_to_linked(item, transaction_id)
        self.assertEqual(item.current.resolve().stat().st_ino, item.candidate_inode)
        self.assertFalse(item.previous.exists())

        self.rollback(item, transaction_id)
        self.assertFalse(item.current.exists())
        self.assertFalse(item.current.is_symlink())
        self.assertFalse(item.previous.exists())
        self.assert_original_configuration(item)

        self.invoke("finish", *self.owned_args(item, transaction_id))
        self.assertFalse(item.release_dir.exists())
        self.assertFalse((item.root / ".activation-transaction").exists())

    def test_same_version_activate_and_rollback_preserve_known_good_inode(self) -> None:
        item = self.layout(same_version=True)
        transaction_id = self.begin(item)

        self.activate_to_linked(item, transaction_id)
        self.assertEqual(item.release_dir.stat().st_ino, item.candidate_inode)
        self.assertEqual(item.old_target.stat().st_ino, item.old_inode)
        self.assertEqual(item.previous.resolve().stat().st_ino, item.old_inode)

        self.rollback(item, transaction_id)
        self.assertEqual(item.release_dir.stat().st_ino, item.old_inode)
        self.assertEqual(item.current.resolve().stat().st_ino, item.old_inode)
        self.assertEqual(os.readlink(item.previous), item.previous_raw)
        self.assert_original_configuration(item)

    def test_legacy_current_directory_activate_and_rollback_is_exact(self) -> None:
        item = self.layout(legacy_current=True)
        transaction_id = self.begin(item)

        self.activate_to_linked(item, transaction_id)
        self.assertTrue(item.current.is_symlink())
        self.assertEqual(item.current.resolve().stat().st_ino, item.candidate_inode)
        self.assertEqual(item.old_target.stat().st_ino, item.old_inode)

        self.rollback(item, transaction_id)
        self.assertTrue(item.current.is_dir())
        self.assertFalse(item.current.is_symlink())
        self.assertEqual(item.current.stat().st_ino, item.old_inode)
        self.assertEqual(os.readlink(item.previous), item.previous_raw)

    def test_activate_is_idempotent_across_each_same_version_file_cut(self) -> None:
        cuts = ("before", "old-moved", "candidate-moved", "previous", "current")
        for cut in cuts:
            with self.subTest(cut=cut):
                item = self.layout(same_version=True)
                transaction_id = self.begin(item)
                self.record(item, transaction_id, "linking")
                if cut in {"old-moved", "candidate-moved", "previous", "current"}:
                    os.rename(item.old_source, item.old_target)
                if cut in {"candidate-moved", "previous", "current"}:
                    os.rename(item.candidate_source, item.release_dir)
                if cut in {"previous", "current"}:
                    item.previous.unlink()
                    item.previous.symlink_to(item.old_target, target_is_directory=True)
                if cut == "current":
                    item.current.unlink()
                    item.current.symlink_to(item.release_dir, target_is_directory=True)

                self.invoke("activate-files", *self.owned_args(item, transaction_id))
                self.invoke("activate-files", *self.owned_args(item, transaction_id))

                self.assertEqual(item.release_dir.stat().st_ino, item.candidate_inode)
                self.assertEqual(item.old_target.stat().st_ino, item.old_inode)
                self.assertEqual(
                    item.current.resolve().stat().st_ino, item.candidate_inode
                )
                self.assertEqual(item.previous.resolve().stat().st_ino, item.old_inode)

    def test_activate_retries_after_rename_committed_but_fsync_failed(self) -> None:
        item = self.layout(same_version=True)
        transaction_id = self.begin(item)
        self.record(item, transaction_id, "linking")
        real_fsync = activation._fsync_directory
        crashed = False

        def crash_after_first_release_fsync(path: Path) -> None:
            nonlocal crashed
            real_fsync(path)
            if Path(path) == item.releases and not crashed:
                crashed = True
                raise SimulatedCrash("after rename before acknowledgement")

        with mock.patch.object(
            activation, "_fsync_directory", side_effect=crash_after_first_release_fsync
        ):
            with self.assertRaises(SimulatedCrash):
                self.invoke("activate-files", *self.owned_args(item, transaction_id))
        self.assertTrue(item.old_target.is_dir())
        self.assertFalse(item.release_dir.exists())

        self.invoke("activate-files", *self.owned_args(item, transaction_id))
        self.assertEqual(item.release_dir.stat().st_ino, item.candidate_inode)
        self.assertEqual(item.old_target.stat().st_ino, item.old_inode)

    def test_activate_retries_after_symlink_replace_before_directory_fsync(
        self,
    ) -> None:
        item = self.layout()
        transaction_id = self.begin(item)
        self.record(item, transaction_id, "linking")
        real_fsync = activation._fsync_directory
        crashed = False

        def crash_after_link_replace(path: Path) -> None:
            nonlocal crashed
            real_fsync(path)
            if Path(path) == item.root and item.previous.is_symlink() and not crashed:
                crashed = True
                raise SimulatedCrash("after symlink replace")

        with mock.patch.object(
            activation, "_fsync_directory", side_effect=crash_after_link_replace
        ):
            with self.assertRaises(SimulatedCrash):
                self.invoke("activate-files", *self.owned_args(item, transaction_id))

        self.invoke("activate-files", *self.owned_args(item, transaction_id))
        self.assertEqual(item.current.resolve().stat().st_ino, item.candidate_inode)
        self.assertEqual(item.previous.resolve().stat().st_ino, item.old_inode)

    def test_activate_missing_or_substituted_candidate_fails_closed(self) -> None:
        for substitution in ("missing", "wrong-inode", "wrong-version"):
            with self.subTest(substitution=substitution):
                item = self.layout()
                transaction_id = self.begin(item)
                self.record(item, transaction_id, "linking")
                if substitution == "missing":
                    item.candidate_source.rename(item.base / "candidate-away")
                elif substitution == "wrong-inode":
                    old = item.candidate_source
                    old.rename(item.base / "candidate-away")
                    ActivationLayout.create_release(
                        old, item.release_version, marker="substitute\n"
                    )
                else:
                    (item.candidate_source / "VERSION").write_text("9.9.9\n")

                with self.assertRaisesRegex(RuntimeError, "candidate release"):
                    self.invoke(
                        "activate-files", *self.owned_args(item, transaction_id)
                    )
                self.assertEqual(item.current.resolve().stat().st_ino, item.old_inode)

    def test_activate_rejects_unowned_existing_destination(self) -> None:
        item = self.layout()
        transaction_id = self.begin(item)
        self.record(item, transaction_id, "linking")
        ActivationLayout.create_release(
            item.release_dir,
            item.release_version,
            marker="unowned-destination\n",
        )

        with self.assertRaisesRegex(RuntimeError, "destination changed"):
            self.invoke("activate-files", *self.owned_args(item, transaction_id))
        self.assertEqual(item.current.resolve().stat().st_ino, item.old_inode)

    def test_replace_config_is_write_ahead_and_atomic(self) -> None:
        item = self.layout()
        transaction_id = self.begin(item)
        self.activate_to_linked(item, transaction_id)
        desired = b"TOKEN=new\n"
        source = item.env.parent / f".env.activation-{transaction_id}-env.source"
        ActivationLayout.write_file(source, desired, 0o600)
        real_replace = activation.os.replace
        observed_manifest: dict[str, object] = {}

        def inspect_before_publish(source_path, destination_path) -> None:
            if Path(destination_path) == item.env:
                observed_manifest.update(self.manifest(item))
            real_replace(source_path, destination_path)

        with mock.patch.object(
            activation.os, "replace", side_effect=inspect_before_publish
        ):
            self.invoke(
                "replace-config",
                *self.owned_args(item, transaction_id),
                "--kind",
                "env",
                "--source",
                str(source),
                "--mode",
                "600",
            )

        digest = hashlib.sha256(desired).hexdigest()
        self.assertEqual(observed_manifest["desired_env"]["sha256"], digest)
        self.assertIn(digest, observed_manifest["observed_env_sha256"])
        self.assertEqual(item.env.read_bytes(), desired)
        self.assertEqual(stat.S_IMODE(item.env.stat().st_mode), 0o600)

    def test_replace_config_retries_when_crash_precedes_publish(self) -> None:
        item = self.layout()
        transaction_id = self.begin(item)
        self.activate_to_linked(item, transaction_id)
        desired = b"TOKEN=new-before-publish\n"
        source = item.env.parent / f".env.activation-{transaction_id}-env.source"
        ActivationLayout.write_file(source, desired, 0o600)
        real_replace = activation.os.replace
        crashed = False

        def crash_before_publish(source_path, destination_path) -> None:
            nonlocal crashed
            if Path(destination_path) == item.env and not crashed:
                crashed = True
                raise SimulatedCrash("before config rename")
            real_replace(source_path, destination_path)

        with mock.patch.object(
            activation.os, "replace", side_effect=crash_before_publish
        ):
            with self.assertRaises(SimulatedCrash):
                self.invoke(
                    "replace-config",
                    *self.owned_args(item, transaction_id),
                    "--kind",
                    "env",
                    "--source",
                    str(source),
                    "--mode",
                    "600",
                )
        self.assertTrue(source.exists())
        self.assertEqual(item.env.read_bytes(), item.original_env)

        self.invoke(
            "replace-config",
            *self.owned_args(item, transaction_id),
            "--kind",
            "env",
            "--source",
            str(source),
            "--mode",
            "600",
        )
        self.assertEqual(item.env.read_bytes(), desired)

    def test_replace_config_retries_around_staging_file_fsync(self) -> None:
        for cut in ("before", "after"):
            with self.subTest(cut=cut):
                item = self.layout()
                transaction_id = self.begin(item)
                self.activate_to_linked(item, transaction_id)
                desired = b"TOKEN=staging-fsync\n"
                source = item.env.parent / f".env.activation-{transaction_id}-env.source"
                ActivationLayout.write_file(source, desired, 0o644)
                source_inode = source.stat().st_ino
                real_fsync = activation.os.fsync
                crashed = False

                def crash_at_source_fsync(descriptor: int) -> None:
                    nonlocal crashed
                    if os.fstat(descriptor).st_ino == source_inode and not crashed:
                        crashed = True
                        if cut == "after":
                            real_fsync(descriptor)
                        raise SimulatedCrash(f"{cut} staging fsync acknowledgement")
                    real_fsync(descriptor)

                with mock.patch.object(
                    activation.os, "fsync", side_effect=crash_at_source_fsync
                ):
                    with self.assertRaises(SimulatedCrash):
                        self.invoke(
                            "replace-config",
                            *self.owned_args(item, transaction_id),
                            "--kind",
                            "env",
                            "--source",
                            str(source),
                            "--mode",
                            "600",
                        )

                self.assertTrue(source.is_file())
                self.assertEqual(item.env.read_bytes(), item.original_env)
                self.invoke(
                    "replace-config",
                    *self.owned_args(item, transaction_id),
                    "--kind",
                    "env",
                    "--source",
                    str(source),
                    "--mode",
                    "600",
                )
                self.assertEqual(item.env.read_bytes(), desired)

    def test_replace_config_retries_when_publish_precedes_fsync_ack(self) -> None:
        item = self.layout()
        transaction_id = self.begin(item)
        self.activate_to_linked(item, transaction_id)
        desired = b"TOKEN=new-after-publish\n"
        source = item.env.parent / f".env.activation-{transaction_id}-env.source"
        ActivationLayout.write_file(source, desired, 0o600)
        real_fsync = activation._fsync_directory
        crashed = False

        def crash_before_config_dir_fsync(path: Path) -> None:
            nonlocal crashed
            if Path(path) == item.env.parent and not crashed:
                crashed = True
                raise SimulatedCrash("after config rename")
            real_fsync(path)

        with mock.patch.object(
            activation, "_fsync_directory", side_effect=crash_before_config_dir_fsync
        ):
            with self.assertRaises(SimulatedCrash):
                self.invoke(
                    "replace-config",
                    *self.owned_args(item, transaction_id),
                    "--kind",
                    "env",
                    "--source",
                    str(source),
                    "--mode",
                    "600",
                )
        self.assertFalse(source.exists())
        self.assertEqual(item.env.read_bytes(), desired)

        self.invoke(
            "replace-config",
            *self.owned_args(item, transaction_id),
            "--kind",
            "env",
            "--source",
            str(source),
            "--mode",
            "600",
        )
        self.assertEqual(item.env.read_bytes(), desired)

    def test_replace_config_tracks_each_observed_digest_and_latest_desired(
        self,
    ) -> None:
        item = self.layout()
        transaction_id = self.begin(item)
        self.activate_to_linked(item, transaction_id)
        first = b"TOKEN=first\n"
        second = b"TOKEN=second\n"

        self.replace_config(
            item,
            transaction_id,
            kind="env",
            value=first,
            mode=0o600,
            name=".env.first",
        )
        self.replace_config(
            item,
            transaction_id,
            kind="env",
            value=second,
            mode=0o600,
            name=".env.second",
        )

        value = self.manifest(item)
        first_digest = hashlib.sha256(first).hexdigest()
        second_digest = hashlib.sha256(second).hexdigest()
        self.assertIn(first_digest, value["observed_env_sha256"])
        self.assertIn(second_digest, value["observed_env_sha256"])
        self.assertEqual(value["desired_env"]["sha256"], second_digest)
        self.assertEqual(item.env.read_bytes(), second)

        self.rollback(item, transaction_id)
        self.assert_original_configuration(item)

    def test_replace_config_rejects_wrong_parent_and_unsafe_sources(self) -> None:
        constructors = {
            "wrong-parent": lambda path: ActivationLayout.write_file(
                path, b"new\n", 0o600
            ),
            "symlink": lambda path: path.symlink_to(item.env),
            "hardlink": lambda path: os.link(item.env, path),
        }
        for kind in constructors:
            with self.subTest(kind=kind):
                item = self.layout()
                transaction_id = self.begin(item)
                self.activate_to_linked(item, transaction_id)
                if kind == "wrong-parent":
                    source = item.base / "outside.env"
                else:
                    source = item.env.parent / f".env.activation-{transaction_id}-env.source"
                constructors[kind](source)
                with self.assertRaises((RuntimeError, PermissionError, OSError)):
                    self.invoke(
                        "replace-config",
                        *self.owned_args(item, transaction_id),
                        "--kind",
                        "env",
                        "--source",
                        str(source),
                        "--mode",
                        "600",
                    )

    def test_replace_config_rejects_source_swap_after_write_ahead(self) -> None:
        item = self.layout()
        transaction_id = self.begin(item)
        self.activate_to_linked(item, transaction_id)
        desired = b"TOKEN=journaled\n"
        substituted = b"TOKEN=not-journaled\n"
        source = item.env.parent / f".env.activation-{transaction_id}-env.source"
        ActivationLayout.write_file(source, desired, 0o600)
        real_replace_private = activation._replace_private
        swapped = False

        def swap_source_after_manifest(path: Path, payload: bytes) -> None:
            nonlocal swapped
            real_replace_private(path, payload)
            if Path(path) == self.manifest_path(item) and not swapped:
                swapped = True
                source.unlink()
                ActivationLayout.write_file(source, substituted, 0o600)

        with mock.patch.object(
            activation, "_replace_private", side_effect=swap_source_after_manifest
        ):
            with self.assertRaises((RuntimeError, PermissionError)):
                self.invoke(
                    "replace-config",
                    *self.owned_args(item, transaction_id),
                    "--kind",
                    "env",
                    "--source",
                    str(source),
                    "--mode",
                    "600",
                )

        self.assertEqual(item.env.read_bytes(), item.original_env)
        self.load(item)

    def test_transaction_cleanup_removes_every_exact_config_staging_cut(self) -> None:
        for kind in ("env", "service"):
            for cut in ("before-helper", "after-link", "after-source-unlink"):
                with self.subTest(kind=kind, cut=cut):
                    item = self.layout()
                    transaction_id = self.begin(item)
                    self.activate_to_linked(item, transaction_id)
                    destination = item.env if kind == "env" else item.service
                    source, publication = activation._config_staging_paths(
                        destination,
                        transaction_id,
                        kind,
                    )
                    desired = f"SECRET={kind}-{cut}\n".encode()
                    ActivationLayout.write_file(source, desired, 0o600)

                    if cut == "after-link":
                        with mock.patch.object(
                            activation,
                            "_publish_staged_config",
                            side_effect=SimulatedCrash("after publication link"),
                        ):
                            with self.assertRaises(SimulatedCrash):
                                self.invoke(
                                    "replace-config",
                                    *self.owned_args(item, transaction_id),
                                    "--kind",
                                    kind,
                                    "--source",
                                    str(source),
                                    "--mode",
                                    "600" if kind == "env" else "644",
                                )
                        self.assertTrue(source.exists())
                        self.assertTrue(publication.exists())
                    elif cut == "after-source-unlink":
                        real_unlink = activation._unlink_if_same_file

                        def unlink_then_crash(path, identity) -> None:
                            real_unlink(path, identity)
                            raise SimulatedCrash("after source unlink")

                        with mock.patch.object(
                            activation,
                            "_unlink_if_same_file",
                            side_effect=unlink_then_crash,
                        ):
                            with self.assertRaises(SimulatedCrash):
                                self.invoke(
                                    "replace-config",
                                    *self.owned_args(item, transaction_id),
                                    "--kind",
                                    kind,
                                    "--source",
                                    str(source),
                                    "--mode",
                                    "600" if kind == "env" else "644",
                                )
                        self.assertFalse(source.exists())
                        self.assertTrue(publication.exists())

                    self.rollback(item, transaction_id)
                    self.invoke(
                        "finish",
                        *self.owned_args(item, transaction_id),
                    )
                    self.assertFalse(source.exists())
                    self.assertFalse(publication.exists())

    def test_second_config_draft_before_write_ahead_is_discarded_on_rollback(
        self,
    ) -> None:
        item = self.layout()
        transaction_id = self.begin(item)
        self.activate_to_linked(item, transaction_id)
        self.replace_config(
            item,
            transaction_id,
            kind="env",
            value=b"TOKEN=first\n",
            mode=0o600,
        )
        source, publication = activation._config_staging_paths(
            item.env,
            transaction_id,
            "env",
        )
        ActivationLayout.write_file(source, b"TOKEN=second\n", 0o600)
        real_replace_private = activation._replace_private

        def fail_manifest_update(path: Path, payload: bytes) -> None:
            if Path(path) == self.manifest_path(item):
                raise SimulatedCrash("before second write-ahead update")
            real_replace_private(path, payload)

        with mock.patch.object(
            activation,
            "_replace_private",
            side_effect=fail_manifest_update,
        ):
            with self.assertRaises(SimulatedCrash):
                self.invoke(
                    "replace-config",
                    *self.owned_args(item, transaction_id),
                    "--kind",
                    "env",
                    "--source",
                    str(source),
                    "--mode",
                    "600",
                )
        self.assertTrue(source.exists())
        self.assertFalse(publication.exists())
        self.rollback(item, transaction_id)
        self.assertFalse(source.exists())
        self.assert_original_configuration(item)

    def test_restore_files_restores_exact_config_contents_and_modes(self) -> None:
        item = self.layout(service_mode=0o640)
        transaction_id = self.begin(item)
        self.activate_to_linked(item, transaction_id)
        self.replace_both_configs(item, transaction_id)

        self.rollback(item, transaction_id)

        self.assert_original_configuration(item)
        self.assertEqual(stat.S_IMODE(item.service.stat().st_mode), 0o640)

    def test_restore_files_removes_configs_that_were_originally_missing(self) -> None:
        item = self.layout(env_exists=False, service_exists=False)
        transaction_id = self.begin(item)
        self.activate_to_linked(item, transaction_id)
        self.replace_both_configs(item, transaction_id)
        self.rollback(item, transaction_id)

        self.assertFalse(item.env.exists())
        self.assertFalse(item.service.exists())

    def test_restore_retries_after_config_replace_before_fsync(self) -> None:
        item = self.layout()
        transaction_id = self.begin(item)
        self.activate_to_linked(item, transaction_id)
        self.replace_both_configs(item, transaction_id)
        self.record(item, transaction_id, "rolling-back")
        real_fsync = activation._fsync_directory
        crashed = False

        def crash_after_env_restore(path: Path) -> None:
            nonlocal crashed
            if (
                Path(path) == item.env.parent
                and item.env.read_bytes() == item.original_env
                and not crashed
            ):
                crashed = True
                raise SimulatedCrash("after env restore")
            real_fsync(path)

        with mock.patch.object(
            activation, "_fsync_directory", side_effect=crash_after_env_restore
        ):
            with self.assertRaises(SimulatedCrash):
                self.invoke("restore-files", *self.owned_args(item, transaction_id))

        self.invoke("restore-files", *self.owned_args(item, transaction_id))
        self.record(item, transaction_id, "rolled-back")
        self.assert_original_configuration(item)

    def test_restore_is_idempotent_across_each_link_and_config_cut(self) -> None:
        cuts = ("before", "current", "previous", "env", "service")
        for cut in cuts:
            with self.subTest(cut=cut):
                item = self.layout()
                transaction_id = self.begin(item)
                original_current = os.readlink(item.current)
                original_previous = os.readlink(item.previous)
                self.activate_to_linked(item, transaction_id)
                self.replace_both_configs(item, transaction_id)
                self.record(item, transaction_id, "rolling-back")

                if cut in {"current", "previous", "env", "service"}:
                    item.current.unlink()
                    item.current.symlink_to(original_current, target_is_directory=True)
                if cut in {"previous", "env", "service"}:
                    item.previous.unlink()
                    item.previous.symlink_to(
                        original_previous, target_is_directory=True
                    )
                if cut in {"env", "service"}:
                    ActivationLayout.write_file(item.env, item.original_env, 0o600)
                if cut == "service":
                    ActivationLayout.write_file(
                        item.service, item.original_service, 0o644
                    )

                self.invoke("restore-files", *self.owned_args(item, transaction_id))
                self.invoke("restore-files", *self.owned_args(item, transaction_id))
                self.record(item, transaction_id, "rolled-back")
                self.record(item, transaction_id, "rollback-healthy")
                self.assertEqual(
                    item.current.resolve().stat().st_ino, item.old_inode
                )
                self.assertEqual(os.readlink(item.previous), original_previous)
                self.assert_original_configuration(item)

    def test_same_version_rollback_recovers_parked_candidate_and_dangling_previous(
        self,
    ) -> None:
        item = self.layout(same_version=True)
        transaction_id = self.begin(item)
        self.activate_to_linked(item, transaction_id)
        self.replace_both_configs(item, transaction_id)
        self.record(item, transaction_id, "rolling-back")

        parked = item.root / ".activation-transaction" / "candidate.retired"
        os.rename(item.release_dir, parked)
        os.rename(item.old_target, item.release_dir)
        self.assertFalse(item.previous.exists())
        self.assertTrue(item.previous.is_symlink())

        self.invoke("restore-files", *self.owned_args(item, transaction_id))
        self.record(item, transaction_id, "rolled-back")
        self.assertEqual(item.release_dir.stat().st_ino, item.old_inode)
        self.assertEqual(os.readlink(item.previous), item.previous_raw)
        self.assert_original_configuration(item)

    def test_missing_candidate_can_load_and_complete_rollback(self) -> None:
        item = self.layout()
        transaction_id = self.begin(item)
        item.candidate_source.rename(item.base / "lost-candidate")

        fields = self.load(item)
        self.assertEqual(fields[34], "")
        self.rollback(item, transaction_id)
        self.assertEqual(item.current.resolve().stat().st_ino, item.old_inode)

    def test_record_enforces_phase_graph_and_idempotent_same_phase(self) -> None:
        item = self.layout()
        transaction_id = self.begin(item)
        self.record(item, transaction_id, "prepared")
        with self.assertRaisesRegex(RuntimeError, "transition"):
            self.record(item, transaction_id, "candidate-healthy")
        self.record(item, transaction_id, "linking")
        self.invoke("activate-files", *self.owned_args(item, transaction_id))
        self.record(item, transaction_id, "linked")
        self.record(item, transaction_id, "linked")
        with self.assertRaisesRegex(RuntimeError, "transition"):
            self.record(item, transaction_id, "prepared")

    def test_owned_operation_rejects_every_wrong_invocation_coordinate(self) -> None:
        cases = (
            "current",
            "previous",
            "env",
            "service",
            "release-dir",
            "release-version",
            "transaction-id",
        )
        for field in cases:
            with self.subTest(field=field):
                item = self.layout()
                transaction_id = self.begin(item)
                arguments = self.owned_args(item, transaction_id)
                option = "--" + field
                index = arguments.index(option) + 1
                if field == "release-version":
                    arguments[index] = "different-version"
                elif field == "transaction-id":
                    arguments[index] = "activation-" + "0" * 24
                else:
                    arguments[index] = str(item.base / ("wrong-" + field))
                before = self.manifest_path(item).read_bytes()
                with self.assertRaises(RuntimeError):
                    self.invoke("record", *arguments, "--phase", "prepared")
                self.assertEqual(self.manifest_path(item).read_bytes(), before)

    def test_record_is_idempotent_after_manifest_replace_fsync_ambiguity(self) -> None:
        item = self.layout()
        transaction_id = self.begin(item)
        transaction_directory = item.root / ".activation-transaction"
        real_fsync = activation._fsync_directory
        crashed = False

        def crash_after_manifest_replace(path: Path) -> None:
            nonlocal crashed
            real_fsync(path)
            if Path(path) == transaction_directory and not crashed:
                crashed = True
                raise SimulatedCrash("manifest rename committed")

        with mock.patch.object(
            activation, "_fsync_directory", side_effect=crash_after_manifest_replace
        ):
            with self.assertRaises(SimulatedCrash):
                self.record(item, transaction_id, "linking")
        self.assertEqual(self.manifest(item)["phase"], "linking")

        self.record(item, transaction_id, "linking")
        self.assertEqual(self.load(item)[3], "linking")

    def test_record_retries_when_manifest_replace_did_not_publish(self) -> None:
        item = self.layout()
        transaction_id = self.begin(item)

        with mock.patch.object(
            activation,
            "_replace_private",
            side_effect=SimulatedCrash("before manifest replace"),
        ):
            with self.assertRaises(SimulatedCrash):
                self.record(item, transaction_id, "linking")

        self.assertEqual(self.load(item)[3], "prepared")
        self.record(item, transaction_id, "linking")
        self.assertEqual(self.load(item)[3], "linking")

    def test_authority_record_is_tri_state(self) -> None:
        item = self.layout()
        transaction_id = self.begin(item)
        self.record(
            item,
            transaction_id,
            "prepared",
            "--authority-pending",
            "true",
        )
        self.record(item, transaction_id, "prepared")
        self.assertTrue(self.manifest(item)["authority_pending"])
        self.record(
            item,
            transaction_id,
            "prepared",
            "--authority-pending",
            "false",
        )
        self.assertFalse(self.manifest(item)["authority_pending"])

    def test_record_rejects_malformed_guard_without_poisoning_manifest(self) -> None:
        cases = ("id", "coordinate")
        for case in cases:
            with self.subTest(case=case):
                item = self.layout()
                transaction_id = self.begin(item)
                before = self.manifest_path(item).read_bytes()
                guard_id = (
                    "not-a-valid-guard"
                    if case == "id"
                    else "cold-handoff-" + "a" * 24
                )
                device = "1" if case == "id" else "0"
                with self.assertRaisesRegex(RuntimeError, "guard|invalid"):
                    self.record(
                        item,
                        transaction_id,
                        "prepared",
                        "--guard-id",
                        guard_id,
                        "--guard-device",
                        device,
                        "--guard-inode",
                        "1",
                    )
                self.assertEqual(self.manifest_path(item).read_bytes(), before)
                self.load(item)

    def test_record_rejects_malformed_hub_without_poisoning_manifest(self) -> None:
        cases = ("hub-id", "intent", "snapshot-traversal")
        for case in cases:
            with self.subTest(case=case):
                item = self.layout(
                    intent="ordinary" if case == "intent" else "server-update"
                )
                transaction_id = self.begin(item)
                data_dir = item.base / "hub-data"
                (data_dir / "maintenance-backups").mkdir(parents=True)
                fence = data_dir / "maintenance-fence.json"
                ActivationLayout.write_file(fence, b"{}\n", 0o600)
                before = self.manifest_path(item).read_bytes()
                hub_id = "short" if case == "hub-id" else "hub-valid-0001"
                snapshot = data_dir / "maintenance-backups" / "snapshot_test"
                if case == "snapshot-traversal":
                    snapshot = (
                        data_dir
                        / "maintenance-backups"
                        / ".."
                        / "snapshot_test"
                    )
                with self.assertRaisesRegex(RuntimeError, "Hub|intent|invalid"):
                    self.record(
                        item,
                        transaction_id,
                        "prepared",
                        "--hub-kind",
                        "server-update",
                        "--hub-data-dir",
                        str(data_dir),
                        "--hub-id",
                        hub_id,
                        "--host-identity",
                        "host-valid-0001",
                        "--operation-id",
                        "operation-1",
                        "--snapshot",
                        str(snapshot),
                    )
                self.assertEqual(self.manifest_path(item).read_bytes(), before)
                self.load(item)

    def test_terminal_record_is_immutable(self) -> None:
        for terminal in ("committed", "rollback-healthy"):
            with self.subTest(terminal=terminal):
                item = self.layout()
                transaction_id = self.begin(item)
                if terminal == "committed":
                    self.advance_to_commit(item, transaction_id)
                else:
                    self.activate_to_linked(item, transaction_id)
                    self.rollback(item, transaction_id)
                before = self.manifest_path(item).read_bytes()
                with self.assertRaisesRegex(RuntimeError, "terminal|phase|immutable"):
                    self.record(
                        item,
                        transaction_id,
                        terminal,
                        "--authority-pending",
                        "true",
                    )
                self.assertEqual(self.manifest_path(item).read_bytes(), before)

    def test_full_commit_is_terminal_and_finish_is_idempotent(self) -> None:
        item = self.layout()
        transaction_id = self.begin(item)
        self.advance_to_commit(item, transaction_id)

        self.invoke("finish", *self.owned_args(item, transaction_id))
        self.invoke("finish", *self.owned_args(item, transaction_id))

        self.assertFalse((item.root / ".activation-transaction").exists())
        self.assertEqual(item.current.resolve().stat().st_ino, item.candidate_inode)
        self.assertEqual(item.previous.resolve().stat().st_ino, item.old_inode)

    def test_finish_rejects_nonterminal_transaction(self) -> None:
        item = self.layout()
        transaction_id = self.begin(item)
        with self.assertRaisesRegex(RuntimeError, "not terminal"):
            self.invoke("finish", *self.owned_args(item, transaction_id))
        self.assertTrue((item.root / ".activation-transaction").is_dir())

    def test_finish_rejects_wrong_owned_invocation_without_retiring(self) -> None:
        cases = ("transaction", "version", "release")
        for case in cases:
            with self.subTest(case=case):
                item = self.layout()
                transaction_id = self.begin(item)
                self.advance_to_commit(item, transaction_id)
                arguments = self.owned_args(item, transaction_id)
                if case == "transaction":
                    arguments[arguments.index("--transaction-id") + 1] = (
                        "activation-" + "0" * 24
                    )
                elif case == "version":
                    arguments[arguments.index("--release-version") + 1] = "9.9.9"
                else:
                    arguments[arguments.index("--release-dir") + 1] = str(
                        item.releases / "other"
                    )
                with self.assertRaises(RuntimeError):
                    self.invoke("finish", *arguments)
                self.assertTrue((item.root / ".activation-transaction").is_dir())

    def test_finish_fails_closed_when_live_terminal_controls_are_missing(self) -> None:
        for control in ("manifest.json", "env.backup", "service.backup"):
            with self.subTest(control=control):
                item = self.layout()
                transaction_id = self.begin(item)
                self.advance_to_commit(item, transaction_id)
                directory = item.root / ".activation-transaction"
                (directory / control).unlink()

                with self.assertRaises((RuntimeError, PermissionError, OSError)):
                    self.invoke("finish", *self.owned_args(item, transaction_id))
                self.assertTrue(directory.is_dir())

    def test_finish_retries_after_atomic_retirement_before_cleanup(self) -> None:
        item = self.layout()
        transaction_id = self.begin(item)
        self.advance_to_commit(item, transaction_id)
        real_cleanup = activation._cleanup_retired_transactions
        crashed = False

        def crash_before_cleanup(root: Path) -> None:
            nonlocal crashed
            if not crashed:
                crashed = True
                raise SimulatedCrash("after transaction retirement")
            real_cleanup(root)

        with mock.patch.object(
            activation,
            "_cleanup_retired_transactions",
            side_effect=crash_before_cleanup,
        ):
            with self.assertRaises(SimulatedCrash):
                self.invoke("finish", *self.owned_args(item, transaction_id))

        retired = item.root / f".activation-transaction-gc-{transaction_id}"
        self.assertTrue(retired.is_dir())
        self.assertFalse((item.root / ".activation-transaction").exists())
        self.invoke("finish", *self.owned_args(item, transaction_id))
        self.assertFalse(retired.exists())

    def test_rollback_finish_retries_after_candidate_park(self) -> None:
        item = self.layout()
        transaction_id = self.begin(item)
        self.activate_to_linked(item, transaction_id)
        self.rollback(item, transaction_id)
        parked = item.root / ".activation-transaction" / "candidate.retired"
        real_rename = activation._rename_and_fsync
        crashed = False

        def crash_after_candidate_park(source: Path, destination: Path) -> None:
            nonlocal crashed
            real_rename(source, destination)
            if Path(destination) == parked and not crashed:
                crashed = True
                raise SimulatedCrash("candidate parked before finish acknowledgement")

        with mock.patch.object(
            activation, "_rename_and_fsync", side_effect=crash_after_candidate_park
        ):
            with self.assertRaises(SimulatedCrash):
                self.invoke("finish", *self.owned_args(item, transaction_id))

        self.assertTrue(parked.is_dir())
        self.invoke("finish", *self.owned_args(item, transaction_id))
        self.assertFalse(parked.exists())
        self.assertFalse(item.release_dir.exists())
        self.assertEqual(item.current.resolve().stat().st_ino, item.old_inode)

    def test_finish_retries_partial_retired_directory_cleanup(self) -> None:
        item = self.layout()
        transaction_id = self.begin(item)
        self.advance_to_commit(item, transaction_id)
        active = item.root / ".activation-transaction"
        retired = item.root / f".activation-transaction-gc-{transaction_id}"
        os.rename(active, retired)
        (retired / "manifest.json").unlink()

        self.invoke("finish", *self.owned_args(item, transaction_id))

        self.assertFalse(retired.exists())

    def test_rolled_back_finish_removes_only_exact_candidate(self) -> None:
        item = self.layout(same_version=True)
        transaction_id = self.begin(item)
        self.activate_to_linked(item, transaction_id)
        self.rollback(item, transaction_id)
        unrelated = item.releases / "unrelated"
        ActivationLayout.create_release(unrelated, "8.8.8", marker="keep\n")

        self.invoke("finish", *self.owned_args(item, transaction_id))

        self.assertEqual(item.release_dir.stat().st_ino, item.old_inode)
        self.assertTrue(unrelated.is_dir())
        self.assertFalse((item.root / ".activation-transaction").exists())

    def test_manifest_corruption_and_control_file_types_fail_closed(self) -> None:
        cases = ("invalid-json", "symlink", "hardlink", "mode")
        for case in cases:
            with self.subTest(case=case):
                item = self.layout()
                self.begin(item)
                manifest = self.manifest_path(item)
                original = manifest.read_bytes()
                if case == "invalid-json":
                    manifest.write_bytes(b"{not-json")
                elif case == "symlink":
                    external = item.base / "external-manifest"
                    ActivationLayout.write_file(external, original, 0o600)
                    manifest.unlink()
                    manifest.symlink_to(external)
                elif case == "hardlink":
                    external = item.base / "external-manifest"
                    manifest.rename(external)
                    os.link(external, manifest)
                else:
                    os.chmod(manifest, 0o644)

                with self.assertRaises((RuntimeError, PermissionError, OSError)):
                    self.load(item)
                self.assertEqual(item.current.resolve().stat().st_ino, item.old_inode)

    def test_backup_tamper_symlink_hardlink_and_fifo_fail_closed(self) -> None:
        cases = ("content", "symlink", "hardlink")
        for case in cases:
            with self.subTest(case=case):
                item = self.layout()
                self.begin(item)
                backup = item.root / ".activation-transaction" / "env.backup"
                if case == "content":
                    backup.write_bytes(b"tampered\n")
                elif case == "symlink":
                    external = item.base / "external-backup"
                    ActivationLayout.write_file(external, item.original_env, 0o600)
                    backup.unlink()
                    backup.symlink_to(external)
                elif case == "hardlink":
                    external = item.base / "external-backup"
                    backup.rename(external)
                    os.link(external, backup)
                with self.assertRaises((RuntimeError, PermissionError, OSError)):
                    self.load(item)

    def test_begin_rejects_symlink_hardlink_and_fifo_config_controls(self) -> None:
        cases = ("symlink", "hardlink")
        for case in cases:
            with self.subTest(case=case):
                item = self.layout()
                original = item.env
                moved = item.base / "real-env"
                if case == "symlink":
                    original.rename(moved)
                    original.symlink_to(moved)
                elif case == "hardlink":
                    os.link(original, moved)
                with self.assertRaises((RuntimeError, PermissionError, OSError)):
                    self.begin(item)

    def test_fifo_controls_are_rejected_without_blocking(self) -> None:
        scenarios = ("manifest", "backup", "begin-config", "replace-config")
        for scenario in scenarios:
            with self.subTest(scenario=scenario):
                item = self.layout()
                if scenario == "begin-config":
                    item.env.unlink()
                    os.mkfifo(item.env, 0o600)
                    arguments = [
                        "begin",
                        *self.layout_args(item),
                        "--release-dir",
                        str(item.release_dir),
                        "--release-version",
                        item.release_version,
                        "--old-source",
                        str(item.old_source),
                        "--old-target",
                        str(item.old_target),
                        "--candidate-source",
                        str(item.candidate_source),
                        "--service-state",
                        "running",
                        "--service-enabled",
                        "true",
                        "--legacy-service-state",
                        "absent",
                        "--legacy-service-enabled",
                        "false",
                        "--prior-port",
                        "7850",
                        "--prior-bind-address",
                        "127.0.0.1",
                        "--intent",
                        "ordinary",
                    ]
                else:
                    transaction_id = self.begin(item)
                    if scenario == "manifest":
                        control = self.manifest_path(item)
                        control.unlink()
                        os.mkfifo(control, 0o600)
                        arguments = ["load", *self.layout_args(item)]
                    elif scenario == "backup":
                        control = (
                            item.root / ".activation-transaction" / "env.backup"
                        )
                        control.unlink()
                        os.mkfifo(control, 0o600)
                        arguments = ["load", *self.layout_args(item)]
                    else:
                        self.activate_to_linked(item, transaction_id)
                        source = item.env.parent / f".env.activation-{transaction_id}-env.source"
                        os.mkfifo(source, 0o600)
                        arguments = [
                            "replace-config",
                            *self.owned_args(item, transaction_id),
                            "--kind",
                            "env",
                            "--source",
                            str(source),
                            "--mode",
                            "600",
                        ]

                result = self.invoke_subprocess(*arguments)
                self.assertNotEqual(result.returncode, 0, result.stdout)

    def test_begin_rejects_symlink_hardlink_and_fifo_release_versions(self) -> None:
        for control_type in ("symlink", "hardlink", "fifo"):
            with self.subTest(control_type=control_type):
                item = self.layout()
                version = item.candidate_source / "VERSION"
                external = item.base / "external-version"
                if control_type == "symlink":
                    version.rename(external)
                    version.symlink_to(external)
                elif control_type == "hardlink":
                    os.link(version, external)
                else:
                    version.unlink()
                    os.mkfifo(version, 0o600)
                arguments = [
                    "begin",
                    *self.layout_args(item),
                    "--release-dir",
                    str(item.release_dir),
                    "--release-version",
                    item.release_version,
                    "--old-source",
                    str(item.old_source),
                    "--old-target",
                    str(item.old_target),
                    "--candidate-source",
                    str(item.candidate_source),
                    "--service-state",
                    "running",
                    "--service-enabled",
                    "true",
                    "--legacy-service-state",
                    "absent",
                    "--legacy-service-enabled",
                    "false",
                    "--prior-port",
                    "7850",
                    "--prior-bind-address",
                    "127.0.0.1",
                    "--intent",
                    "ordinary",
                ]
                result = self.invoke_subprocess(*arguments)
                self.assertNotEqual(result.returncode, 0, result.stdout)
                self.assertFalse((item.root / ".activation-transaction").exists())

    def test_tampered_release_inode_version_and_links_fail_closed(self) -> None:
        cases = ("old-inode", "old-version", "current", "previous")
        for case in cases:
            with self.subTest(case=case):
                item = self.layout()
                self.begin(item)
                if case == "old-inode":
                    item.old_source.rename(item.base / "old-away")
                    ActivationLayout.create_release(
                        item.old_source, "1.0.0", marker="substitute\n"
                    )
                elif case == "old-version":
                    (item.old_source / "VERSION").write_text("1.0.1\n")
                elif case == "current":
                    wrong = item.releases / "wrong-current"
                    ActivationLayout.create_release(wrong, "7.0.0", marker="wrong\n")
                    item.current.unlink()
                    item.current.symlink_to(wrong, target_is_directory=True)
                else:
                    wrong = item.releases / "wrong-previous"
                    ActivationLayout.create_release(wrong, "7.0.1", marker="wrong\n")
                    item.previous.unlink()
                    item.previous.symlink_to(wrong, target_is_directory=True)

                with self.assertRaises(RuntimeError):
                    self.load(item)

    def test_release_identity_hash_reads_exact_size_across_short_reads(self) -> None:
        item = self.layout()
        version_inodes = {
            (item.candidate_source / "VERSION").stat().st_ino,
            (item.old_source / "VERSION").stat().st_ino,
        }
        real_read = activation.os.read

        def short_read(descriptor: int, count: int) -> bytes:
            if os.fstat(descriptor).st_ino in version_inodes:
                count = min(count, 1)
            return real_read(descriptor, count)

        with mock.patch.object(activation.os, "read", side_effect=short_read):
            transaction_id = self.begin(item)
        self.assertRegex(transaction_id, r"^activation-[0-9a-f]{24}$")

    def test_release_identity_rejects_writable_directory_or_version(self) -> None:
        for target in ("directory", "version"):
            with self.subTest(target=target):
                item = self.layout()
                path = (
                    item.candidate_source
                    if target == "directory"
                    else item.candidate_source / "VERSION"
                )
                os.chmod(path, 0o777 if target == "directory" else 0o666)
                with self.assertRaises(PermissionError):
                    self.begin(item)

    def test_tampered_configuration_after_begin_fails_closed(self) -> None:
        item = self.layout()
        self.begin(item)
        item.env.write_bytes(b"external mutation\n")

        with self.assertRaisesRegex(RuntimeError, "configuration"):
            self.load(item)

    def test_manifest_release_path_escape_fails_closed(self) -> None:
        item = self.layout()
        self.begin(item)
        external = item.base / "outside" / "candidate"
        external.parent.mkdir()
        item.candidate_source.rename(external)

        def escape(value: dict[str, object]) -> None:
            value["candidate_release"]["source"] = str(external)
            value["candidate_release"]["target"] = str(external)

        self.rewrite_manifest(item, escape)

        with self.assertRaisesRegex(RuntimeError, "path|layout|release"):
            self.load(item)

    def test_unknown_schema_phase_and_bad_coordinates_fail_closed(self) -> None:
        mutations = {
            "schema": lambda value: value.__setitem__("format", 999),
            "schema-extra": lambda value: value.__setitem__("unexpected", True),
            "schema-missing": lambda value: value.pop("guard"),
            "phase": lambda value: value.__setitem__("phase", "unknown"),
            "transaction": lambda value: value.__setitem__("transaction_id", "bad"),
            "candidate-hash": lambda value: value["candidate_release"].__setitem__(
                "version_sha256", "g" * 64
            ),
            "prior-port": lambda value: value.__setitem__("prior_port", 0),
            "prior-bind": lambda value: value.__setitem__(
                "prior_bind_address", "127.000.000.001"
            ),
            "guard-zero": lambda value: value.__setitem__(
                "guard", {"id": "cold-handoff-" + "a" * 24, "device": 0, "inode": 1}
            ),
        }
        for name, mutate in mutations.items():
            with self.subTest(name=name):
                item = self.layout()
                self.begin(item)
                self.rewrite_manifest(item, mutate)
                with self.assertRaises(RuntimeError):
                    self.load(item)

    def test_finish_rejects_unexpected_or_unsafe_retired_controls(self) -> None:
        item = self.layout()
        transaction_id = self.begin(item)
        self.advance_to_commit(item, transaction_id)
        unexpected = item.root / ".activation-transaction" / "unexpected"
        ActivationLayout.write_file(unexpected, b"keep\n", 0o600)
        with self.assertRaisesRegex(RuntimeError, "unexpected"):
            self.invoke("finish", *self.owned_args(item, transaction_id))
        self.assertTrue(unexpected.exists())

    def test_unsafe_orphan_gc_symlink_is_not_followed(self) -> None:
        item = self.layout()
        external = item.base / "external-directory"
        external.mkdir()
        sentinel = external / "sentinel"
        sentinel.write_text("preserve\n")
        unsafe = item.root / (
            ".activation-transaction-gc-activation-" + "d" * 24
        )
        unsafe.symlink_to(external, target_is_directory=True)

        with self.assertRaises(PermissionError):
            self.begin(item)
        self.assertEqual(sentinel.read_text(), "preserve\n")


if __name__ == "__main__":
    unittest.main()
