import argparse
import io
import hashlib
import json
import os
import sys
import tarfile
import tempfile
import unittest
from urllib.error import HTTPError
from pathlib import Path
from unittest.mock import patch

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import update_runner


class UpdateRunnerTests(unittest.TestCase):
    @staticmethod
    def secure_peer_capability(*, state_available: bool = True):
        return {
            "available": True,
            "state_available": state_available,
            "state_error_code": (
                None if state_available else "secure_peer_state_unavailable"
            ),
            "required": False,
            "version": 1,
            "control_path": "/api/admin/secure-peers/v1/status",
            "proxy_prefix": "/api/team-hub-secure",
        }

    def signed_manifest(
        self,
        version: str = "1.2.3",
        *,
        track: str | None = None,
        prerelease: bool | None = None,
    ):
        private = Ed25519PrivateKey.generate()
        manifest = {
            "schema": 1,
            "version": version,
            "api_contract_version": 10,
            "archive": {
                "name": f"agents-server-{version}.tar.gz",
                "url": f"https://github.com/ZhengyiLuo/AgentsServer/releases/download/v{version}/agents-server-{version}.tar.gz",
                "sha256": "a" * 64,
            },
        }
        if track is not None:
            manifest["track"] = track
        if prerelease is not None:
            manifest["prerelease"] = prerelease
        payload = (json.dumps(manifest, sort_keys=True) + "\n").encode()
        return private, payload, private.sign(payload)

    @staticmethod
    def release(version: str, *, prerelease: bool | None = None, draft: bool = False):
        return {
            "tag_name": f"v{version}",
            "prerelease": ("-" in version) if prerelease is None else prerelease,
            "draft": draft,
        }

    def test_signed_manifest_accepts_only_trusted_release_location(self):
        private, payload, signature = self.signed_manifest()
        with tempfile.TemporaryDirectory() as temporary:
            public_path = Path(temporary) / "public.pem"
            public_path.write_bytes(private.public_key().public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            ))
            manifest = update_runner.verify_manifest(payload, signature, public_path)
        self.assertEqual(manifest["version"], "1.2.3")

    def test_manifest_signature_tampering_is_rejected(self):
        private, payload, signature = self.signed_manifest()
        with tempfile.TemporaryDirectory() as temporary:
            public_path = Path(temporary) / "public.pem"
            public_path.write_bytes(private.public_key().public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            ))
            with self.assertRaises(Exception):
                update_runner.verify_manifest(payload + b" ", signature, public_path)

    def test_manifest_must_match_immutable_release_tag(self):
        private, payload, signature = self.signed_manifest("1.2.3")
        with tempfile.TemporaryDirectory() as temporary:
            public_path = Path(temporary) / "public.pem"
            public_path.write_bytes(private.public_key().public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            ))
            with self.assertRaisesRegex(RuntimeError, "immutable release tag"):
                update_runner.verify_manifest(
                    payload,
                    signature,
                    public_path,
                    expected_version="1.2.4",
                )

    def test_legacy_beta_manifest_is_accepted_only_on_beta_track(self):
        private, payload, signature = self.signed_manifest("1.3.0-beta.2")
        with tempfile.TemporaryDirectory() as temporary:
            public_path = Path(temporary) / "public.pem"
            public_path.write_bytes(private.public_key().public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            ))
            manifest = update_runner.verify_manifest(
                payload,
                signature,
                public_path,
                track="beta",
            )
            with self.assertRaisesRegex(RuntimeError, "requested stable track"):
                update_runner.verify_manifest(payload, signature, public_path)
        self.assertEqual(manifest["version"], "1.3.0-beta.2")

    def test_manifest_track_metadata_must_match_version(self):
        private, payload, signature = self.signed_manifest(
            "1.3.0-beta.2",
            track="stable",
            prerelease=True,
        )
        with tempfile.TemporaryDirectory() as temporary:
            public_path = Path(temporary) / "public.pem"
            public_path.write_bytes(private.public_key().public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            ))
            with self.assertRaisesRegex(RuntimeError, "track metadata"):
                update_runner.verify_manifest(
                    payload,
                    signature,
                    public_path,
                    track="beta",
                )

    def test_stable_release_candidates_exclude_prereleases_and_drafts(self):
        releases = [
            self.release("1.2.4-beta.2"),
            self.release("1.2.3"),
            self.release("1.2.2"),
            self.release("9.0.0", draft=True),
            self.release("8.0.0", prerelease=True),
        ]
        self.assertEqual(update_runner.stable_release_candidates(releases), ["1.2.3", "1.2.2"])

    def test_beta_release_candidates_exclude_stable_mislabeled_and_drafts(self):
        releases = [
            self.release("1.3.0-beta.2"),
            self.release("1.3.0-beta.1"),
            self.release("1.2.3"),
            self.release("9.0.0-beta.1", draft=True),
            self.release("8.0.0-beta.1", prerelease=False),
        ]
        self.assertEqual(
            update_runner.release_candidates(releases, "beta"),
            ["1.3.0-beta.2", "1.3.0-beta.1"],
        )

    def test_html_release_discovery_filters_by_track(self):
        content = b"""
        <a href="/ZhengyiLuo/AgentsServer/releases/tag/v1.2.3">stable</a>
        <a href="/ZhengyiLuo/AgentsServer/releases/tag/v1.3.0-beta.2">beta</a>
        """
        self.assertEqual(update_runner.release_versions_from_html(content), {"1.2.3"})
        self.assertEqual(
            update_runner.release_versions_from_html(content, "beta"),
            {"1.3.0-beta.2"},
        )

    def test_signed_stable_release_uses_only_versioned_asset_urls(self):
        private, payload, signature = self.signed_manifest("1.2.3")
        releases = json.dumps([
            self.release("2.0.0-beta.1"),
            self.release("1.2.3"),
        ]).encode()
        assets = {
            update_runner.RELEASES_API_URL: releases,
            update_runner.release_manifest_url("1.2.3"): payload,
            update_runner.release_signature_url("1.2.3"): signature,
        }
        seen: list[str] = []

        def download(url, _limit, timeout=30.0):
            seen.append(url)
            self.assertNotIn("/latest/", url)
            return assets[url]

        with tempfile.TemporaryDirectory() as temporary:
            public_path = Path(temporary) / "public.pem"
            public_path.write_bytes(private.public_key().public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            ))
            with patch.object(update_runner, "download_bytes", side_effect=download):
                manifest = update_runner.check_release(public_path)

        self.assertEqual(manifest["version"], "1.2.3")
        self.assertFalse(any("2.0.0-beta.1" in url for url in seen))

    def test_signed_beta_release_uses_only_versioned_asset_urls(self):
        private, payload, signature = self.signed_manifest("1.3.0-beta.2")
        releases = json.dumps([
            self.release("1.3.0-beta.2"),
            self.release("1.2.3"),
        ]).encode()
        assets = {
            update_runner.RELEASES_API_URL: releases,
            update_runner.release_manifest_url("1.3.0-beta.2"): payload,
            update_runner.release_signature_url("1.3.0-beta.2"): signature,
        }
        seen: list[str] = []

        def download(url, _limit, timeout=30.0):
            seen.append(url)
            self.assertNotIn("/latest/", url)
            return assets[url]

        with tempfile.TemporaryDirectory() as temporary:
            public_path = Path(temporary) / "public.pem"
            public_path.write_bytes(private.public_key().public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            ))
            with patch.object(update_runner, "download_bytes", side_effect=download):
                manifest = update_runner.check_release(public_path, "beta")

        self.assertEqual(manifest["version"], "1.3.0-beta.2")
        self.assertFalse(any("/v1.2.3/" in url for url in seen))

    def test_pinned_release_uses_exact_immutable_assets_without_latest_discovery(self):
        private, payload, signature = self.signed_manifest("1.3.0-beta.1")
        assets = {
            update_runner.release_manifest_url("1.3.0-beta.1"): payload,
            update_runner.release_signature_url("1.3.0-beta.1"): signature,
        }
        seen: list[str] = []

        def download(url, _limit, timeout=30.0):
            seen.append(url)
            return assets[url]

        with tempfile.TemporaryDirectory() as temporary:
            public_path = Path(temporary) / "public.pem"
            public_path.write_bytes(private.public_key().public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            ))
            with patch.object(update_runner, "download_bytes", side_effect=download):
                manifest = update_runner.check_release(
                    public_path,
                    "beta",
                    expected_version="1.3.0-beta.1",
                )

        self.assertEqual(manifest["version"], "1.3.0-beta.1")
        self.assertEqual(
            seen,
            [
                update_runner.release_manifest_url("1.3.0-beta.1"),
                update_runner.release_signature_url("1.3.0-beta.1"),
            ],
        )
        self.assertNotIn(update_runner.RELEASES_API_URL, seen)

    def test_pinned_release_must_match_requested_track_before_download(self):
        with patch.object(update_runner, "download_bytes") as download:
            with self.assertRaisesRegex(RuntimeError, "requested stable track"):
                update_runner.check_release(
                    Path("unused-key.pem"),
                    "stable",
                    expected_version="1.3.0-beta.1",
                )
        download.assert_not_called()

    def test_beta_channel_exit_rejects_a_pinned_older_stable_release(self):
        private, latest_payload, latest_signature = self.signed_manifest("1.2.4")
        releases = json.dumps([
            self.release("1.2.4"),
            self.release("1.0.0"),
        ]).encode()
        assets = {
            update_runner.RELEASES_API_URL: releases,
            update_runner.release_manifest_url("1.2.4"): latest_payload,
            update_runner.release_signature_url("1.2.4"): latest_signature,
        }
        seen: list[str] = []

        def download(url, _limit, timeout=30.0):
            seen.append(url)
            return assets[url]

        with tempfile.TemporaryDirectory() as temporary:
            public_path = Path(temporary) / "public.pem"
            public_path.write_bytes(private.public_key().public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            ))
            with patch.object(update_runner, "download_bytes", side_effect=download):
                with self.assertRaisesRegex(RuntimeError, "no longer the latest"):
                    update_runner.check_release(
                        public_path,
                        "stable",
                        expected_version="1.0.0",
                        require_latest=True,
                    )

        self.assertEqual(
            seen,
            [
                update_runner.RELEASES_API_URL,
                update_runner.release_manifest_url("1.2.4"),
                update_runner.release_signature_url("1.2.4"),
            ],
        )
        self.assertNotIn(update_runner.release_manifest_url("1.0.0"), seen)

    def test_safe_extract_rejects_path_traversal(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            archive_path = root / "bad.tar.gz"
            with tarfile.open(archive_path, "w:gz") as archive:
                entry = tarfile.TarInfo("../outside")
                entry.size = 1
                archive.addfile(entry, io.BytesIO(b"x"))
            with self.assertRaisesRegex(RuntimeError, "unsafe path"):
                update_runner.safe_extract(archive_path, root / "extract")

    def test_status_write_is_durable_json(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "admin" / "status.json"
            update_runner.update_status(path, phase="checking", update_id="abc")
            update_runner.update_status(path, phase="complete")
            value = json.loads(path.read_text())
        self.assertEqual(value["phase"], "complete")
        self.assertEqual(value["update_id"], "abc")

    def test_stale_runner_cannot_heartbeat_or_complete_newer_update(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            status_path = root / "server-update.json"
            log_path = root / "server-update.log"
            newer = update_runner.update_status(
                status_path,
                phase="starting",
                update_id="update-new",
                target_version="2.0.0",
            )
            with self.assertRaises(update_runner.UpdateOwnershipLostError):
                update_runner.run_installer(
                    [sys.executable, "-c", "import time; time.sleep(5)"],
                    cwd=root,
                    status_path=status_path,
                    log_path=log_path,
                    version="1.2.3",
                    expected_update_id="update-old",
                    timeout_seconds=2,
                    heartbeat_seconds=0.02,
                )
            self.assertEqual(json.loads(status_path.read_text()), newer)
            with self.assertRaises(update_runner.UpdateOwnershipLostError):
                update_runner.update_status(
                    status_path,
                    expected_update_id="update-old",
                    phase="complete",
                    installed_version="1.2.3",
                )
            self.assertEqual(json.loads(status_path.read_text()), newer)
            terminal = update_runner.update_status(
                status_path,
                phase="failed",
                update_id="update-old",
                message="finalized by the server",
            )
            with self.assertRaises(update_runner.UpdateOwnershipLostError):
                update_runner.update_status(
                    status_path,
                    expected_update_id="update-old",
                    phase="complete",
                )
            self.assertEqual(json.loads(status_path.read_text()), terminal)

    def test_missing_release_has_a_clear_error(self):
        missing = HTTPError(update_runner.RELEASES_API_URL, 404, "Not Found", {}, None)
        with patch.object(update_runner, "download_bytes", side_effect=missing):
            with self.assertRaisesRegex(update_runner.ReleaseUnavailableError, "No signed AgentsServer release"):
                update_runner.check_release(Path("unused.pem"))

    def test_installer_streams_log_and_records_heartbeat(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            status_path = root / "server-update.json"
            log_path = root / "server-update.log"
            update_runner.run_installer(
                [
                    sys.executable,
                    "-c",
                    "import time; print('started', flush=True); time.sleep(0.08); print('finished')",
                ],
                cwd=root,
                status_path=status_path,
                log_path=log_path,
                version="1.2.3",
                timeout_seconds=2,
                heartbeat_seconds=0.02,
            )

            self.assertEqual(log_path.read_text().splitlines(), ["started", "finished"])
            self.assertEqual(os.stat(log_path).st_mode & 0o777, 0o600)
            status = json.loads(status_path.read_text())
            self.assertEqual(status["phase"], "installing")
            self.assertGreaterEqual(status["elapsed_seconds"], 1)
            self.assertIn("elapsed", status["message"])

    def test_installer_failure_includes_bounded_log_tail(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with self.assertRaisesRegex(RuntimeError, r"installer failed \(7\): useful diagnostic"):
                update_runner.run_installer(
                    [
                        sys.executable,
                        "-c",
                        "import sys; print('useful diagnostic', file=sys.stderr, flush=True); raise SystemExit(7)",
                    ],
                    cwd=root,
                    status_path=root / "server-update.json",
                    log_path=root / "server-update.log",
                    version="1.2.3",
                    timeout_seconds=2,
                    heartbeat_seconds=0.02,
                )

    def test_installer_failure_redacts_setup_and_bearer_secrets_from_status_tail(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            secret = "secret_agent_token_abcdefghijklmnopqrstuvwxyz0123456789"
            script = (
                "import sys; "
                f"print('AGENTSDOCK_SETUP_RESULT={{\"access_token\":\"{secret}\"}}', flush=True); "
                f"print('Authorization: Bearer {secret}', flush=True); "
                f"print('{{\"access_token\":\"{secret}\"}}', flush=True); "
                "print('safe diagnostic', flush=True); "
                "raise SystemExit(7)"
            )
            with self.assertRaises(RuntimeError) as raised:
                update_runner.run_installer(
                    [sys.executable, "-c", script],
                    cwd=root,
                    status_path=root / "server-update.json",
                    log_path=root / "server-update.log",
                    version="1.2.3",
                    timeout_seconds=2,
                    heartbeat_seconds=0.02,
                )

            message = str(raised.exception)
            self.assertIn("safe diagnostic", message)
            self.assertNotIn(secret, message)
            self.assertNotIn("AGENTSDOCK_SETUP_RESULT", message)
            self.assertIn("[REDACTED]", message)

    def test_installer_log_tail_redacts_json_secret_when_tail_starts_mid_line(self):
        with tempfile.TemporaryDirectory() as temporary:
            log_path = Path(temporary) / "server-update.log"
            secret = "secret_agent_token_abcdefghijklmnopqrstuvwxyz0123456789"
            log_path.write_text(
                "AGENTSDOCK_SETUP_RESULT={\"padding\":\""
                + ("x" * (update_runner.INSTALLER_LOG_TAIL_BYTES + 100))
                + f"\",\"access_token\":\"{secret}\"}}\n"
                + "safe diagnostic\n"
            )

            tail = update_runner.installer_log_tail(log_path)

            self.assertNotIn(secret, tail)
            self.assertEqual(tail, "safe diagnostic")

    def test_installer_log_tail_redacts_short_and_punctuated_secrets(self):
        with tempfile.TemporaryDirectory() as temporary:
            log_path = Path(temporary) / "server-update.log"
            secrets = ("x+:/=", "/a b", "p+q==:$", "Q")
            log_path.write_text(
                "prefix AGENTSDOCK_SETUP_RESULT={\"access_token\":\"drop-me\"}\n"
                f"Authorization: Bearer {secrets[0]}\n"
                f"AGENTSDOCK_PROVIDER_AUTHORITY_FILE={secrets[1]}\n"
                f"{{\"access_token\":\"{secrets[2]}\"}}\n"
                f"Bearer {secrets[3]}\n"
                "safe diagnostic\n"
            )

            tail = update_runner.installer_log_tail(log_path)

            self.assertNotIn("AGENTSDOCK_SETUP_RESULT", tail)
            for secret in secrets:
                self.assertNotIn(secret, tail)
            self.assertEqual(tail.count("[REDACTED]"), 4)
            self.assertIn("safe diagnostic", tail)

    def test_installer_log_tail_discards_a_partial_secret_line_at_the_cutoff(self):
        with tempfile.TemporaryDirectory() as temporary:
            log_path = Path(temporary) / "server-update.log"
            secret_suffix = "LEAK+:/=END"
            log_path.write_text(
                "AGENTSDOCK_AGENT_TOKEN="
                + ("x" * (update_runner.INSTALLER_LOG_TAIL_BYTES + 128))
                + secret_suffix
                + "\n"
                + "safe diagnostic\n"
            )

            tail = update_runner.installer_log_tail(log_path)

            self.assertNotIn(secret_suffix, tail)
            self.assertEqual(tail, "safe diagnostic")

    def test_installer_timeout_includes_log_tail_and_stops_process(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with self.assertRaisesRegex(RuntimeError, r"timed out after 0.08 seconds: started"):
                update_runner.run_installer(
                    [
                        sys.executable,
                        "-c",
                        "import time; print('started', flush=True); time.sleep(5)",
                    ],
                    cwd=root,
                    status_path=root / "server-update.json",
                    log_path=root / "server-update.log",
                    version="1.2.3",
                    timeout_seconds=0.08,
                    heartbeat_seconds=0.02,
                )

    def test_installer_drops_inherited_workspace_environment_selectors(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            captured_path = root / "installer-environment.json"
            hostile = {
                name: f"/unrelated/{name.lower()}"
                for name in update_runner.INSTALLER_ENVIRONMENT_SELECTORS
            }
            with patch.dict(os.environ, hostile):
                update_runner.run_installer(
                    [
                        sys.executable,
                        "-c",
                        (
                            "import json, os, pathlib; "
                            f"pathlib.Path({str(captured_path)!r}).write_text("
                            "json.dumps(dict(os.environ)))"
                        ),
                    ],
                    cwd=root,
                    status_path=root / "server-update.json",
                    log_path=root / "server-update.log",
                    version="1.2.3",
                    timeout_seconds=2,
                    heartbeat_seconds=0.02,
                )

            captured = json.loads(captured_path.read_text())
            for name in update_runner.INSTALLER_ENVIRONMENT_SELECTORS:
                self.assertNotIn(name, captured)
            self.assertEqual(captured.get("PATH"), os.environ.get("PATH"))

    def test_private_managed_update_environment_keeps_legacy_cli_compatible(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            legacy_installer = root / "legacy-install.sh"
            captured_path = root / "legacy-arguments.txt"
            captured_environment_path = root / "managed-environment.txt"
            legacy_installer.write_text(
                "#!/bin/sh\n"
                "for argument in \"$@\"; do\n"
                "  case \"$argument\" in\n"
                "    --managed-update-id|--expected-service-cgroup) exit 2 ;;\n"
                "  esac\n"
                "done\n"
                f"printf '%s\\n' \"$@\" > {str(captured_path)!r}\n"
                "printf '%s\\n%s\\n' "
                '"$AGENTSDOCK_MANAGED_UPDATE_ID" '
                '"$AGENTSDOCK_EXPECTED_SERVICE_CGROUP" '
                f"> {str(captured_environment_path)!r}\n"
            )
            legacy_installer.chmod(0o755)

            update_runner.run_installer(
                [str(legacy_installer), "--non-interactive"],
                cwd=root,
                status_path=root / "server-update.json",
                log_path=root / "server-update.log",
                version="1.2.3",
                managed_update_id="update-test-legacy",
                expected_service_cgroup=(
                    "/user.slice/user@1000.service/app.slice/agents-server.service"
                ),
                timeout_seconds=2,
                heartbeat_seconds=0.02,
            )

            self.assertEqual(captured_path.read_text(), "--non-interactive\n")
            self.assertEqual(
                captured_environment_path.read_text().splitlines(),
                [
                    "update-test-legacy",
                    "/user.slice/user@1000.service/app.slice/agents-server.service",
                ],
            )

    def test_detached_runner_rejects_downgrades_before_download(self):
        args = argparse.Namespace(
            status_file="unused-status.json",
            public_key="unused-key.pem",
            port=7850,
            bind="127.0.0.1",
            expected_version="1.2.3",
            current_version="1.2.4",
            expected_server_identity="server-test-identity",
            update_id="update-test-downgrade",
        )
        with patch.object(update_runner, "update_status"), \
             patch.object(update_runner, "check_release", return_value={"version": "1.2.3"}), \
             patch.object(update_runner, "download_bytes") as download:
            with self.assertRaisesRegex(RuntimeError, "only permit forward updates"):
                update_runner.run_update(args)
        download.assert_not_called()

    def test_transition_allows_only_forward_or_beta_to_stable(self):
        self.assertTrue(update_runner.release_transition_allowed("1.2.3", "1.2.4", "stable"))
        self.assertTrue(update_runner.release_transition_allowed("1.3.0-beta.2", "1.2.4", "stable"))
        self.assertFalse(update_runner.release_transition_allowed("1.2.4", "1.2.3", "stable"))
        self.assertFalse(update_runner.release_transition_allowed("1.3.0-beta.2", "1.3.0-beta.1", "beta"))
        self.assertFalse(update_runner.release_transition_allowed("1.3.0", "1.4.0-beta.1", "stable"))
        self.assertFalse(update_runner.release_transition_allowed("1.2.3", "1.2.3", "stable"))

    def test_successful_update_records_default_stable_track(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            archive_buffer = io.BytesIO()
            with tarfile.open(fileobj=archive_buffer, mode="w:gz") as archive:
                installer = b"#!/bin/sh\nexit 0\n"
                entry = tarfile.TarInfo("agents-server-1.2.4/install.sh")
                entry.mode = 0o755
                entry.size = len(installer)
                archive.addfile(entry, io.BytesIO(installer))
            archive_bytes = archive_buffer.getvalue()
            manifest = {
                "version": "1.2.4",
                "archive": {
                    "name": "agents-server-1.2.4.tar.gz",
                    "url": "https://example.invalid/agents-server-1.2.4.tar.gz",
                    "sha256": hashlib.sha256(archive_bytes).hexdigest(),
                },
            }
            args = argparse.Namespace(
                status_file=str(root / "server-update.json"),
                public_key=str(root / "release-public-key.pem"),
                port=7850,
                bind="127.0.0.1",
                expected_version="1.2.4",
                current_version="1.2.3",
                expected_server_identity="server-test-identity",
                update_id="update-test-stable",
                expected_service_cgroup=(
                    "/user.slice/user@1000.service/app.slice/agents-server.service"
                ),
            )
            statuses: list[dict] = []

            def record_status(_path, **changes):
                statuses.append(changes)
                return changes

            with patch.object(update_runner, "check_release", return_value=manifest), \
                 patch.object(update_runner, "download_bytes", return_value=archive_bytes), \
                 patch.object(update_runner, "update_status", side_effect=record_status), \
                 patch.object(update_runner, "assert_server_idle") as idle_check, \
                 patch.object(update_runner, "assert_post_update_identity") as identity_check, \
                 patch.object(update_runner, "run_installer") as install:
                update_runner.run_update(args)

        self.assertEqual(statuses[-1]["phase"], "complete")
        self.assertEqual(statuses[0]["phase"], "checking")
        self.assertEqual(statuses[0]["runner_pid"], os.getpid())
        self.assertTrue(statuses[0]["heartbeat_at"])
        self.assertEqual(statuses[-1]["installed_version"], "1.2.4")
        self.assertFalse(statuses[-1]["update_available"])
        self.assertEqual(statuses[-1]["track"], "stable")
        self.assertIsNone(statuses[-1]["heartbeat_at"])
        self.assertIsNone(statuses[-1]["runner_pid"])
        self.assertIsNone(statuses[-1]["elapsed_seconds"])
        self.assertIsNone(statuses[-1]["error_code"])
        self.assertIsNone(statuses[-1]["error_action"])
        self.assertIsNone(statuses[-1]["retryable"])
        idle_check.assert_called_once_with(
            7850,
            token="",
            require_verified_service_cgroup=True,
        )
        install.assert_called_once()
        install_command = install.call_args.args[0]
        self.assertNotIn("--managed-update-id", install_command)
        self.assertNotIn("--expected-service-cgroup", install_command)
        self.assertEqual(
            install.call_args.kwargs["managed_update_id"],
            "update-test-stable",
        )
        self.assertEqual(
            install.call_args.kwargs["expected_service_cgroup"],
            "/user.slice/user@1000.service/app.slice/agents-server.service",
        )
        identity_check.assert_called_once_with(
            7850,
            token="",
            expected_server_identity="server-test-identity",
            expected_team_hub_id=None,
        )

    def test_post_update_identity_binds_exact_tailnet_transport_and_url(self):
        health = {
            "server_identity": "server-test-identity",
            "capabilities": {
                "secure_peer_v1": self.secure_peer_capability(),
                "team_hub_v1": {
                    "available": True,
                    "designated_host": True,
                    "version": 1,
                    "base_path": "/api/team-hub",
                    "hub_id": "hub_test12345678",
                    "host_server_identity": "server-test-identity",
                    "transport": "tailscale_serve",
                    "hub_url": (
                        "https://sonic.example.ts.net:8444/api/team-hub"
                    ),
                }
            },
        }
        with patch.object(
            update_runner,
            "server_health_snapshot",
            return_value=health,
        ):
            update_runner.assert_post_update_identity(
                7850,
                token="secret",
                expected_server_identity="server-test-identity",
                expected_team_hub_id="hub_test12345678",
                expected_team_hub_transport="tailscale_serve",
                expected_team_hub_url=(
                    "https://sonic.example.ts.net:8444/api/team-hub"
                ),
            )
            with self.assertRaisesRegex(RuntimeError, "changed its Team Hub transport"):
                update_runner.assert_post_update_identity(
                    7850,
                    token="secret",
                    expected_server_identity="server-test-identity",
                    expected_team_hub_id="hub_test12345678",
                    expected_team_hub_transport="tailscale_serve",
                    expected_team_hub_url=(
                        "https://other.example.ts.net:8444/api/team-hub"
                    ),
                )

    def test_post_update_identity_binds_exact_direct_route_set_and_order(self):
        serve_url = "https://sonic.example.ts.net:8444/api/team-hub"
        direct_url = "http://100.73.184.23:7850/api/team-hub"
        capability = {
            "available": True,
            "designated_host": True,
            "version": 1,
            "base_path": "/api/team-hub",
            "hub_id": "hub_test12345678",
            "host_server_identity": "server-test-identity",
            "transport": "tailscale_serve",
            "hub_url": serve_url,
            "routes": [
                {"transport": "tailscale_serve", "hub_url": serve_url},
                {"transport": "direct_ip", "hub_url": direct_url},
            ],
        }
        health = {
            "server_identity": "server-test-identity",
            "capabilities": {
                "secure_peer_v1": self.secure_peer_capability(),
                "team_hub_v1": capability,
            },
        }
        with patch.object(
            update_runner,
            "server_health_snapshot",
            return_value=health,
        ):
            update_runner.assert_post_update_identity(
                7850,
                token="secret",
                expected_server_identity="server-test-identity",
                expected_team_hub_id="hub_test12345678",
                expected_team_hub_transport="tailscale_serve",
                expected_team_hub_url=serve_url,
                expected_team_hub_direct_ip_url=direct_url,
            )
            capability["routes"] = list(reversed(capability["routes"]))
            with self.assertRaisesRegex(RuntimeError, "changed its Team Hub routes"):
                update_runner.assert_post_update_identity(
                    7850,
                    token="secret",
                    expected_server_identity="server-test-identity",
                    expected_team_hub_id="hub_test12345678",
                    expected_team_hub_transport="tailscale_serve",
                    expected_team_hub_url=serve_url,
                    expected_team_hub_direct_ip_url=direct_url,
                )

    def test_repaired_team_hub_identity_requires_exact_host_and_routes(self):
        health = {
            "server_identity": "server-test-identity",
            "capabilities": {
                "team_hub_v1": {
                    "available": True,
                    "designated_host": True,
                    "version": 1,
                    "base_path": "/api/team-hub",
                    "hub_id": "hub_repaired_12345678",
                    "host_server_identity": "server-test-identity",
                    "transport": "loopback",
                    "hub_url": None,
                    "routes": [{"transport": "loopback", "hub_url": None}],
                }
            },
        }
        with patch.object(update_runner, "server_health_snapshot", return_value=health):
            self.assertEqual(
                update_runner.assert_repaired_team_hub_identity(
                    7850,
                    token="secret",
                    expected_server_identity="server-test-identity",
                    expected_team_hub_transport="loopback",
                    expected_team_hub_url=None,
                    expected_team_hub_direct_ip_url="",
                ),
                "hub_repaired_12345678",
            )
            health["capabilities"]["team_hub_v1"]["routes"] = []
            with self.assertRaisesRegex(RuntimeError, "routes changed"):
                update_runner.assert_repaired_team_hub_identity(
                    7850,
                    token="secret",
                    expected_server_identity="server-test-identity",
                    expected_team_hub_transport="loopback",
                    expected_team_hub_url=None,
                    expected_team_hub_direct_ip_url="",
                )

    def test_post_update_identity_rejects_quarantined_secure_peer_state(self):
        health = {
            "server_identity": "server-test-identity",
            "capabilities": {
                "secure_peer_v1": self.secure_peer_capability(
                    state_available=False
                ),
            },
        }
        with patch.object(
            update_runner,
            "server_health_snapshot",
            return_value=health,
        ):
            with self.assertRaisesRegex(RuntimeError, "secure-peer state is unavailable"):
                update_runner.assert_post_update_identity(
                    7850,
                    token="secret",
                    expected_server_identity="server-test-identity",
                )

    def test_runner_passes_explicit_empty_url_for_loopback_hub(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            archive_buffer = io.BytesIO()
            with tarfile.open(fileobj=archive_buffer, mode="w:gz") as archive:
                installer = b"#!/bin/sh\nexit 0\n"
                entry = tarfile.TarInfo("agents-server-1.2.4/install.sh")
                entry.mode = 0o755
                entry.size = len(installer)
                archive.addfile(entry, io.BytesIO(installer))
            archive_bytes = archive_buffer.getvalue()
            manifest = {
                "version": "1.2.4",
                "archive": {
                    "name": "agents-server-1.2.4.tar.gz",
                    "url": "https://example.invalid/agents-server-1.2.4.tar.gz",
                    "sha256": hashlib.sha256(archive_bytes).hexdigest(),
                },
            }
            args = argparse.Namespace(
                status_file=str(root / "server-update.json"),
                public_key=str(root / "release-public-key.pem"),
                port=7850,
                bind="127.0.0.1",
                expected_version="1.2.4",
                current_version="1.2.3",
                expected_server_identity="server-test-identity",
                update_id="update-test-loopback-hub",
                expected_team_hub_id="hub_test12345678",
                expected_team_hub_transport="loopback",
                expected_team_hub_url="",
                expected_team_hub_direct_ip_url="",
                team_hub_snapshot=str(root / "snapshot_exact"),
                team_hub_data_dir=str(root / "hub"),
            )
            with patch.object(update_runner, "check_release", return_value=manifest), \
                 patch.object(update_runner, "download_bytes", return_value=archive_bytes), \
                 patch.object(update_runner, "update_status", side_effect=lambda _path, **changes: changes), \
                 patch.object(update_runner, "assert_server_idle"), \
                 patch.object(update_runner, "assert_post_update_identity") as identity_check, \
                 patch.object(update_runner, "run_installer") as install:
                update_runner.run_update(args)

        command = install.call_args.args[0]
        transport_index = command.index("--expected-team-hub-transport")
        self.assertEqual(command[transport_index + 1], "loopback")
        self.assertEqual(command[transport_index + 2], "--expected-team-hub-url")
        self.assertEqual(command[transport_index + 3], "")
        direct_index = command.index("--expected-team-hub-direct-ip-url")
        self.assertEqual(command[direct_index + 1], "")
        identity_check.assert_called_once_with(
            7850,
            token="",
            expected_server_identity="server-test-identity",
            expected_team_hub_id="hub_test12345678",
            expected_team_hub_transport="loopback",
            expected_team_hub_direct_ip_url="",
        )

    def test_failed_hub_repair_requires_exact_admitted_status_ownership(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            status_path = root / "server-update.json"
            status_path.write_text(
                json.dumps(
                    {
                        "phase": "starting",
                        "update_id": "different-update",
                        "team_hub_repair_mode": "failed_start",
                        "team_hub_host_server_identity": "server-test-identity",
                        "team_hub_transport": "loopback",
                        "team_hub_url": None,
                        "team_hub_direct_ip_url": "",
                        "team_hub_routes": [
                            {"transport": "loopback", "hub_url": None}
                        ],
                    }
                )
            )
            args = argparse.Namespace(
                status_file=str(status_path),
                public_key=str(root / "release-public-key.pem"),
                port=7850,
                bind="127.0.0.1",
                expected_version="1.2.4",
                current_version="1.2.3",
                expected_server_identity="server-test-identity",
                update_id="repair-update-12345678",
                repair_failed_team_hub_host=True,
                expected_team_hub_transport="loopback",
                expected_team_hub_url="",
                expected_team_hub_direct_ip_url="",
            )
            with patch.object(update_runner, "check_release") as release_check:
                with self.assertRaisesRegex(RuntimeError, "exact admitted update"):
                    update_runner.run_update(args)
            release_check.assert_not_called()

    def test_owned_failed_hub_repair_is_forwarded_and_reverified(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            archive_buffer = io.BytesIO()
            with tarfile.open(fileobj=archive_buffer, mode="w:gz") as archive:
                installer = b"#!/bin/sh\nexit 0\n"
                entry = tarfile.TarInfo("agents-server-1.2.4/install.sh")
                entry.mode = 0o755
                entry.size = len(installer)
                archive.addfile(entry, io.BytesIO(installer))
            archive_bytes = archive_buffer.getvalue()
            manifest = {
                "version": "1.2.4",
                "archive": {
                    "name": "agents-server-1.2.4.tar.gz",
                    "url": "https://example.invalid/agents-server-1.2.4.tar.gz",
                    "sha256": hashlib.sha256(archive_bytes).hexdigest(),
                },
            }
            update_id = "repair-update-12345678"
            status_path = root / "server-update.json"
            status_path.write_text(
                json.dumps(
                    {
                        "phase": "starting",
                        "update_id": update_id,
                        "team_hub_repair_mode": "failed_start",
                        "team_hub_host_server_identity": "server-test-identity",
                        "team_hub_transport": "loopback",
                        "team_hub_url": None,
                        "team_hub_direct_ip_url": "",
                        "team_hub_routes": [
                            {"transport": "loopback", "hub_url": None}
                        ],
                    }
                )
            )
            args = argparse.Namespace(
                status_file=str(status_path),
                public_key=str(root / "release-public-key.pem"),
                port=7850,
                bind="127.0.0.1",
                expected_version="1.2.4",
                current_version="1.2.3",
                expected_server_identity="server-test-identity",
                update_id=update_id,
                repair_failed_team_hub_host=True,
                expected_team_hub_transport="loopback",
                expected_team_hub_url="",
                expected_team_hub_direct_ip_url="",
            )
            with patch.object(update_runner, "check_release", return_value=manifest), \
                 patch.object(update_runner, "download_bytes", return_value=archive_bytes), \
                 patch.object(update_runner, "update_status", side_effect=lambda _path, **changes: changes), \
                 patch.object(update_runner, "assert_server_idle"), \
                 patch.object(update_runner, "assert_post_update_identity") as identity_check, \
                 patch.object(update_runner, "assert_repaired_team_hub_identity") as repair_check, \
                 patch.object(update_runner, "run_installer") as install:
                update_runner.run_update(args)

        command = install.call_args.args[0]
        self.assertIn("--repair-failed-team-hub-host", command)
        managed_index = command.index("--managed-update-id")
        self.assertEqual(command[managed_index + 1], update_id)
        self.assertIsNone(install.call_args.kwargs["expected_service_cgroup"])
        self.assertEqual(install.call_args.kwargs["managed_update_id"], update_id)
        identity_check.assert_called_once_with(
            7850,
            token="",
            expected_server_identity="server-test-identity",
            expected_team_hub_id=None,
        )
        repair_check.assert_called_once_with(
            7850,
            token="",
            expected_server_identity="server-test-identity",
            expected_team_hub_transport="loopback",
            expected_team_hub_url=None,
            expected_team_hub_direct_ip_url="",
        )

    def test_detached_runner_allows_explicit_beta_to_pinned_stable_switch(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            legacy_installer_ran = root / "legacy-installer-ran"
            archive_buffer = io.BytesIO()
            with tarfile.open(fileobj=archive_buffer, mode="w:gz") as archive:
                installer = (
                    "#!/bin/sh\n"
                    "for argument in \"$@\"; do\n"
                    "  case \"$argument\" in\n"
                    "    --managed-update-id|--expected-service-cgroup) exit 2 ;;\n"
                    "  esac\n"
                    "done\n"
                    "[ -z \"${AGENTSDOCK_MANAGED_UPDATE_ID:-}\" ] || exit 3\n"
                    "[ -z \"${AGENTSDOCK_EXPECTED_SERVICE_CGROUP:-}\" ] || exit 4\n"
                    f": > {str(legacy_installer_ran)!r}\n"
                ).encode()
                entry = tarfile.TarInfo("agents-server-1.2.4/install.sh")
                entry.mode = 0o755
                entry.size = len(installer)
                archive.addfile(entry, io.BytesIO(installer))
            archive_bytes = archive_buffer.getvalue()
            manifest = {
                "version": "1.2.4",
                "archive": {
                    "name": "agents-server-1.2.4.tar.gz",
                    "url": "https://example.invalid/agents-server-1.2.4.tar.gz",
                    "sha256": hashlib.sha256(archive_bytes).hexdigest(),
                },
            }
            args = argparse.Namespace(
                status_file=str(root / "server-update.json"),
                public_key=str(root / "release-public-key.pem"),
                port=7850,
                bind="127.0.0.1",
                expected_version="1.2.4",
                current_version="1.3.0-beta.2",
                track="stable",
                expected_server_identity="server-test-identity",
                update_id="update-test-switch",
            )
            statuses: list[dict] = []

            with patch.object(update_runner, "check_release", return_value=manifest) as check, \
                 patch.object(update_runner, "download_bytes", return_value=archive_bytes), \
                 patch.object(update_runner, "update_status", side_effect=lambda _path, **changes: statuses.append(changes) or changes), \
                 patch.object(update_runner, "assert_server_idle") as idle_check, \
                 patch.object(update_runner, "assert_post_update_identity") as identity_check:
                update_runner.run_update(args)
            legacy_installer_completed = legacy_installer_ran.is_file()

        check.assert_called_once_with(
            Path(args.public_key).resolve(),
            "stable",
            expected_version="1.2.4",
            require_latest=True,
        )
        idle_check.assert_called_once_with(
            7850,
            token="",
            require_verified_service_cgroup=False,
        )
        self.assertTrue(legacy_installer_completed)
        identity_check.assert_called_once()
        self.assertEqual(statuses[-1]["phase"], "complete")
        self.assertEqual(statuses[-1]["installed_version"], "1.2.4")
        self.assertFalse(statuses[-1]["update_available"])
        self.assertEqual(statuses[-1]["track"], "stable")

    def test_pre_restart_idle_check_rejects_late_work(self):
        with patch.object(
            update_runner,
            "server_work_snapshot",
            return_value=(2, 3),
        ):
            with self.assertRaisesRegex(
                RuntimeError,
                "2 active agent runs and 3 queued turns",
            ):
                update_runner.assert_server_idle(7850, token="one-time-token")

    def test_pre_restart_idle_check_ignores_server_declared_durable_queue(self):
        payload = json.dumps({
            "ok": True,
            "active_count": 0,
            "queued": {"chat": 4},
            "update_blocking_queued_count": 0,
        }).encode()

        class Response:
            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return False

            def read(self, _limit):
                return payload

        with patch.object(update_runner.urllib.request, "urlopen", return_value=Response()):
            snapshot = update_runner.server_work_snapshot(7850)

        self.assertEqual(snapshot, (0, 0))

    def test_pre_restart_idle_check_keeps_legacy_queue_fail_closed(self):
        payload = json.dumps({
            "ok": True,
            "active_count": 0,
            "queued": {"chat": 2},
        }).encode()

        class Response:
            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return False

            def read(self, _limit):
                return payload

        with patch.object(update_runner.urllib.request, "urlopen", return_value=Response()):
            snapshot = update_runner.server_work_snapshot(7850)

        self.assertEqual(snapshot, (0, 2))

    def test_pre_restart_check_rejects_a_nonempty_service_cgroup(self):
        payload = json.dumps({
            "ok": True,
            "active_count": 0,
            "queued": {},
            "update_blocking_queued_count": 0,
            "update_service_cgroup": {
                "safe": False,
                "unknown_descendant_count": 1,
                "inspection": "verified",
            },
        }).encode()

        class Response:
            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return False

            def read(self, _limit):
                return payload

        with patch.object(update_runner.urllib.request, "urlopen", return_value=Response()):
            with self.assertRaisesRegex(RuntimeError, "nonempty service cgroup"):
                update_runner.assert_server_idle(7850)

    def test_pre_restart_check_requires_verified_systemd_ownership_when_bound(self):
        payload = json.dumps({
            "ok": True,
            "active_count": 0,
            "queued": {},
            "update_blocking_queued_count": 0,
            "update_service_cgroup": {
                "safe": True,
                "unknown_descendant_count": 0,
                "inspection": "not-systemd-managed",
            },
        }).encode()

        class Response:
            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return False

            def read(self, _limit):
                return payload

        with patch.object(update_runner.urllib.request, "urlopen", return_value=Response()):
            with self.assertRaisesRegex(RuntimeError, "verified systemd"):
                update_runner.assert_server_idle(
                    7850,
                    require_verified_service_cgroup=True,
                )

    def test_pre_restart_check_reports_tracked_work_before_cgroup_proof(self):
        payload = json.dumps({
            "ok": True,
            "active_count": 1,
            "queued": {},
            "update_blocking_queued_count": 0,
        }).encode()

        class Response:
            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return False

            def read(self, _limit):
                return payload

        with patch.object(update_runner.urllib.request, "urlopen", return_value=Response()):
            with self.assertRaisesRegex(RuntimeError, "1 active agent run"):
                update_runner.assert_server_idle(7850)

    def test_one_time_health_credential_is_consumed(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "update-auth.json"
            update_runner.atomic_json(path, {"token": "secret"})
            token = update_runner.consume_auth_token_file(str(path))

        self.assertEqual(token, "secret")
        self.assertFalse(path.exists())

    def test_termination_never_force_kills_masked_installer_recovery(self):
        class RecoveringInstaller:
            pid = 424242

            def __init__(self):
                self.wait_timeouts = []

            def poll(self):
                return None

            def wait(self, timeout=None):
                self.wait_timeouts.append(timeout)
                if len(self.wait_timeouts) <= 3:
                    raise update_runner.subprocess.TimeoutExpired(
                        "install.sh",
                        timeout,
                    )
                return 0

            def terminate(self):
                raise AssertionError("terminate fallback must not be used")

            def kill(self):
                raise AssertionError("SIGKILL fallback must not be used")

        process = RecoveringInstaller()
        observed_waits = []
        with patch.object(update_runner.os, "killpg") as kill_group:
            update_runner.terminate_installer(
                process,
                on_wait=lambda: observed_waits.append(True),
            )

        self.assertEqual(
            process.wait_timeouts,
            [update_runner.INSTALLER_TERMINATION_POLL_SECONDS] * 4,
        )
        self.assertEqual(observed_waits, [True] * 4)
        kill_group.assert_called_once_with(process.pid, update_runner.signal.SIGTERM)
        self.assertFalse(any(
            call.args == (process.pid, update_runner.signal.SIGKILL)
            for call in kill_group.call_args_list
        ))

    def test_timeout_heartbeats_while_waiting_for_protected_rollback(self):
        class RecoveringInstaller:
            pid = 424242

            def __init__(self):
                self.wait_calls = 0

            def poll(self):
                return None

            def wait(self, timeout=None):
                self.wait_calls += 1
                if self.wait_calls <= 2:
                    raise update_runner.subprocess.TimeoutExpired(
                        "install.sh",
                        timeout,
                    )
                return 0

            def terminate(self):
                raise AssertionError("terminate fallback must not be used")

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            status_path = root / "server-update.json"
            update_runner.update_status(
                status_path,
                phase="installing",
                update_id="update-protected-rollback",
            )
            process = RecoveringInstaller()
            with patch.object(update_runner.subprocess, "Popen", return_value=process), \
                    patch.object(update_runner.os, "killpg") as kill_group:
                with self.assertRaisesRegex(RuntimeError, "timed out after 0 seconds"):
                    update_runner.run_installer(
                        ["install.sh"],
                        cwd=root,
                        status_path=status_path,
                        log_path=root / "server-update.log",
                        version="1.2.3",
                        expected_update_id="update-protected-rollback",
                        timeout_seconds=0,
                    )

            status = json.loads(status_path.read_text())
            self.assertEqual(status["phase"], "installing")
            self.assertIn("waiting for its protected rollback", status["message"])
            self.assertTrue(status["heartbeat_at"])
            self.assertGreaterEqual(status["elapsed_seconds"], 1)
            kill_group.assert_called_once_with(
                process.pid,
                update_runner.signal.SIGTERM,
            )


if __name__ == "__main__":
    unittest.main()
