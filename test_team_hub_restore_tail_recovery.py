from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest

from agentsdock_team_hub.store import HubStore
import test_team_hub_managed_host as managed_host_tests


HOST_IDENTITY = "server-host-a-12345678"


class RestoreTailRecoveryTests(unittest.TestCase):
    def test_prepared_receipt_tail_blocks_startup_then_exact_retry_converges(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            data_dir = Path(temporary) / "hub"
            store = HubStore(data_dir, managed_host_identity=HOST_IDENTITY)
            operation_id = "restore-tail-recovery"
            snapshot = store.maintenance_snapshot_and_fence(
                "server-update",
                operation_id=operation_id,
            )

            # Leave a durable prepared restore transaction, then interrupt its
            # rollback cleanup immediately after the journal unlink.  This is
            # the only safe one-file tail: the prepared receipt remains as a
            # startup blocker and an exact retry token.
            crashed_restore = (
                managed_host_tests.ManagedHostTests.run_restore_until_crash(
                    data_dir,
                    snapshot,
                    hub_id=store.hub_id,
                    operation_id=operation_id,
                    crash_point="retire",
                )
            )
            self.assertEqual(crashed_restore.returncode, 71, crashed_restore.stderr)
            crashed_cleanup = (
                managed_host_tests.ManagedHostTests.run_restore_cleanup_until_crash(
                    data_dir,
                    target_name=".restore-transaction.json",
                )
            )
            self.assertEqual(crashed_cleanup.returncode, 76, crashed_cleanup.stderr)

            journal_path = data_dir / ".restore-transaction.json"
            receipt_path = data_dir / ".restore-completion.json"
            self.assertFalse(journal_path.exists())
            receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
            self.assertEqual(receipt["state"], "prepared")
            self.assertEqual(receipt["operation_id"], operation_id)
            self.assertTrue((data_dir / "maintenance-fence.json").exists())
            with self.assertRaisesRegex(
                RuntimeError,
                "rollback settlement is pending",
            ):
                HubStore(data_dir, managed_host_identity=HOST_IDENTITY)

            # The same fenced operation adopts the prepared receipt. It
            # reaches a committed receipt, remains fail-closed until the
            # outer activation rollback confirms it, and can then be retired
            # idempotently without a journal/no-receipt wedge.
            HubStore.restore_maintenance_snapshot(
                data_dir,
                snapshot,
                expected_host_identity=HOST_IDENTITY,
                expected_hub_id=store.hub_id,
                expected_operation_id=operation_id,
            )
            self.assertFalse(journal_path.exists())
            self.assertEqual(
                json.loads(receipt_path.read_text(encoding="utf-8"))["state"],
                "committed",
            )
            with self.assertRaisesRegex(
                RuntimeError,
                "rollback settlement is pending",
            ):
                HubStore(data_dir, managed_host_identity=HOST_IDENTITY)

            HubStore.confirm_restored_maintenance_snapshot(
                data_dir,
                snapshot,
                expected_host_identity=HOST_IDENTITY,
                expected_hub_id=store.hub_id,
                expected_operation_id=operation_id,
            )
            HubStore.acknowledge_restored_maintenance_snapshot(
                data_dir,
                snapshot,
                expected_host_identity=HOST_IDENTITY,
                expected_hub_id=store.hub_id,
                expected_operation_id=operation_id,
            )
            self.assertFalse(receipt_path.exists())
            self.assertEqual(
                HubStore(data_dir, managed_host_identity=HOST_IDENTITY).hub_id,
                store.hub_id,
            )


if __name__ == "__main__":
    unittest.main()
