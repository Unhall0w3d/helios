"""Tests for the intentionally conservative Cisco lifecycle catalog."""

from __future__ import annotations

from datetime import date
import unittest

from cisco_collab_health.lifecycle import lifecycle_for, lifecycle_status


class LifecycleCatalogTests(unittest.TestCase):
    def test_exact_known_release_is_returned(self) -> None:
        record = lifecycle_for("cucm", "12.5.1.11900-146")

        self.assertIsNotNone(record)
        assert record is not None
        self.assertEqual(record.release, "12.5")
        self.assertEqual(record.last_support, date(2025, 8, 31))

    def test_10x_maintenance_releases_use_the_major_version_notice(self) -> None:
        for version in ("10.5.2.12901-1", "v10SU3", "10SU6"):
            with self.subTest(version=version):
                record = lifecycle_for("cucm", version)
                self.assertIsNotNone(record)
                assert record is not None
                self.assertEqual(record.release, "10")

    def test_unverified_release_is_not_inferred(self) -> None:
        self.assertIsNone(lifecycle_for("cucm", "15.0.1.12900-43"))

    def test_maintenance_status_is_plain_language(self) -> None:
        record = lifecycle_for("cucm", "14.0")
        assert record is not None

        status = lifecycle_status(record, as_of=date(2026, 7, 16))

        self.assertEqual(status.label, "Cisco software maintenance ended")
        self.assertTrue(status.attention_needed)
