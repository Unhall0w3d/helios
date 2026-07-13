"""Tests for bounded CUCM UCOS CLI summaries."""

from __future__ import annotations

import unittest

from cisco_collab_health.collectors.cucm_platform import _summary


class CucmPlatformSummaryTests(unittest.TestCase):
    def test_ntp_and_replication_summaries(self) -> None:
        ntp = _summary(
            "utils ntp status",
            "synchronized to NTP server (10.0.0.10) at stratum 3\n^? bad-source",
        )
        replication = _summary(
            "utils dbreplication runtimestate",
            "pub 10.0.0.1 0.01 Y/Y/Y 0 (g_2) (2) Setup Completed\n"
            "sub 10.0.0.2 0.01 Y/Y/Y 0 (g_2) (1) Setup Failed",
        )

        self.assertEqual(ntp["synchronized"], "true")
        self.assertEqual(ntp["stratum"], "3")
        self.assertEqual(ntp["bad_sources"], "1")
        self.assertEqual(replication["replication_rows"], "2")
        self.assertEqual(replication["replication_bad_rows"], "1")
