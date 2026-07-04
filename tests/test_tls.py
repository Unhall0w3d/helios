"""Tests for TLS policy helpers."""

from __future__ import annotations

import unittest
from pathlib import Path
from unittest.mock import patch

from cisco_collab_health.cli import _tls_policy_from_args, _validate_args, build_parser
from cisco_collab_health.collectors.base import TlsPolicy
from cisco_collab_health.transport.tls import build_ssl_context


class TlsPolicyTests(unittest.TestCase):
    def test_default_cli_tls_policy_is_insecure(self) -> None:
        args = build_parser().parse_args([])

        policy = _tls_policy_from_args(args)

        self.assertFalse(policy.verify)
        self.assertIsNone(policy.ca_bundle)

    def test_cli_tls_policy_supports_verify_and_ca_bundle(self) -> None:
        args = build_parser().parse_args(["--verify-tls", "--ca-bundle", "/tmp/ca.pem"])

        policy = _tls_policy_from_args(args)

        self.assertTrue(policy.verify)
        self.assertEqual(policy.ca_bundle, Path("/tmp/ca.pem"))

    def test_verify_tls_and_insecure_are_mutually_exclusive(self) -> None:
        with self.assertRaises(SystemExit) as exc:
            build_parser().parse_args(["--verify-tls", "--insecure"])

        self.assertEqual(exc.exception.code, 2)

    def test_ca_bundle_requires_verify_tls(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["--ca-bundle", "/tmp/ca.pem"])

        with self.assertRaises(SystemExit) as exc:
            _validate_args(parser, args)

        self.assertEqual(exc.exception.code, 2)

    def test_build_ssl_context_uses_unverified_context_when_disabled(self) -> None:
        with patch("cisco_collab_health.transport.tls.ssl._create_unverified_context") as create:
            build_ssl_context(TlsPolicy(verify=False))

        create.assert_called_once_with()

    def test_build_ssl_context_uses_ca_bundle_when_verification_enabled(self) -> None:
        with patch("cisco_collab_health.transport.tls.ssl.create_default_context") as create:
            build_ssl_context(TlsPolicy(verify=True, ca_bundle=Path("/tmp/ca.pem")))

        create.assert_called_once_with(cafile="/tmp/ca.pem")


if __name__ == "__main__":
    unittest.main()
