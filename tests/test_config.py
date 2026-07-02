"""Tests for local profile and credential handling."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from cisco_collab_health.config import (
    KEYRING_SERVICE,
    ensure_runtime_profile,
    load_profile_names,
    load_profiles,
    profile_secret_key,
    register_profile_name,
    resolve_publisher,
    select_or_create_runtime_profile,
)


class FakeCredentialStore:
    def __init__(self) -> None:
        self.secrets: dict[tuple[str, str], str] = {}

    def get_password(self, service_name: str, username: str) -> str | None:
        return self.secrets.get((service_name, username))

    def set_password(self, service_name: str, username: str, password: str) -> None:
        self.secrets[(service_name, username)] = password

    def delete_password(self, service_name: str, username: str) -> None:
        self.secrets.pop((service_name, username), None)


class ConfigTests(unittest.TestCase):
    def test_ip_publisher_is_accepted_without_resolution(self) -> None:
        self.assertEqual(resolve_publisher("192.0.2.10"), "192.0.2.10")

    def test_profile_is_saved_to_credential_store_when_available(self) -> None:
        store = FakeCredentialStore()
        inputs = iter(["192.0.2.10", "admin", "osadmin"])
        passwords = iter(["gui-secret", "os-secret"])

        with tempfile.TemporaryDirectory() as tmpdir:
            runtime = ensure_runtime_profile(
                "lab",
                config_dir=Path(tmpdir),
                input_func=lambda prompt: next(inputs),
                getpass_func=lambda prompt: next(passwords),
                credential_store=store,
            )
            profiles = load_profiles(Path(tmpdir))

        self.assertEqual(runtime.stored.publisher_ip, "192.0.2.10")
        self.assertEqual(profiles, {})
        payload = store.get_password(KEYRING_SERVICE, profile_secret_key("lab"))
        self.assertIsNotNone(payload)
        self.assertIn('"gui_username": "admin"', payload)
        self.assertIn('"gui_password": "gui-secret"', payload)

    def test_saved_profile_reuses_stored_passwords(self) -> None:
        store = FakeCredentialStore()
        inputs = iter(["192.0.2.10", "admin", "osadmin"])
        passwords = iter(["gui-secret", "os-secret"])

        with tempfile.TemporaryDirectory() as tmpdir:
            config_dir = Path(tmpdir)
            ensure_runtime_profile(
                "lab",
                config_dir=config_dir,
                input_func=lambda prompt: next(inputs),
                getpass_func=lambda prompt: next(passwords),
                credential_store=store,
            )
            runtime = ensure_runtime_profile(
                "lab",
                config_dir=config_dir,
                input_func=lambda prompt: self.fail(f"unexpected input prompt: {prompt}"),
                getpass_func=lambda prompt: self.fail(f"unexpected password prompt: {prompt}"),
                credential_store=store,
            )

        self.assertEqual(runtime.gui_password, "gui-secret")
        self.assertEqual(runtime.os_password, "os-secret")

    def test_keyring_backed_profile_registers_profile_name(self) -> None:
        store = FakeCredentialStore()
        inputs = iter(["192.0.2.10", "admin", "osadmin"])
        passwords = iter(["gui-secret", "os-secret"])

        with tempfile.TemporaryDirectory() as tmpdir:
            config_dir = Path(tmpdir)
            ensure_runtime_profile(
                "lab",
                config_dir=config_dir,
                input_func=lambda prompt: next(inputs),
                getpass_func=lambda prompt: next(passwords),
                credential_store=store,
            )

            profile_names = load_profile_names(config_dir)

        self.assertEqual(profile_names, ["lab"])

    def test_select_or_create_prompts_for_new_profile_name_first(self) -> None:
        store = FakeCredentialStore()
        prompts: list[str] = []
        inputs = iter(["lab", "192.0.2.10", "admin", "osadmin"])
        passwords = iter(["gui-secret", "os-secret"])

        def input_func(prompt: str) -> str:
            prompts.append(prompt)
            return next(inputs)

        with tempfile.TemporaryDirectory() as tmpdir:
            runtime = select_or_create_runtime_profile(
                config_dir=Path(tmpdir),
                input_func=input_func,
                getpass_func=lambda prompt: next(passwords),
                output_func=lambda message: None,
                credential_store=store,
            )

        self.assertEqual(runtime.stored.name, "lab")
        self.assertEqual(prompts[0], "New profile name: ")
        self.assertEqual(prompts[1], "Publisher IP or FQDN: ")

    def test_select_or_create_can_use_existing_profile_by_number(self) -> None:
        store = FakeCredentialStore()
        inputs = iter(["y", "1"])

        with tempfile.TemporaryDirectory() as tmpdir:
            config_dir = Path(tmpdir)
            register_profile_name("lab", config_dir)
            ensure_runtime_profile(
                "lab",
                config_dir=config_dir,
                input_func=lambda prompt: "192.0.2.10" if "Publisher" in prompt else "admin",
                getpass_func=lambda prompt: "secret",
                credential_store=store,
            )
            runtime = select_or_create_runtime_profile(
                config_dir=config_dir,
                input_func=lambda prompt: next(inputs),
                getpass_func=lambda prompt: self.fail(f"unexpected password prompt: {prompt}"),
                output_func=lambda message: None,
                credential_store=store,
            )

        self.assertEqual(runtime.stored.name, "lab")
        self.assertEqual(runtime.stored.publisher_ip, "192.0.2.10")

    def test_new_profile_name_cannot_reuse_existing_name(self) -> None:
        store = FakeCredentialStore()
        messages: list[str] = []
        inputs = iter(["n", "lab", "prod", "192.0.2.10", "admin", "osadmin"])
        passwords = iter(["gui-secret", "os-secret"])

        with tempfile.TemporaryDirectory() as tmpdir:
            config_dir = Path(tmpdir)
            register_profile_name("lab", config_dir)
            runtime = select_or_create_runtime_profile(
                config_dir=config_dir,
                input_func=lambda prompt: next(inputs),
                getpass_func=lambda prompt: next(passwords),
                output_func=messages.append,
                credential_store=store,
            )

        self.assertEqual(runtime.stored.name, "prod")
        self.assertIn("Profile Name In Use", messages)

    def test_existing_profile_prompt_can_create_new_profile(self) -> None:
        store = FakeCredentialStore()
        inputs = iter(["n", "prod", "192.0.2.10", "admin", "osadmin"])
        passwords = iter(["gui-secret", "os-secret"])

        with tempfile.TemporaryDirectory() as tmpdir:
            config_dir = Path(tmpdir)
            register_profile_name("lab", config_dir)
            runtime = select_or_create_runtime_profile(
                config_dir=config_dir,
                input_func=lambda prompt: next(inputs),
                getpass_func=lambda prompt: next(passwords),
                output_func=lambda message: None,
                credential_store=store,
            )

        self.assertEqual(runtime.stored.name, "prod")

    def test_without_credential_store_only_non_secret_profile_is_saved(self) -> None:
        inputs = iter(["192.0.2.10", "admin", "osadmin"])
        passwords = iter(["gui-secret", "os-secret"])

        with tempfile.TemporaryDirectory() as tmpdir:
            config_dir = Path(tmpdir)
            runtime = ensure_runtime_profile(
                "lab",
                config_dir=config_dir,
                input_func=lambda prompt: next(inputs),
                getpass_func=lambda prompt: next(passwords),
                credential_store=None,
                use_system_keyring=False,
            )
            profiles = load_profiles(config_dir)

        self.assertEqual(profiles["lab"].publisher_ip, "192.0.2.10")
        self.assertIn("Passwords will be requested again", runtime.warnings[0])


if __name__ == "__main__":
    unittest.main()
