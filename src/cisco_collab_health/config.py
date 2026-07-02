"""Local configuration and credential profile handling."""

from __future__ import annotations

import getpass
import ipaddress
import json
import os
import socket
from collections.abc import Callable
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Protocol

APP_NAME = "cisco-collab-health"
KEYRING_SERVICE = APP_NAME


class CredentialStore(Protocol):
    """Minimal credential store interface used by the CLI profile layer."""

    def get_password(self, service_name: str, username: str) -> str | None:
        """Return a stored secret, if present."""

    def set_password(self, service_name: str, username: str, password: str) -> None:
        """Store a secret."""

    def delete_password(self, service_name: str, username: str) -> None:
        """Delete a secret."""


@dataclass(frozen=True)
class StoredProfile:
    """Non-secret profile data persisted between runs."""

    name: str
    publisher_input: str
    publisher_ip: str
    gui_username: str
    os_username: str


@dataclass(frozen=True)
class RuntimeProfile:
    """Profile data plus runtime secrets needed by collectors."""

    stored: StoredProfile
    gui_password: str = field(repr=False)
    os_password: str = field(repr=False)
    warnings: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class ProfileSelection:
    """User-selected profile action."""

    profile_name: str
    reset: bool = False


def resolve_publisher(value: str) -> str:
    """Resolve a Publisher IP or FQDN to an IPv4 address string."""

    candidate = value.strip()
    if not candidate:
        raise ValueError("Publisher IP/FQDN cannot be empty.")

    try:
        return str(ipaddress.ip_address(candidate))
    except ValueError:
        pass

    try:
        results = socket.getaddrinfo(candidate, None, family=socket.AF_INET, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise ValueError(f"Unable to resolve Publisher FQDN '{candidate}'.") from exc

    if not results:
        raise ValueError(f"Unable to resolve Publisher FQDN '{candidate}'.")

    return str(results[0][4][0])


def default_config_dir() -> Path:
    """Return the platform-appropriate local config directory."""

    override = os.environ.get("CCHA_CONFIG_DIR")
    if override:
        return Path(override).expanduser()

    if os.name == "nt":
        appdata = os.environ.get("APPDATA")
        if appdata:
            return Path(appdata) / APP_NAME

    xdg_config_home = os.environ.get("XDG_CONFIG_HOME")
    if xdg_config_home:
        return Path(xdg_config_home) / APP_NAME

    return Path.home() / ".config" / APP_NAME


def profile_config_path(config_dir: Path | None = None) -> Path:
    """Return the profile config file path."""

    return (config_dir or default_config_dir()) / "profiles.json"


def load_profiles(config_dir: Path | None = None) -> dict[str, StoredProfile]:
    """Load stored profiles from disk."""

    path = profile_config_path(config_dir)
    if not path.exists():
        return {}

    with path.open("r", encoding="utf-8") as handle:
        payload = json.load(handle)

    profiles = payload.get("profiles", {})
    return {
        name: StoredProfile(
            name=name,
            publisher_input=data["publisher_input"],
            publisher_ip=data["publisher_ip"],
            gui_username=data["gui_username"],
            os_username=data["os_username"],
        )
        for name, data in profiles.items()
    }


def load_profile_names(config_dir: Path | None = None) -> list[str]:
    """Load known profile names from local registry and fallback profiles."""

    path = profile_config_path(config_dir)
    if not path.exists():
        return []

    with path.open("r", encoding="utf-8") as handle:
        payload = json.load(handle)

    names = set(payload.get("profile_names", []))
    names.update(payload.get("profiles", {}).keys())
    return sorted(names)


def save_profile_names(profile_names: list[str], config_dir: Path | None = None) -> Path:
    """Persist the local profile-name registry without storing secrets."""

    path = profile_config_path(config_dir)
    payload: dict[str, object] = {}
    if path.exists():
        with path.open("r", encoding="utf-8") as handle:
            payload = json.load(handle)

    payload["profile_names"] = sorted(set(profile_names))
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2, sort_keys=True)
        handle.write("\n")
    try:
        path.chmod(0o600)
    except OSError:
        pass
    return path


def register_profile_name(profile_name: str, config_dir: Path | None = None) -> None:
    """Add a profile name to the local registry."""

    names = load_profile_names(config_dir)
    if profile_name not in names:
        names.append(profile_name)
        save_profile_names(names, config_dir)


def unregister_profile_name(profile_name: str, config_dir: Path | None = None) -> None:
    """Remove a profile name from the local registry."""

    save_profile_names([name for name in load_profile_names(config_dir) if name != profile_name], config_dir)


def save_profiles(profiles: dict[str, StoredProfile], config_dir: Path | None = None) -> Path:
    """Persist non-secret profiles to disk."""

    path = profile_config_path(config_dir)
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "profile_names": sorted(set(load_profile_names(config_dir)) | set(profiles)),
        "profiles": {
            name: {
                key: value
                for key, value in asdict(profile).items()
                if key != "name"
            }
            for name, profile in sorted(profiles.items())
        }
    }
    with path.open("w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2, sort_keys=True)
        handle.write("\n")
    try:
        path.chmod(0o600)
    except OSError:
        pass
    return path


def load_keyring() -> CredentialStore | None:
    """Load the optional keyring backend."""

    try:
        import keyring
    except ImportError:
        return None

    return keyring


def credential_key(profile_name: str, credential_name: str) -> str:
    """Return the keyring username used for a stored credential."""

    return f"{profile_name}:{credential_name}"


def profile_secret_key(profile_name: str) -> str:
    """Return the keyring username used for an encrypted profile payload."""

    return credential_key(profile_name, "profile")


def delete_profile_credentials(profile_name: str, store: CredentialStore | None) -> None:
    """Best-effort deletion of stored profile credentials."""

    if store is None:
        return

    for credential_name in ("profile", "gui_password", "os_password"):
        try:
            store.delete_password(KEYRING_SERVICE, credential_key(profile_name, credential_name))
        except Exception:
            pass


def prompt_for_profile_name(
    existing_names: list[str],
    input_func: Callable[[str], str] = input,
    output_func: Callable[[str], None] = print,
) -> ProfileSelection:
    """Prompt the user to select an existing profile or create a new one."""

    if not existing_names:
        output_func("No saved profiles found. Create a new connection profile.")
        return ProfileSelection(_prompt_new_profile_name(existing_names, input_func, output_func))

    output_func("Saved profiles:")
    for index, name in enumerate(existing_names, start=1):
        output_func(f"  {index}. {name}")

    while True:
        choice = input_func("Use profile number/name, or enter 'n' for new profile: ").strip()
        if choice.lower() in {"n", "new"}:
            return ProfileSelection(_prompt_new_profile_name(existing_names, input_func, output_func))
        if choice.isdigit():
            index = int(choice)
            if 1 <= index <= len(existing_names):
                return ProfileSelection(existing_names[index - 1])
        if choice in existing_names:
            return ProfileSelection(choice)
        output_func("Invalid profile selection.")


def _prompt_new_profile_name(
    existing_names: list[str],
    input_func: Callable[[str], str],
    output_func: Callable[[str], None],
) -> str:
    while True:
        profile_name = input_func("New profile name: ").strip()
        if not profile_name:
            output_func("Profile name cannot be empty.")
            continue
        if profile_name in existing_names:
            output_func("Profile Name In Use")
            continue
        return profile_name


def prompt_for_profile(
    profile_name: str,
    input_func: Callable[[str], str] = input,
    getpass_func: Callable[[str], str] = getpass.getpass,
) -> RuntimeProfile:
    """Prompt for profile values and return a runtime profile."""

    publisher_input = input_func("Publisher IP or FQDN: ").strip()
    publisher_ip = resolve_publisher(publisher_input)
    gui_username = input_func("CUCM GUI/API username: ").strip()
    gui_password = getpass_func("CUCM GUI/API password: ")
    os_username = input_func("CUCM OS/SSH username: ").strip()
    os_password = getpass_func("CUCM OS/SSH password: ")

    if not gui_username:
        raise ValueError("CUCM GUI/API username cannot be empty.")
    if not os_username:
        raise ValueError("CUCM OS/SSH username cannot be empty.")

    return RuntimeProfile(
        stored=StoredProfile(
            name=profile_name,
            publisher_input=publisher_input,
            publisher_ip=publisher_ip,
            gui_username=gui_username,
            os_username=os_username,
        ),
        gui_password=gui_password,
        os_password=os_password,
    )


def ensure_runtime_profile(
    profile_name: str,
    *,
    reset: bool = False,
    save_credentials: bool = True,
    config_dir: Path | None = None,
    input_func: Callable[[str], str] = input,
    getpass_func: Callable[[str], str] = getpass.getpass,
    credential_store: CredentialStore | None = None,
    use_system_keyring: bool = True,
) -> RuntimeProfile:
    """Load or create a runtime profile for API and CLI collectors."""

    profiles = load_profiles(config_dir)
    store = credential_store if credential_store is not None else None
    if store is None and use_system_keyring:
        store = load_keyring()

    if store is not None:
        if reset:
            delete_profile_credentials(profile_name, store)
            unregister_profile_name(profile_name, config_dir)

        runtime = _load_runtime_profile_from_store(profile_name, store)
        if runtime is not None:
            return runtime

        runtime = prompt_for_profile(profile_name, input_func, getpass_func)
        runtime = _store_or_warn(runtime, store, save_credentials)
        if save_credentials and not any("Unable to store encrypted profile" in warning for warning in runtime.warnings):
            register_profile_name(profile_name, config_dir)
        return runtime

    if reset and profile_name in profiles:
        profiles.pop(profile_name)
        save_profiles(profiles, config_dir)
        unregister_profile_name(profile_name, config_dir)

    stored = profiles.get(profile_name)
    if stored is None:
        runtime = prompt_for_profile(profile_name, input_func, getpass_func)
        profiles[profile_name] = runtime.stored
        save_profiles(profiles, config_dir)
        register_profile_name(profile_name, config_dir)
        return _store_or_warn(runtime, store, save_credentials)

    warnings: list[str] = []
    gui_password = _load_or_prompt_secret(
        store,
        profile_name,
        "gui_password",
        f"CUCM GUI/API password for {stored.gui_username}: ",
        getpass_func,
        warnings,
    )
    os_password = _load_or_prompt_secret(
        store,
        profile_name,
        "os_password",
        f"CUCM OS/SSH password for {stored.os_username}: ",
        getpass_func,
        warnings,
    )
    runtime = RuntimeProfile(
        stored=stored,
        gui_password=gui_password,
        os_password=os_password,
        warnings=warnings,
    )
    return _store_or_warn(runtime, store, save_credentials)


def select_or_create_runtime_profile(
    *,
    reset: bool = False,
    save_credentials: bool = True,
    config_dir: Path | None = None,
    input_func: Callable[[str], str] = input,
    getpass_func: Callable[[str], str] = getpass.getpass,
    output_func: Callable[[str], None] = print,
    credential_store: CredentialStore | None = None,
    use_system_keyring: bool = True,
) -> RuntimeProfile:
    """Select an existing profile or prompt for a new named profile."""

    selection = prompt_for_profile_name(load_profile_names(config_dir), input_func, output_func)
    return ensure_runtime_profile(
        selection.profile_name,
        reset=reset or selection.reset,
        save_credentials=save_credentials,
        config_dir=config_dir,
        input_func=input_func,
        getpass_func=getpass_func,
        credential_store=credential_store,
        use_system_keyring=use_system_keyring,
    )


def _load_runtime_profile_from_store(
    profile_name: str,
    store: CredentialStore,
) -> RuntimeProfile | None:
    try:
        payload = store.get_password(KEYRING_SERVICE, profile_secret_key(profile_name))
    except Exception:
        return None

    if not payload:
        return None

    data = json.loads(payload)
    return RuntimeProfile(
        stored=StoredProfile(
            name=profile_name,
            publisher_input=data["publisher_input"],
            publisher_ip=data["publisher_ip"],
            gui_username=data["gui_username"],
            os_username=data["os_username"],
        ),
        gui_password=data["gui_password"],
        os_password=data["os_password"],
    )


def _load_or_prompt_secret(
    store: CredentialStore | None,
    profile_name: str,
    credential_name: str,
    prompt: str,
    getpass_func: Callable[[str], str],
    warnings: list[str],
) -> str:
    if store is not None:
        try:
            stored_secret = store.get_password(KEYRING_SERVICE, credential_key(profile_name, credential_name))
            if stored_secret:
                return stored_secret
        except Exception as exc:
            warnings.append(f"Unable to read {credential_name} from keyring: {exc}")

    return getpass_func(prompt)


def _store_or_warn(
    runtime: RuntimeProfile,
    store: CredentialStore | None,
    save_credentials: bool,
) -> RuntimeProfile:
    warnings = list(runtime.warnings)
    if not save_credentials:
        warnings.append("Credential saving disabled; passwords will be requested again on future runs.")
        return RuntimeProfile(runtime.stored, runtime.gui_password, runtime.os_password, warnings)

    if store is None:
        warnings.append(
            "Python keyring is not available; only non-secret profile details were saved locally. "
            "Passwords will be requested again."
        )
        return RuntimeProfile(runtime.stored, runtime.gui_password, runtime.os_password, warnings)

    payload = {
        "publisher_input": runtime.stored.publisher_input,
        "publisher_ip": runtime.stored.publisher_ip,
        "gui_username": runtime.stored.gui_username,
        "gui_password": runtime.gui_password,
        "os_username": runtime.stored.os_username,
        "os_password": runtime.os_password,
    }
    try:
        store.set_password(
            KEYRING_SERVICE,
            profile_secret_key(runtime.stored.name),
            json.dumps(payload, sort_keys=True),
        )
    except Exception as exc:
        warnings.append(f"Unable to store encrypted profile in keyring: {exc}")

    return RuntimeProfile(runtime.stored, runtime.gui_password, runtime.os_password, warnings)
