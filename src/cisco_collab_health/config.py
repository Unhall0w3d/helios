"""Local configuration and credential profile handling."""

from __future__ import annotations

import getpass
import ipaddress
import json
import os
import socket
from collections.abc import Callable
from dataclasses import asdict, dataclass, field, replace
from pathlib import Path
from typing import Protocol, cast

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
    technology: str = "cucm"


@dataclass(frozen=True)
class RuntimeProfile:
    """Profile data plus runtime secrets needed by collectors."""

    stored: StoredProfile
    gui_password: str = field(repr=False)
    os_password: str = field(repr=False)
    technology: str = "cucm"
    warnings: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class ProfileSelection:
    """User-selected profile action."""

    profile_name: str
    reset: bool = False


SUPPORTED_TECHNOLOGIES = frozenset({"cucm", "cuc", "cer", "imp"})
ASSESSABLE_TECHNOLOGIES = frozenset({"cucm", "cuc"})
TECHNOLOGY_LABELS = {
    "cucm": "Cisco Unified Communications Manager",
    "cuc": "Cisco Unity Connection",
    "cer": "Cisco Emergency Responder",
    "imp": "Cisco IM and Presence",
}


def technology_label(technology: str) -> str:
    """Return the user-facing label for a supported technology."""

    return TECHNOLOGY_LABELS.get(technology, technology.upper())


@dataclass(frozen=True)
class AssessmentTarget:
    """One technology-specific connection profile in a combined assessment."""

    target_id: str
    technology: str
    connection_profile: str

    def __post_init__(self) -> None:
        if not self.target_id.strip():
            raise ValueError("Assessment target ID cannot be empty.")
        if self.technology not in SUPPORTED_TECHNOLOGIES:
            raise ValueError(f"Unsupported assessment technology: {self.technology}")
        if not self.connection_profile.strip():
            raise ValueError("Assessment target connection profile cannot be empty.")


@dataclass(frozen=True)
class AssessmentProfile:
    """Named group of independently credentialed technology targets."""

    name: str
    targets: tuple[AssessmentTarget, ...]

    def __post_init__(self) -> None:
        if not self.name.strip():
            raise ValueError("Assessment profile name cannot be empty.")
        if not self.targets:
            raise ValueError("Assessment profile must contain at least one target.")
        ids = [target.target_id.lower() for target in self.targets]
        if len(ids) != len(set(ids)):
            raise ValueError("Assessment target IDs must be unique within a profile.")


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
        results = socket.getaddrinfo(
            candidate,
            None,
            family=socket.AF_INET,
            type=socket.SOCK_STREAM,
        )
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
            os_username=data.get("os_username", ""),
            technology=data.get("technology", "cucm"),
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


def load_profile_names_for_technology(
    technology: str,
    config_dir: Path | None = None,
) -> list[str]:
    """Return profiles owned by one technology; legacy profiles are CUCM."""

    path = profile_config_path(config_dir)
    if not path.exists():
        return []
    with path.open("r", encoding="utf-8") as handle:
        payload = json.load(handle)
    ownership = payload.get("profile_technologies", {})
    return [
        name
        for name in load_profile_names(config_dir)
        if technology
        in (
            ownership.get(name, "cucm")
            if isinstance(ownership.get(name, "cucm"), list)
            else [ownership.get(name, "cucm")]
        )
    ]


def load_assessment_profiles(config_dir: Path | None = None) -> dict[str, AssessmentProfile]:
    """Load multi-technology assessment groups without resolving credentials."""

    path = profile_config_path(config_dir)
    if not path.exists():
        return {}
    with path.open("r", encoding="utf-8") as handle:
        payload = json.load(handle)
    profiles = {}
    for name, data in payload.get("assessment_profiles", {}).items():
        profiles[name] = AssessmentProfile(
            name=name,
            targets=tuple(
                AssessmentTarget(
                    target_id=target["target_id"],
                    technology=target["technology"],
                    connection_profile=target["connection_profile"],
                )
                for target in data.get("targets", [])
            ),
        )
    return profiles


def save_assessment_profiles(
    profiles: dict[str, AssessmentProfile],
    config_dir: Path | None = None,
) -> Path:
    """Persist assessment composition while leaving all secrets in target profiles."""

    path = profile_config_path(config_dir)
    payload: dict[str, object] = {}
    if path.exists():
        with path.open("r", encoding="utf-8") as handle:
            payload = json.load(handle)
    payload["assessment_profiles"] = {
        name: {
            "targets": [asdict(target) for target in profile.targets],
        }
        for name, profile in sorted(profiles.items())
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2, sort_keys=True)
        handle.write("\n")
    try:
        path.chmod(0o600)
    except OSError:
        pass
    return path


def delete_assessment_profile(name: str, config_dir: Path | None = None) -> bool:
    """Remove one saved assessment set without affecting connection profiles."""

    path = profile_config_path(config_dir)
    if not path.exists():
        return False
    with path.open("r", encoding="utf-8") as handle:
        payload = json.load(handle)
    assessments = payload.get("assessment_profiles")
    if not isinstance(assessments, dict) or name not in assessments:
        return False
    assessments.pop(name)
    with path.open("w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2, sort_keys=True)
        handle.write("\n")
    return True


def resolve_assessment_targets(
    assessment: AssessmentProfile,
    *,
    reset: bool = False,
    save_credentials: bool = True,
    config_dir: Path | None = None,
    input_func: Callable[[str], str] = input,
    getpass_func: Callable[[str], str] = getpass.getpass,
    credential_store: CredentialStore | None = None,
    use_system_keyring: bool = True,
) -> list[tuple[AssessmentTarget, RuntimeProfile]]:
    """Resolve each target independently, prompting only for its missing credentials."""

    unsupported = sorted(
        {target.technology for target in assessment.targets} - ASSESSABLE_TECHNOLOGIES
    )
    if unsupported:
        raise ValueError(
            "Assessment collectors are not available for: "
            + ", ".join(technology_label(technology) for technology in unsupported)
            + ". You can save and manage these connection profiles, but cannot assess them yet."
        )

    return [
        (
            target,
            ensure_runtime_profile(
                target.connection_profile,
                reset=reset,
                save_credentials=save_credentials,
                technology=target.technology,
                config_dir=config_dir,
                input_func=input_func,
                getpass_func=getpass_func,
                credential_store=credential_store,
                use_system_keyring=use_system_keyring,
            ),
        )
        for target in assessment.targets
    ]


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


def register_profile_name(
    profile_name: str,
    config_dir: Path | None = None,
    technology: str = "cucm",
) -> None:
    """Add a profile name to the local registry."""

    names = load_profile_names(config_dir)
    if profile_name not in names:
        names.append(profile_name)
        save_profile_names(names, config_dir)
    path = profile_config_path(config_dir)
    with path.open("r", encoding="utf-8") as handle:
        payload = json.load(handle)
    ownership = payload.setdefault("profile_technologies", {})
    if isinstance(ownership, dict):
        current = ownership.get(profile_name, [])
        values = current if isinstance(current, list) else [current]
        ownership[profile_name] = sorted(set(values + [technology]))
    with path.open("w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2, sort_keys=True)
        handle.write("\n")


def unregister_profile_name(profile_name: str, config_dir: Path | None = None) -> None:
    """Remove a profile name and its ownership metadata from the registry."""

    path = profile_config_path(config_dir)
    if not path.exists():
        return
    with path.open("r", encoding="utf-8") as handle:
        payload = json.load(handle)

    payload["profile_names"] = [
        name for name in payload.get("profile_names", []) if name != profile_name
    ]
    profiles = payload.get("profiles")
    if isinstance(profiles, dict):
        profiles.pop(profile_name, None)
    ownership = payload.get("profile_technologies")
    if isinstance(ownership, dict):
        ownership.pop(profile_name, None)

    with path.open("w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2, sort_keys=True)
        handle.write("\n")


def delete_connection_profile(
    profile_name: str,
    *,
    config_dir: Path | None = None,
    credential_store: CredentialStore | None = None,
    use_system_keyring: bool = True,
) -> list[str]:
    """Delete a connection profile and remove saved assessments that reference it."""

    store = credential_store
    if store is None and use_system_keyring:
        store = load_keyring()
    delete_profile_credentials(profile_name, store)

    removed_assessments: list[str] = []
    path = profile_config_path(config_dir)
    if path.exists():
        with path.open("r", encoding="utf-8") as handle:
            payload = json.load(handle)
        assessments = payload.get("assessment_profiles")
        if isinstance(assessments, dict):
            for name, assessment in list(assessments.items()):
                targets = assessment.get("targets", []) if isinstance(assessment, dict) else []
                if any(
                    isinstance(target, dict) and target.get("connection_profile") == profile_name
                    for target in targets
                ):
                    assessments.pop(name, None)
                    removed_assessments.append(name)
        with path.open("w", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=2, sort_keys=True)
            handle.write("\n")

    unregister_profile_name(profile_name, config_dir)
    return sorted(removed_assessments)


def load_connection_profile_details(
    profile_name: str,
    *,
    config_dir: Path | None = None,
    credential_store: CredentialStore | None = None,
    use_system_keyring: bool = True,
) -> dict[str, StoredProfile]:
    """Return non-secret details for every technology in a connection profile.

    Passwords deliberately remain in the credential store and are never returned.
    """

    details: dict[str, StoredProfile] = {}
    stored = load_profiles(config_dir).get(profile_name)
    if stored is not None:
        details[stored.technology] = stored

    store = credential_store if credential_store is not None else None
    if store is None and use_system_keyring:
        store = load_keyring()
    if store is None:
        return details
    try:
        raw_payload = store.get_password(KEYRING_SERVICE, profile_secret_key(profile_name))
        payload = json.loads(raw_payload) if raw_payload else {}
    except (Exception,):
        return details
    if not isinstance(payload, dict):
        return details

    sections = payload.get("technology_profiles")
    if not isinstance(sections, dict):
        sections = {"cucm": payload}
    for technology, data in sections.items():
        if technology not in SUPPORTED_TECHNOLOGIES or not isinstance(data, dict):
            continue
        required = ("publisher_input", "publisher_ip", "gui_username")
        if any(not str(data.get(field) or "").strip() for field in required):
            continue
        details[technology] = StoredProfile(
            name=profile_name,
            publisher_input=str(data["publisher_input"]),
            publisher_ip=str(data["publisher_ip"]),
            gui_username=str(data["gui_username"]),
            os_username=str(data.get("os_username") or ""),
            technology=technology,
        )
    return details


def edit_connection_profile(
    profile_name: str,
    *,
    technology: str = "cucm",
    save_credentials: bool = True,
    config_dir: Path | None = None,
    input_func: Callable[[str], str] = input,
    getpass_func: Callable[[str], str] = getpass.getpass,
    credential_store: CredentialStore | None = None,
    use_system_keyring: bool = True,
) -> RuntimeProfile:
    """Replace one technology's connection details, preserving other sections."""

    if technology not in SUPPORTED_TECHNOLOGIES:
        raise ValueError(f"Unsupported profile technology: {technology}")
    runtime = prompt_for_profile(profile_name, technology, input_func, getpass_func)
    store = credential_store if credential_store is not None else None
    if store is None and use_system_keyring:
        store = load_keyring()
    if store is not None:
        runtime = _store_or_warn(runtime, store, save_credentials)
        if save_credentials and not any(
            "Unable to store encrypted profile" in warning for warning in runtime.warnings
        ):
            register_profile_name(profile_name, config_dir, technology)
        return runtime

    profiles = load_profiles(config_dir)
    profiles[profile_name] = runtime.stored
    save_profiles(profiles, config_dir)
    register_profile_name(profile_name, config_dir, technology)
    return _store_or_warn(runtime, None, save_credentials)


def save_profiles(profiles: dict[str, StoredProfile], config_dir: Path | None = None) -> Path:
    """Persist non-secret profiles to disk."""

    path = profile_config_path(config_dir)
    path.parent.mkdir(parents=True, exist_ok=True)
    payload: dict[str, object] = {}
    if path.exists():
        with path.open("r", encoding="utf-8") as handle:
            loaded = json.load(handle)
        if isinstance(loaded, dict):
            payload = loaded
    payload["profile_names"] = sorted(set(load_profile_names(config_dir)) | set(profiles))
    payload["profiles"] = {
        name: {key: value for key, value in asdict(profile).items() if key != "name"}
        for name, profile in sorted(profiles.items())
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

    return cast(CredentialStore, keyring)


def credential_key(profile_name: str, credential_name: str) -> str:
    """Return the keyring username used for a stored credential."""

    return f"{profile_name}:{credential_name}"


def profile_secret_key(profile_name: str) -> str:
    """Return the keyring username used for an encrypted profile payload."""

    return credential_key(profile_name, "profile")


def node_platform_password_key(profile_name: str, technology: str) -> str:
    """Return the keyring username for node-specific platform credentials."""

    return credential_key(profile_name, f"{technology}:node_platform_passwords")


def normalize_node_address(node: str) -> str:
    """Normalize a server address used as a per-node credential key."""

    return node.strip().rstrip(".").casefold()


def load_node_platform_passwords(
    profile_name: str, technology: str, store: CredentialStore | None = None
) -> dict[str, str]:
    """Load encrypted per-node platform passwords for the active technology profile."""

    credential_store = store if store is not None else load_keyring()
    if credential_store is None:
        return {}
    try:
        payload = credential_store.get_password(
            KEYRING_SERVICE, node_platform_password_key(profile_name, technology)
        )
        parsed = json.loads(payload) if payload else {}
    except Exception:
        return {}
    if not isinstance(parsed, dict):
        return {}
    return {
        normalize_node_address(str(node)): str(password)
        for node, password in parsed.items()
        if isinstance(node, str) and isinstance(password, str) and password
    }


def save_node_platform_passwords(
    profile_name: str,
    technology: str,
    passwords: dict[str, str],
    store: CredentialStore | None = None,
) -> str | None:
    """Persist verified node-specific platform passwords in the OS credential store."""

    credential_store = store if store is not None else load_keyring()
    if credential_store is None:
        return "Python keyring is unavailable; node-specific platform passwords were not saved."
    payload = {
        normalize_node_address(node): password
        for node, password in passwords.items()
        if password
    }
    try:
        credential_store.set_password(
            KEYRING_SERVICE,
            node_platform_password_key(profile_name, technology),
            json.dumps(payload, sort_keys=True),
        )
    except Exception as exc:
        return f"Unable to save node-specific platform passwords: {exc}"
    return None


def delete_profile_credentials(profile_name: str, store: CredentialStore | None) -> None:
    """Best-effort deletion of stored profile credentials."""

    if store is None:
        return

    credential_names = ["profile", "gui_password", "os_password"]
    credential_names.extend(
        f"{technology}:node_platform_passwords"
        for technology in SUPPORTED_TECHNOLOGIES
    )
    for credential_name in credential_names:
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

    while True:
        choice = (
            input_func("Existing profile found. Load existing profile? (Y/N): ").strip().lower()
        )
        if choice == "n":
            return ProfileSelection(
                _prompt_new_profile_name(existing_names, input_func, output_func)
            )
        if choice == "y":
            return ProfileSelection(
                _prompt_existing_profile_name(existing_names, input_func, output_func)
            )
        output_func("Enter Y to load an existing profile or N to create a new profile.")


def _prompt_existing_profile_name(
    existing_names: list[str],
    input_func: Callable[[str], str],
    output_func: Callable[[str], None],
) -> str:
    output_func("Saved profiles:")
    for index, name in enumerate(existing_names, start=1):
        output_func(f"  {index}. {name}")

    while True:
        choice = input_func("Profile number/name: ").strip()
        if choice.isdigit():
            index = int(choice)
            if 1 <= index <= len(existing_names):
                return existing_names[index - 1]
        if choice in existing_names:
            return choice
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
    technology: str = "cucm",
    input_func: Callable[[str], str] = input,
    getpass_func: Callable[[str], str] = getpass.getpass,
) -> RuntimeProfile:
    """Prompt for profile values and return a runtime profile."""

    label = technology_label(technology)
    publisher_prompt = f"{label} Publisher IP or FQDN: "
    publisher_input = input_func(publisher_prompt).strip()
    publisher_ip = resolve_publisher(publisher_input)
    gui_username = input_func(f"{label} GUI/API username: ").strip()
    gui_password = getpass_func(f"{label} GUI/API password: ")
    os_username = input_func(f"{label} Platform/CLI username: ").strip()
    os_password = getpass_func(f"{label} Platform/CLI password: ")

    if not gui_username:
        raise ValueError(f"{label} GUI/API username cannot be empty.")
    if not os_username:
        raise ValueError(f"{label} Platform/CLI username cannot be empty.")

    return RuntimeProfile(
        stored=StoredProfile(
            name=profile_name,
            publisher_input=publisher_input,
            publisher_ip=publisher_ip,
            gui_username=gui_username,
            os_username=os_username,
            technology=technology,
        ),
        gui_password=gui_password,
        os_password=os_password,
        technology=technology,
    )


def ensure_runtime_profile(
    profile_name: str,
    *,
    reset: bool = False,
    technology: str = "cucm",
    reset_technology: bool = False,
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
        if reset_technology:
            _reset_encrypted_technology_profile(profile_name, technology, store)
        if reset:
            delete_profile_credentials(profile_name, store)
            unregister_profile_name(profile_name, config_dir)

        runtime = _load_runtime_profile_from_store(
            profile_name,
            store,
            technology=technology,
            input_func=input_func,
            getpass_func=getpass_func,
        )
        if runtime is not None:
            return _store_or_warn(runtime, store, save_credentials)

        runtime = prompt_for_profile(profile_name, technology, input_func, getpass_func)
        runtime = _store_or_warn(runtime, store, save_credentials)
        if save_credentials and not any(
            "Unable to store encrypted profile" in warning for warning in runtime.warnings
        ):
            register_profile_name(profile_name, config_dir, technology)
        return runtime

    if reset and profile_name in profiles:
        profiles.pop(profile_name)
        save_profiles(profiles, config_dir)
        unregister_profile_name(profile_name, config_dir)

    stored = profiles.get(profile_name)
    if stored is None:
        runtime = prompt_for_profile(profile_name, technology, input_func, getpass_func)
        profiles[profile_name] = runtime.stored
        save_profiles(profiles, config_dir)
        register_profile_name(profile_name, config_dir, technology)
        return _store_or_warn(runtime, store, save_credentials)

    warnings: list[str] = []
    if not stored.os_username:
        os_username = input_func("CUCM Platform/CLI username: ").strip()
        if not os_username:
            raise ValueError("CUCM Platform/CLI username cannot be empty.")
        stored = replace(stored, os_username=os_username)
        profiles[profile_name] = stored
        save_profiles(profiles, config_dir)
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
        f"CUCM Platform/CLI password for {stored.os_username}: ",
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


def _reset_encrypted_technology_profile(
    profile_name: str,
    technology: str,
    store: CredentialStore,
) -> None:
    """Remove one technology section while preserving other technology credentials."""

    key = profile_secret_key(profile_name)
    try:
        payload_text = store.get_password(KEYRING_SERVICE, key)
        if not payload_text:
            return
        payload = json.loads(payload_text)
        sections = payload.get("technology_profiles")
        if isinstance(sections, dict):
            sections.pop(technology, None)
            store.set_password(KEYRING_SERVICE, key, json.dumps(payload, sort_keys=True))
    except (Exception,):
        return


def select_or_create_runtime_profile(
    *,
    technology: str = "cucm",
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
        technology=technology,
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
    *,
    technology: str = "cucm",
    input_func: Callable[[str], str],
    getpass_func: Callable[[str], str],
) -> RuntimeProfile | None:
    try:
        payload = store.get_password(KEYRING_SERVICE, profile_secret_key(profile_name))
    except Exception:
        return None

    if not payload:
        return None

    try:
        data = json.loads(payload)
    except (json.JSONDecodeError, TypeError):
        return None
    if not isinstance(data, dict):
        return None

    technology_profiles = data.get("technology_profiles", {})
    profile_data = (
        technology_profiles.get(technology) if isinstance(technology_profiles, dict) else None
    )
    if profile_data is None:
        # Legacy top-level fields are CUCM only. Never reinterpret them as CUC.
        if technology != "cucm":
            return None
        profile_data = data
    if not isinstance(profile_data, dict):
        return None

    required = ("publisher_input", "publisher_ip", "gui_username", "gui_password")
    if any(not str(profile_data.get(field) or "").strip() for field in required):
        return None

    platform_credentials_configured = profile_data.get("platform_credentials_configured") is True
    os_username = str(profile_data.get("os_username") or "").strip()
    os_password = str(profile_data.get("os_password") or "")
    warnings = []
    if not platform_credentials_configured:
        label = "CUCM" if technology == "cucm" else "Unity Connection"
        os_username = input_func(
            f"{label} Platform/CLI username (required for certificate and CLI collection): "
        ).strip()
        if not os_username:
            raise ValueError("CUCM Platform/CLI username cannot be empty.")
        os_password = getpass_func(f"CUCM Platform/CLI password for {os_username}: ")
        warnings.append("Platform/CLI credentials were added to the encrypted profile.")
    return RuntimeProfile(
        stored=StoredProfile(
            name=profile_name,
            publisher_input=str(profile_data["publisher_input"]),
            publisher_ip=str(profile_data["publisher_ip"]),
            gui_username=str(profile_data["gui_username"]),
            os_username=os_username,
            technology=technology,
        ),
        gui_password=str(profile_data["gui_password"]),
        os_password=os_password,
        technology=technology,
        warnings=list(dict.fromkeys(warnings)),
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
            stored_secret = store.get_password(
                KEYRING_SERVICE,
                credential_key(profile_name, credential_name),
            )
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
        warnings.append(
            "Credential saving disabled; passwords will be requested again on future runs."
        )
        return RuntimeProfile(
            runtime.stored,
            runtime.gui_password,
            runtime.os_password,
            runtime.technology,
            warnings,
        )

    if store is None:
        warnings.append(
            "Python keyring is not available; only non-secret profile details were saved locally. "
            "Passwords will be requested again."
        )
        return RuntimeProfile(
            runtime.stored,
            runtime.gui_password,
            runtime.os_password,
            runtime.technology,
            warnings,
        )

    section = {
        "publisher_input": runtime.stored.publisher_input,
        "publisher_ip": runtime.stored.publisher_ip,
        "gui_username": runtime.stored.gui_username,
        "gui_password": runtime.gui_password,
        "os_username": runtime.stored.os_username,
        "os_password": runtime.os_password,
        "platform_credentials_configured": True,
    }
    try:
        existing_payload: dict[str, object] = {}
        profile_key = profile_secret_key(runtime.stored.name)
        existing = store.get_password(KEYRING_SERVICE, profile_key)
        if existing:
            try:
                existing_payload = json.loads(existing)
            except json.JSONDecodeError:
                existing_payload = {}
        technology_profiles = existing_payload.setdefault("technology_profiles", {})
        if isinstance(technology_profiles, dict):
            technology_profiles[runtime.technology] = section
        if runtime.technology == "cucm":
            existing_payload.update(section)
        store.set_password(
            KEYRING_SERVICE,
            profile_key,
            json.dumps(existing_payload, sort_keys=True),
        )
    except Exception as exc:
        warnings.append(f"Unable to store encrypted profile in keyring: {exc}")

    return RuntimeProfile(
        runtime.stored,
        runtime.gui_password,
        runtime.os_password,
        runtime.technology,
        warnings,
    )


def update_runtime_gui_credentials(
    runtime: RuntimeProfile,
    username: str,
    password: str,
    store: CredentialStore | None,
) -> RuntimeProfile:
    """Persist credentials re-entered after an authenticated API failure."""

    updated = replace(
        runtime,
        stored=replace(runtime.stored, gui_username=username),
        gui_password=password,
    )
    return _store_or_warn(updated, store, True)
