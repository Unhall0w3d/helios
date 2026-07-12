"""Interactive guided assessment workflow."""

from __future__ import annotations

import argparse
from collections.abc import Callable

from cisco_collab_health.config import (
    AssessmentProfile,
    AssessmentTarget,
    RuntimeProfile,
    delete_connection_profile,
    edit_connection_profile,
    ensure_runtime_profile,
    load_connection_profile_details,
    load_assessment_profiles,
    load_profile_names_for_technology,
    load_profile_names,
    resolve_assessment_targets,
    save_assessment_profiles,
)
from cisco_collab_health.status import StatusPrinter

RunAssessment = Callable[[argparse.Namespace, StatusPrinter, RuntimeProfile | None], int]
RunMultiAssessment = Callable[
    [argparse.Namespace, StatusPrinter, str, list[tuple[AssessmentTarget, RuntimeProfile]]], int
]


def run_menu(
    args: argparse.Namespace,
    status: StatusPrinter,
    run_assessment: RunAssessment,
    run_multi_assessment: RunMultiAssessment,
) -> int:
    """Run the primary guided workflow while retaining development options."""

    while True:
        print("\nAletheiaUC Main Menu\n====================")
        print("1. Guided assessment (select technologies and profiles)")
        print("2. Run saved multi-technology assessment")
        print("3. Run single connection profile")
        print("M. Manage connection profiles")
        print("T. Test/framework options")
        print("Q. Quit\n")
        choice = input("Selection: ").strip().lower()
        if choice in {"1", "g"}:
            result = _guided_assessment(args, status, run_multi_assessment)
        elif choice in {"2", "a"}:
            result = _saved_assessment(args, status, run_multi_assessment)
        elif choice in {"3", "p", "l"}:
            result = _single_profile(args, status, run_assessment)
        elif choice == "m":
            _manage_profiles(status)
            continue
        elif choice == "t":
            result = _test_options(args, status, run_assessment)
        elif choice == "q":
            status.info("Exiting AletheiaUC")
            return 0
        else:
            status.warn("Invalid selection")
            continue
        if result is not None:
            return result


def _guided_assessment(
    args: argparse.Namespace,
    status: StatusPrinter,
    run_multi: RunMultiAssessment,
) -> int | None:
    assessments = load_assessment_profiles()
    name = input("Assessment name (for example District): ").strip()
    if not name:
        status.warn("Assessment name cannot be empty")
        return None
    targets = []
    for technology, label, default_id in (
        ("cucm", "Cisco Unified Communications Manager", "call-control"),
        ("cuc", "Cisco Unity Connection", "voicemail"),
    ):
        if not _yes_no(f"Include {label}?", default=technology == "cucm"):
            continue
        profile_name = _select_connection_profile(technology, label, status)
        if profile_name is None:
            return None
        targets.append(AssessmentTarget(default_id, technology, profile_name))
    if not targets:
        status.warn("Select at least one technology")
        return None
    assessment = AssessmentProfile(name, tuple(targets))
    assessments[name] = assessment
    save_assessment_profiles(assessments)
    status.ok(f"Assessment profile saved: {name}")
    run_args = _prompt_run_mode(args)
    if run_args is None:
        return None
    resolved = resolve_assessment_targets(
        assessment,
        save_credentials=not run_args.no_save_credentials,
    )
    return run_multi(run_args, status, name, resolved)


def _saved_assessment(
    args: argparse.Namespace,
    status: StatusPrinter,
    run_multi: RunMultiAssessment,
) -> int | None:
    assessments = load_assessment_profiles()
    if not assessments:
        status.warn("No saved assessments found. Starting guided setup.")
        return _guided_assessment(args, status, run_multi)
    names = sorted(assessments)
    selected = _choose_name("Saved Assessments", names, status)
    if selected is None:
        return None
    assessment = assessments[selected]
    print("Targets:")
    for target in assessment.targets:
        print(
            f"  - {target.target_id}: {target.technology.upper()} using {target.connection_profile}"
        )
    run_args = _prompt_run_mode(args)
    if run_args is None:
        return None
    resolved = resolve_assessment_targets(
        assessment,
        save_credentials=not run_args.no_save_credentials,
    )
    return run_multi(run_args, status, assessment.name, resolved)


def _single_profile(
    args: argparse.Namespace,
    status: StatusPrinter,
    run_assessment: RunAssessment,
) -> int | None:
    technology = _choose_technology(status)
    if technology is None:
        return None
    label = "CUCM" if technology == "cucm" else "Unity Connection"
    profile_name = _select_connection_profile(technology, label, status)
    if profile_name is None:
        return None
    run_args = _prompt_run_mode(args)
    if run_args is None:
        return None
    run_args.product = technology
    runtime = ensure_runtime_profile(
        profile_name,
        technology=technology,
        save_credentials=not run_args.no_save_credentials,
    )
    return run_assessment(run_args, status, runtime)


def _select_connection_profile(
    technology: str,
    label: str,
    status: StatusPrinter,
) -> str | None:
    names = sorted(set(load_profile_names_for_technology(technology)))
    print(f"\n{label} connection profile")
    if names:
        for index, name in enumerate(names, start=1):
            print(f"{index}. {name}")
        print("N. Create a new profile")
        print("R. Return")
        while True:
            choice = input("Profile number/name: ").strip()
            if choice.lower() == "r":
                return None
            if choice.lower() == "n":
                break
            if choice.isdigit() and 1 <= int(choice) <= len(names):
                return names[int(choice) - 1]
            if choice in names:
                return choice
            status.warn("Invalid profile selection")
    profile_name = _prompt_new_profile_name(names, status)
    ensure_runtime_profile(profile_name, technology=technology)
    return profile_name


def _manage_profiles(status: StatusPrinter) -> None:
    """View, edit, or delete saved connection profiles."""

    names = load_profile_names()
    if not names:
        status.info("No saved connection profiles")
        return None
    selected = _choose_name("Connection Profiles", names, status)
    if selected is None:
        return None
    while True:
        print(f"\nProfile: {selected}")
        print(
            "V. View non-secret details\nE. Edit connection details\nD. Delete profile\nR. Return"
        )
        choice = input("Selection: ").strip().lower()
        if choice == "v":
            _show_profile_details(selected, status)
        elif choice == "e":
            _edit_profile(selected, status)
        elif choice == "d":
            confirmation = input(f"Type DELETE to permanently remove '{selected}': ").strip()
            if confirmation != "DELETE":
                status.info("Profile deletion cancelled")
                continue
            removed = delete_connection_profile(selected)
            status.ok(f"Deleted connection profile: {selected}")
            if removed:
                status.warn(
                    "Removed saved assessments that referenced the deleted profile: "
                    + ", ".join(removed)
                )
            return None
        elif choice == "r":
            return None
        else:
            status.warn("Invalid selection")


def _show_profile_details(profile_name: str, status: StatusPrinter) -> None:
    details = load_connection_profile_details(profile_name)
    if not details:
        status.warn("No readable connection details found; credentials may be unavailable.")
        return
    print("\nNon-secret connection details")
    for technology, profile in sorted(details.items()):
        label = "CUCM" if technology == "cucm" else "Unity Connection"
        print(
            f"{label}:\n  Address: {profile.publisher_input}\n  Resolved IP: {profile.publisher_ip}"
        )
        print(
            f"  GUI/API username: {profile.gui_username}\n  Platform/CLI username: {profile.os_username or '(not set)'}"
        )


def _edit_profile(profile_name: str, status: StatusPrinter) -> None:
    technology = _choose_technology(status)
    if technology is None:
        return
    status.info(
        "Enter replacement address, usernames, and passwords. Other technology sections are preserved."
    )
    runtime = edit_connection_profile(profile_name, technology=technology)
    status.ok(f"Updated {technology.upper()} connection details for {profile_name}")
    for warning in runtime.warnings:
        status.warn(warning)
    return None


def _prompt_run_mode(args: argparse.Namespace) -> argparse.Namespace | None:
    run_args = argparse.Namespace(**vars(args))
    while True:
        print("\nRun Options\n===========")
        print("1. Output and reports")
        print("2. Artifacts and logs")
        print("3. Collection and diagnostics")
        print("4. Network and TLS")
        print("S. Start assessment\nR. Return")
        choice = input("Selection: ").strip().lower()
        if choice == "1":
            _configure_output(run_args)
        elif choice == "2":
            _configure_storage(run_args)
        elif choice == "3":
            _configure_collection(run_args)
        elif choice == "4":
            _configure_network(run_args)
        elif choice in {"", "s"}:
            # Keep the guided workflow's established one-key default: a
            # diagnostic capture with a review bundle. Explicit settings in
            # the submenus always take precedence.
            if not choice:
                run_args.diagnostic_capture = True
                run_args.export_review_zip = True
                run_args.no_logs = False
                run_args.no_artifacts = False
            if run_args.export_review_zip and run_args.no_logs:
                status_message = "Review ZIP requires troubleshooting logs; logs have been enabled."
                print(f"[INFO] {status_message}")
                run_args.no_logs = False
            return run_args
        elif choice == "r":
            return None
        else:
            print("Invalid selection")


def _configure_output(args: argparse.Namespace) -> None:
    args.format = _choose_value("Terminal format", {"1": "summary", "2": "json"}, args.format)
    args.no_html_report = not _yes_no("Write HTML report?", default=not args.no_html_report)
    if not args.no_html_report:
        args.html_report = _optional_value("HTML report path", args.html_report)
        args.customer_safe_report = _yes_no(
            "Mask identifiers in HTML report?", default=args.customer_safe_report
        )


def _configure_storage(args: argparse.Namespace) -> None:
    args.no_artifacts = not _yes_no("Write local artifacts?", default=not args.no_artifacts)
    if not args.no_artifacts:
        args.artifact_dir = _required_value("Artifact directory", args.artifact_dir)
        args.artifact_redaction = _choose_value(
            "Artifact redaction", {"1": "secrets", "2": "none"}, args.artifact_redaction
        )
    args.no_logs = not _yes_no("Write troubleshooting logs?", default=not args.no_logs)
    if not args.no_logs:
        args.log_dir = _required_value("Log directory", args.log_dir)
    args.export_review_zip = _yes_no(
        "Export review ZIP to Downloads?", default=args.export_review_zip
    )


def _configure_collection(args: argparse.Namespace) -> None:
    args.no_save_credentials = not _yes_no(
        "Save prompted passwords in the OS credential store?", default=not args.no_save_credentials
    )
    args.collect_phone_inventory = _yes_no(
        "Collect phone inventory?", default=args.collect_phone_inventory
    )
    if args.collect_phone_inventory:
        args.phone_inventory_page_size = _positive_integer(
            "Phone inventory page size", args.phone_inventory_page_size
        )
        args.phone_inventory_max_devices = _positive_integer(
            "Phone inventory maximum devices", args.phone_inventory_max_devices
        )
    args.diagnostic_capture = _yes_no(
        "Capture diagnostic API evidence?", default=args.diagnostic_capture
    )
    if args.diagnostic_capture:
        args.diagnostic_max_devices = _bounded_integer(
            "Diagnostic maximum devices", args.diagnostic_max_devices, 1, 2000
        )
        args.diagnostic_axl_page_size = _positive_integer(
            "Diagnostic AXL page size", args.diagnostic_axl_page_size
        )
        args.diagnostic_axl_max_records = _positive_integer(
            "Diagnostic AXL maximum records", args.diagnostic_axl_max_records
        )


def _configure_network(args: argparse.Namespace) -> None:
    args.axl_port = _positive_integer("AXL HTTPS port", args.axl_port)
    args.risport_port = _positive_integer("RISPort HTTPS port", args.risport_port)
    args.control_center_port = _positive_integer(
        "Control Center HTTPS port", args.control_center_port
    )
    args.perfmon_port = _positive_integer("PerfMon HTTPS port", args.perfmon_port)
    args.verify_tls = _yes_no("Verify TLS certificates?", default=args.verify_tls)
    args.insecure = not args.verify_tls
    args.ca_bundle = (
        _optional_value("CA bundle path (blank uses system trust)", args.ca_bundle)
        if args.verify_tls
        else None
    )


def _choose_value(prompt: str, choices: dict[str, str], current: str) -> str:
    options = ", ".join(f"{key}={value}" for key, value in choices.items())
    while True:
        choice = input(f"{prompt} [{options}] (current: {current}): ").strip().lower()
        if not choice:
            return current
        if choice in choices:
            return choices[choice]
        if choice in choices.values():
            return choice
        print("Invalid selection")


def _optional_value(prompt: str, current: str | None) -> str | None:
    value = input(f"{prompt} [{current or 'default'}]: ").strip()
    return value or None


def _required_value(prompt: str, current: str) -> str:
    value = input(f"{prompt} [{current}]: ").strip()
    return value or current


def _positive_integer(prompt: str, current: int) -> int:
    return _bounded_integer(prompt, current, 1, None)


def _bounded_integer(prompt: str, current: int, minimum: int, maximum: int | None) -> int:
    while True:
        value = input(f"{prompt} [{current}]: ").strip()
        if not value:
            return current
        try:
            number = int(value)
        except ValueError:
            print("Enter a whole number")
            continue
        if number < minimum or (maximum is not None and number > maximum):
            upper = f" and {maximum}" if maximum is not None else ""
            print(f"Enter a number between {minimum}{upper}")
            continue
        return number


def _choose_technology(status: StatusPrinter) -> str | None:
    while True:
        choice = input("Technology: 1=CUCM, 2=Unity Connection, R=Return: ").strip().lower()
        if choice == "1":
            return "cucm"
        if choice == "2":
            return "cuc"
        if choice == "r":
            return None
        status.warn("Invalid technology selection")


def _choose_name(title: str, names: list[str], status: StatusPrinter) -> str | None:
    print(f"\n{title}\n{'=' * len(title)}")
    for index, name in enumerate(names, start=1):
        print(f"{index}. {name}")
    print("R. Return")
    while True:
        choice = input("Selection: ").strip()
        if choice.lower() == "r":
            return None
        if choice.isdigit() and 1 <= int(choice) <= len(names):
            return names[int(choice) - 1]
        if choice in names:
            return choice
        status.warn("Invalid selection")


def _yes_no(prompt: str, *, default: bool) -> bool:
    suffix = " [Y/n]: " if default else " [y/N]: "
    while True:
        choice = input(prompt + suffix).strip().lower()
        if not choice:
            return default
        if choice in {"y", "yes"}:
            return True
        if choice in {"n", "no"}:
            return False


def _prompt_new_profile_name(existing: list[str], status: StatusPrinter) -> str:
    while True:
        name = input("New profile name: ").strip()
        if not name:
            status.warn("Profile name cannot be empty")
        elif name in existing:
            status.warn("Profile Name In Use")
        else:
            return name


def _test_options(
    args: argparse.Namespace,
    status: StatusPrinter,
    run_assessment: RunAssessment,
) -> int | None:
    print("\nTEMP Test Options / Framework\n=============================")
    print("S. Run framework smoke test\nR. Return")
    while True:
        choice = input("Selection: ").strip().lower()
        if choice == "s":
            return run_assessment(args, status, None)
        if choice == "r":
            return None
        status.warn("Invalid selection")
