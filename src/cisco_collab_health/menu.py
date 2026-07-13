"""Interactive guided assessment workflow."""

from __future__ import annotations

import argparse
from collections.abc import Callable

from cisco_collab_health.config import (
    AssessmentProfile,
    AssessmentTarget,
    RuntimeProfile,
    SUPPORTED_TECHNOLOGIES,
    delete_assessment_profile,
    delete_connection_profile,
    edit_connection_profile,
    ensure_runtime_profile,
    load_connection_profile_details,
    load_assessment_profiles,
    load_profile_names,
    resolve_assessment_targets,
    save_assessment_profiles,
    technology_label,
)
from cisco_collab_health.status import StatusPrinter
from cisco_collab_health.reports.html import available_report_templates

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
        print("1. Run assessment (select one or more clusters)")
        print("2. Manage saved assessment sets")
        print("3. Manage connection profiles")
        print("4. Test/framework options")
        print("Q. Quit\n")
        choice = input("Selection: ").strip().lower()
        if choice == "1":
            result = _run_selected_profiles(args, status, run_multi_assessment)
        elif choice == "2":
            result = _manage_assessment_sets(args, status, run_multi_assessment)
        elif choice == "3":
            _manage_profiles(status)
            continue
        elif choice == "4":
            result = _test_options(args, status, run_assessment)
        elif choice == "q":
            status.info("Exiting AletheiaUC")
            return 0
        else:
            status.warn("Invalid selection")
            continue
        if result is not None:
            return result


def _run_selected_profiles(
    args: argparse.Namespace,
    status: StatusPrinter,
    run_multi: RunMultiAssessment,
) -> int | None:
    targets = _select_assessment_targets(status)
    if targets is None:
        return None
    name = "On-demand assessment"
    if _yes_no("Save this cluster selection for later?", default=False):
        name = _prompt_assessment_name(load_assessment_profiles(), status)
        assessments = load_assessment_profiles()
        assessments[name] = AssessmentProfile(name, targets)
        save_assessment_profiles(assessments)
        status.ok(f"Saved assessment set: {name}")
    return _run_targets(args, status, run_multi, AssessmentProfile(name, targets))


def _manage_assessment_sets(
    args: argparse.Namespace,
    status: StatusPrinter,
    run_multi: RunMultiAssessment,
) -> int | None:
    while True:
        assessments = load_assessment_profiles()
        print("\nSaved Assessment Sets\n=====================")
        for index, name in enumerate(sorted(assessments), start=1):
            print(f"{index}. {name} ({len(assessments[name].targets)} clusters)")
        print("C. Create from connection profiles\nR. Return")
        choice = input("Selection: ").strip()
        if choice.lower() == "r":
            return None
        if choice.lower() == "c":
            targets = _select_assessment_targets(status)
            if targets is None:
                continue
            name = _prompt_assessment_name(assessments, status)
            assessments[name] = AssessmentProfile(name, targets)
            save_assessment_profiles(assessments)
            status.ok(f"Saved assessment set: {name}")
            continue
        names = sorted(assessments)
        if not choice.isdigit() or not 1 <= int(choice) <= len(names):
            status.warn("Invalid selection")
            continue
        name = names[int(choice) - 1]
        assessment = assessments[name]
        _show_assessment_set(assessment)
        action = input("R=Run, E=Edit clusters, D=Delete, B=Back: ").strip().lower()
        if action == "r":
            return _run_targets(args, status, run_multi, assessment)
        if action == "e":
            targets = _select_assessment_targets(status)
            if targets is not None:
                assessments[name] = AssessmentProfile(name, targets)
                save_assessment_profiles(assessments)
                status.ok(f"Updated assessment set: {name}")
        elif action == "d":
            if input(f"Type DELETE to remove assessment set '{name}': ").strip() == "DELETE":
                delete_assessment_profile(name)
                status.ok(f"Deleted assessment set: {name}")
            else:
                status.info("Assessment deletion cancelled")
        elif action != "b":
            status.warn("Invalid selection")


def _run_targets(
    args: argparse.Namespace,
    status: StatusPrinter,
    run_multi: RunMultiAssessment,
    assessment: AssessmentProfile,
) -> int | None:
    _show_assessment_set(assessment)
    run_args = _prompt_run_mode(args)
    if run_args is None:
        return None
    resolved = resolve_assessment_targets(
        assessment,
        save_credentials=not run_args.no_save_credentials,
    )
    return run_multi(run_args, status, assessment.name, resolved)


def _select_assessment_targets(status: StatusPrinter) -> tuple[AssessmentTarget, ...] | None:
    entries = _connection_profile_entries()
    if not entries:
        status.warn("No connection profiles found. Create one first.")
        return None
    print("\nSelect clusters to assess")
    for index, (technology, name, address) in enumerate(entries, start=1):
        print(f"{index}. {technology.upper():4} {address:15} {name}")
    print("Enter one or more numbers separated by commas, A for all, or R to return.")
    while True:
        choice = input("Clusters: ").strip().lower()
        if choice == "r":
            return None
        selected = (
            range(1, len(entries) + 1) if choice == "a" else _parse_numbers(choice, len(entries))
        )
        if selected is None:
            status.warn("Enter valid cluster numbers separated by commas")
            continue
        targets = tuple(
            AssessmentTarget(
                f"{entries[index - 1][0]}-{entries[index - 1][1]}",
                entries[index - 1][0],
                entries[index - 1][1],
            )
            for index in selected
        )
        return targets


def _connection_profile_entries() -> list[tuple[str, str, str]]:
    entries = []
    for name in load_profile_names():
        details = load_connection_profile_details(name)
        for technology, profile in details.items():
            entries.append((technology, name, profile.publisher_ip))
    return sorted(entries, key=lambda entry: (entry[0], entry[2], entry[1].lower()))


def _parse_numbers(value: str, maximum: int) -> list[int] | None:
    try:
        numbers = [int(item.strip()) for item in value.split(",")]
    except ValueError:
        return None
    if (
        not numbers
        or len(numbers) != len(set(numbers))
        or any(number not in range(1, maximum + 1) for number in numbers)
    ):
        return None
    return numbers


def _prompt_assessment_name(
    assessments: dict[str, AssessmentProfile], status: StatusPrinter
) -> str:
    while True:
        name = input("Assessment set name: ").strip()
        if not name:
            status.warn("Assessment set name cannot be empty")
        elif name in assessments:
            status.warn("Assessment set name already exists")
        else:
            return name


def _show_assessment_set(assessment: AssessmentProfile) -> None:
    print(f"\nAssessment: {assessment.name}")
    for target in assessment.targets:
        print(f"  - {target.technology.upper()} {target.connection_profile}")


def _manage_profiles(status: StatusPrinter) -> None:
    """View, edit, or delete saved connection profiles."""

    while True:
        names = load_profile_names()
        print("\nConnection Profiles\n===================")
        for index, name in enumerate(names, start=1):
            print(f"{index}. {name}")
        print("C. Create profile\nR. Return")
        choice = input("Selection: ").strip().lower()
        if choice == "r":
            return None
        if choice == "c":
            _create_connection_profile(names, status)
            continue
        if not choice.isdigit() or not 1 <= int(choice) <= len(names):
            status.warn("Invalid selection")
            continue
        selected = names[int(choice) - 1]
        print(f"\nProfile: {selected}")
        print("V. View non-secret details\nE. Edit connection details\nD. Delete profile\nB. Back")
        action = input("Selection: ").strip().lower()
        if action == "v":
            _show_profile_details(selected, status)
        elif action == "e":
            _edit_profile(selected, status)
        elif action == "d":
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
        elif action != "b":
            status.warn("Invalid selection")


def _create_connection_profile(existing: list[str], status: StatusPrinter) -> None:
    technology = _choose_technology(status)
    if technology is None:
        return
    profile_name = _prompt_new_profile_name(existing, status)
    runtime = ensure_runtime_profile(profile_name, technology=technology)
    status.ok(f"Created {technology.upper()} connection profile: {profile_name}")
    for warning in runtime.warnings:
        status.warn(warning)


def _show_profile_details(profile_name: str, status: StatusPrinter) -> None:
    details = load_connection_profile_details(profile_name)
    if not details:
        status.warn("No readable connection details found; credentials may be unavailable.")
        return
    print("\nNon-secret connection details")
    for technology, profile in sorted(details.items()):
        label = technology_label(technology)
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
        print("S. Start recommended assessment\nR. Return")
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
            # The primary start action follows the established guided-workflow
            # recommendation. Explicit settings in the relevant submenus win.
            if not getattr(run_args, "_diagnostics_configured", False):
                run_args.diagnostic_capture = True
            if not getattr(run_args, "_storage_configured", False):
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
    args.html_template = _choose_value(
        "HTML report template",
        {str(index): name for index, name in enumerate(available_report_templates(), start=1)},
        args.html_template,
    )
    args.format = _choose_value("Terminal format", {"1": "summary", "2": "json"}, args.format)
    args.no_html_report = not _yes_no("Write HTML report?", default=not args.no_html_report)
    if not args.no_html_report:
        args.html_report = _optional_value("HTML report path", args.html_report)
        args.customer_safe_report = _yes_no(
            "Build customer-deliverable HTML?", default=args.customer_safe_report
        )


def _configure_storage(args: argparse.Namespace) -> None:
    args._storage_configured = True
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
    args._diagnostics_configured = True
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
        args.accept_new_host_key = _yes_no(
            "After verifying fingerprints out of band, enroll newly discovered UCOS SSH host keys?",
            default=args.accept_new_host_key,
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
        options = list(sorted(SUPPORTED_TECHNOLOGIES))
        display = ", ".join(
            f"{index}={technology.upper()}" for index, technology in enumerate(options, 1)
        )
        choice = input(f"Technology: {display}, R=Return: ").strip().lower()
        if choice.isdigit() and 1 <= int(choice) <= len(options):
            return options[int(choice) - 1]
        if choice in SUPPORTED_TECHNOLOGIES:
            return choice
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
