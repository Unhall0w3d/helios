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
    """Run the guided workflow with session settings and explicit run modes."""

    settings = argparse.Namespace(**vars(args))
    while True:
        print("\nAletheiaUC Main Menu\n====================")
        print(_settings_summary(settings))
        print("1. Run standard assessment")
        print("2. Run diagnostic assessment (full evidence bundle)")
        print("3. Profile management")
        print("4. Settings")
        print("5. Developer Options")
        print("Q. Quit\n")
        choice = input("Selection: ").strip().lower()
        if choice == "1":
            result = _choose_and_run_assessment(
                settings, status, run_multi_assessment, diagnostic=False
            )
        elif choice == "2":
            result = _choose_and_run_assessment(
                settings, status, run_multi_assessment, diagnostic=True
            )
        elif choice == "3":
            _manage_profile_management(status)
            continue
        elif choice == "4":
            _manage_settings(settings, status)
            continue
        elif choice == "5":
            result = _test_options(settings, status, run_assessment)
        elif choice == "q":
            status.info("Exiting AletheiaUC")
            return 0
        else:
            status.warn("Invalid selection")
            continue
        if result is not None:
            return result


def _choose_and_run_assessment(
    args: argparse.Namespace,
    status: StatusPrinter,
    run_multi: RunMultiAssessment,
    *,
    diagnostic: bool,
) -> int | None:
    while True:
        print("\nAssessment Selection\n====================")
        print("1. Select clusters for this run")
        print("2. Use a saved assessment profile")
        print("R. Return")
        choice = input("Selection: ").strip().lower()
        if choice == "r":
            return None
        if choice == "1":
            return _run_selected_profiles(args, status, run_multi, diagnostic=diagnostic)
        if choice == "2":
            assessment = _choose_saved_assessment_profile(status)
            if assessment is not None:
                return _run_targets(args, status, run_multi, assessment, diagnostic=diagnostic)
        else:
            status.warn("Invalid selection")


def _run_selected_profiles(
    args: argparse.Namespace,
    status: StatusPrinter,
    run_multi: RunMultiAssessment,
    *,
    diagnostic: bool,
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
        status.ok(f"Saved assessment profile: {name}")
    return _run_targets(
        args, status, run_multi, AssessmentProfile(name, targets), diagnostic=diagnostic
    )


def _manage_assessment_profiles(status: StatusPrinter) -> None:
    while True:
        assessments = load_assessment_profiles()
        print("\nAssessment Profiles\n===================")
        if assessments:
            for index, name in enumerate(sorted(assessments), start=1):
                print(f"{index}. {name} ({len(assessments[name].targets)} clusters)")
        else:
            print("No saved assessment profiles.")
        print("C. Create assessment profile from connection profiles\nR. Return")
        choice = input("Selection: ").strip()
        if choice.lower() == "r":
            return
        if choice.lower() == "c":
            targets = _select_assessment_targets(status)
            if targets is None:
                continue
            name = _prompt_assessment_name(assessments, status)
            assessments[name] = AssessmentProfile(name, targets)
            save_assessment_profiles(assessments)
            status.ok(f"Saved assessment profile: {name}")
            continue
        names = sorted(assessments)
        if not choice.isdigit() or not 1 <= int(choice) <= len(names):
            status.warn("Invalid selection")
            continue
        name = names[int(choice) - 1]
        assessment = assessments[name]
        _show_assessment_set(assessment)
        action = input("C=Copy and edit, E=Edit clusters, D=Delete, B=Back: ").strip().lower()
        if action == "e":
            targets = _edit_assessment_targets(assessment.targets, status)
            if targets is not None:
                assessments[name] = AssessmentProfile(name, targets)
                save_assessment_profiles(assessments)
                status.ok(f"Updated assessment profile: {name}")
        elif action == "c":
            copy_name = _prompt_assessment_name(assessments, status)
            print("Review the copied cluster selection and make any needed changes.")
            targets = _edit_assessment_targets(assessment.targets, status)
            if targets is not None:
                assessments[copy_name] = AssessmentProfile(copy_name, targets)
                save_assessment_profiles(assessments)
                status.ok(f"Copied assessment profile: {copy_name}")
        elif action == "d":
            if input(f"Type DELETE to remove assessment profile '{name}': ").strip() == "DELETE":
                delete_assessment_profile(name)
                status.ok(f"Deleted assessment profile: {name}")
            else:
                status.info("Assessment deletion cancelled")
        elif action != "b":
            status.warn("Invalid selection")


def _choose_saved_assessment_profile(status: StatusPrinter) -> AssessmentProfile | None:
    assessments = load_assessment_profiles()
    if not assessments:
        status.warn("No saved assessment profiles found. Create one under Profile Management.")
        return None
    name = _choose_name("Saved Assessment Profiles", sorted(assessments), status)
    return assessments.get(name) if name is not None else None


def _run_targets(
    args: argparse.Namespace,
    status: StatusPrinter,
    run_multi: RunMultiAssessment,
    assessment: AssessmentProfile,
    *,
    diagnostic: bool,
) -> int | None:
    _show_assessment_set(assessment)
    run_args = _run_args_for_mode(args, diagnostic=diagnostic)
    if not _confirm_run(assessment, run_args, diagnostic=diagnostic):
        return None
    resolved = resolve_assessment_targets(
        assessment,
        save_credentials=not run_args.no_save_credentials,
    )
    return run_multi(run_args, status, assessment.name, resolved)


def _run_args_for_mode(args: argparse.Namespace, *, diagnostic: bool) -> argparse.Namespace:
    """Copy session settings and apply the selected guided-run contract."""

    run_args = argparse.Namespace(**vars(args))
    run_args._prompt_ssh_host_keys = True
    run_args._prompt_ssh_password_retry = True
    # Both guided modes deliver the customer and engineering HTML reports.
    run_args.no_html_report = False
    run_args.customer_safe_report = False
    run_args.include_customer_safe_report = True
    if diagnostic:
        run_args.diagnostic_capture = True
        run_args.export_review_zip = True
        run_args.no_logs = False
        run_args.no_artifacts = False
    else:
        # A standard assessment is intentionally report-only.  Its collection
        # and presentation settings still come from the session configuration.
        run_args.diagnostic_capture = False
        run_args.export_review_zip = False
        run_args.no_logs = True
        run_args.no_artifacts = True
    return run_args


def _settings_summary(args: argparse.Namespace) -> str:
    """Return a non-secret summary of settings that influence guided runs."""

    tls_mode = "verify TLS" if args.verify_tls else "allow self-signed TLS"
    return (
        f"Current settings: template={args.html_template} | {tls_mode} | "
        f"SSH workers={args.ssh_parallel_workers} | "
        f"endpoint HTTPS sample={'on' if args.endpoint_web_sample else 'off'}"
    )


def _confirm_run(
    assessment: AssessmentProfile, args: argparse.Namespace, *, diagnostic: bool
) -> bool:
    print("\nRun Confirmation\n================")
    print(f"Mode: {'Diagnostic assessment (full evidence bundle)' if diagnostic else 'Standard assessment'}")
    print(f"Clusters: {len(assessment.targets)}")
    for target in assessment.targets:
        print(f"  - {target.technology.upper()} {target.connection_profile}")
    print(f"Report template: {args.html_template}")
    print("Reports: engineering and customer-facing HTML, with PDF copies when Chromium is installed")
    print(f"TLS verification: {'enabled' if args.verify_tls else 'disabled'}")
    if diagnostic:
        print("Bundle: artifacts, logs, and private review ZIP")
        if args.endpoint_web_sample:
            print(
                "Endpoint HTTPS sample: enabled "
                f"({args.endpoint_web_sample_size} registered endpoints, "
                f"{args.endpoint_web_timeout_seconds}s each)"
            )
    return _yes_no("Start this assessment?", default=True)


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


def _edit_assessment_targets(
    current_targets: tuple[AssessmentTarget, ...], status: StatusPrinter
) -> tuple[AssessmentTarget, ...] | None:
    """Select a revised cluster set, retaining the copied/current members by default."""

    entries = _connection_profile_entries()
    if not entries:
        status.warn("No connection profiles found. Create one first.")
        return None
    current_keys = {(target.technology, target.connection_profile) for target in current_targets}
    current_numbers = [
        index
        for index, (technology, name, _address) in enumerate(entries, start=1)
        if (technology, name) in current_keys
    ]
    print("\nEdit clusters in assessment profile")
    for index, (technology, name, address) in enumerate(entries, start=1):
        marker = "*" if index in current_numbers else " "
        print(f"{marker} {index}. {technology.upper():4} {address:15} {name}")
    current_text = ",".join(str(index) for index in current_numbers) or "none"
    print("Enter revised numbers, A for all, blank to keep the copied selection, or R to cancel.")
    while True:
        choice = input(f"Clusters [{current_text}]: ").strip().lower()
        if not choice:
            return current_targets
        if choice == "r":
            return None
        selected = (
            range(1, len(entries) + 1) if choice == "a" else _parse_numbers(choice, len(entries))
        )
        if selected is None:
            status.warn("Enter valid cluster numbers separated by commas")
            continue
        return tuple(
            AssessmentTarget(
                f"{entries[index - 1][0]}-{entries[index - 1][1]}",
                entries[index - 1][0],
                entries[index - 1][1],
            )
            for index in selected
        )


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
        name = input("Assessment profile name: ").strip()
        if not name:
            status.warn("Assessment profile name cannot be empty")
        elif name in assessments:
            status.warn("Assessment profile name already exists")
        else:
            return name


def _show_assessment_set(assessment: AssessmentProfile) -> None:
    print(f"\nAssessment profile: {assessment.name}")
    for target in assessment.targets:
        print(f"  - {target.technology.upper()} {target.connection_profile}")


def _manage_profiles(status: StatusPrinter) -> None:
    """View, edit, or delete saved connection profiles."""

    while True:
        names = load_profile_names()
        print("\nConnection Profiles\n===================")
        if names:
            for index, name in enumerate(names, start=1):
                print(f"{index}. {name} — {_connection_profile_summary(name)}")
        else:
            print("No saved connection profiles.")
        print("C. Create connection profile\nR. Return")
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


def _manage_profile_management(status: StatusPrinter) -> None:
    """Keep technology connection profiles and multi-cluster profiles together."""

    while True:
        print("\nProfile Management\n==================")
        print("1. Connection profiles by technology (CUCM, CUC, CER, IM&P)")
        print("2. Assessment profiles (multi-technology)")
        print("R. Return")
        choice = input("Selection: ").strip().lower()
        if choice == "1":
            _manage_profiles(status)
        elif choice == "2":
            _manage_assessment_profiles(status)
        elif choice == "r":
            return
        else:
            status.warn("Invalid selection")


def _connection_profile_summary(profile_name: str) -> str:
    """Render saved technologies and addresses without exposing credentials."""

    details = load_connection_profile_details(profile_name)
    if not details:
        return "connection details unavailable"
    return "; ".join(
        f"{technology.upper()} {profile.publisher_ip}"
        for technology, profile in sorted(details.items())
    )


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


def _manage_settings(args: argparse.Namespace, status: StatusPrinter) -> None:
    """Configure session defaults; returning here never starts an assessment."""

    while True:
        print("\nSettings\n========")
        print(f"1. Reports (template: {args.html_template})")
        print("2. Collection")
        print(f"3. Network and TLS ({'verify' if args.verify_tls else 'allow self-signed'})")
        print("4. Artifact and log locations")
        print("5. Diagnostic collection limits")
        print("R. Return")
        choice = input("Selection: ").strip().lower()
        if choice == "1":
            _configure_output(args)
        elif choice == "2":
            _configure_collection(args)
        elif choice == "3":
            _configure_network(args)
        elif choice == "4":
            _configure_storage(args)
        elif choice == "5":
            _configure_diagnostic_limits(args)
        elif choice == "r":
            return
        else:
            status.warn("Invalid selection")


def _configure_output(args: argparse.Namespace) -> None:
    args.html_template = _choose_value(
        "HTML report template",
        {str(index): name for index, name in enumerate(available_report_templates(), start=1)},
        args.html_template,
    )
    args.format = _choose_value("Terminal format", {"1": "summary", "2": "json"}, args.format)
    args.no_html_report = False
    args.html_report = _optional_value("Engineering HTML report path", args.html_report)
    print("[INFO] Guided runs always create engineering and customer-facing HTML reports.")


def _configure_storage(args: argparse.Namespace) -> None:
    print("These locations apply when running a diagnostic assessment.")
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
    args.ssh_parallel_workers = _positive_integer(
        "Independent UCOS SSH node workers", args.ssh_parallel_workers
    )
    args.endpoint_web_sample = _yes_no(
        "Run optional HTTPS web-interface sample against registered endpoints during diagnostic assessments?",
        default=args.endpoint_web_sample,
    )
    if args.endpoint_web_sample:
        args.endpoint_web_sample_size = _positive_integer(
            "Endpoint HTTPS sample size", args.endpoint_web_sample_size
        )
        args.endpoint_web_timeout_seconds = _positive_integer(
            "Endpoint HTTPS timeout seconds", args.endpoint_web_timeout_seconds
        )


def _configure_diagnostic_limits(args: argparse.Namespace) -> None:
    print("Diagnostic assessment enables evidence capture and the private review bundle.")
    args.diagnostic_max_devices = _bounded_integer(
        "Diagnostic maximum devices", args.diagnostic_max_devices, 1, 2000
    )
    args.diagnostic_axl_page_size = _positive_integer(
        "Diagnostic AXL page size", args.diagnostic_axl_page_size
    )
    args.diagnostic_axl_max_records = _positive_integer(
        "Diagnostic AXL maximum records", args.diagnostic_axl_max_records
    )
    args.diagnostic_cupi_max_records = _positive_integer(
        "Diagnostic CUPI maximum records", args.diagnostic_cupi_max_records
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
    print("\nDeveloper Options\n=================")
    print("S. Run framework smoke test\nR. Return")
    while True:
        choice = input("Selection: ").strip().lower()
        if choice == "s":
            return run_assessment(args, status, None)
        if choice == "r":
            return None
        status.warn("Invalid selection")
