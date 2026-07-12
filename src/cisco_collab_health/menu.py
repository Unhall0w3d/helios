"""Interactive guided assessment workflow."""

from __future__ import annotations

import argparse
from collections.abc import Callable

from cisco_collab_health.config import (
    AssessmentProfile,
    AssessmentTarget,
    RuntimeProfile,
    ensure_runtime_profile,
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
    args: argparse.Namespace, status: StatusPrinter, run_assessment: RunAssessment,
    run_multi_assessment: RunMultiAssessment,
) -> int:
    """Run the primary guided workflow while retaining development options."""

    while True:
        print("\nAletheiaUC Main Menu\n====================")
        print("1. Guided assessment (select technologies and profiles)")
        print("2. Run saved multi-technology assessment")
        print("3. Run single connection profile")
        print("T. Test/framework options")
        print("Q. Quit\n")
        choice = input("Selection: ").strip().lower()
        if choice in {"1", "g"}:
            result = _guided_assessment(args, status, run_multi_assessment)
        elif choice in {"2", "a"}:
            result = _saved_assessment(args, status, run_multi_assessment)
        elif choice in {"3", "p", "l"}:
            result = _single_profile(args, status, run_assessment)
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
    args: argparse.Namespace, status: StatusPrinter, run_multi: RunMultiAssessment,
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
    resolved = resolve_assessment_targets(
        assessment, save_credentials=not run_args.no_save_credentials,
    )
    return run_multi(run_args, status, name, resolved)


def _saved_assessment(
    args: argparse.Namespace, status: StatusPrinter, run_multi: RunMultiAssessment,
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
        print(f"  - {target.target_id}: {target.technology.upper()} using {target.connection_profile}")
    run_args = _prompt_run_mode(args)
    resolved = resolve_assessment_targets(
        assessment, save_credentials=not run_args.no_save_credentials,
    )
    return run_multi(run_args, status, assessment.name, resolved)


def _single_profile(
    args: argparse.Namespace, status: StatusPrinter, run_assessment: RunAssessment,
) -> int | None:
    technology = _choose_technology(status)
    if technology is None:
        return None
    label = "CUCM" if technology == "cucm" else "Unity Connection"
    profile_name = _select_connection_profile(technology, label, status)
    if profile_name is None:
        return None
    run_args = _prompt_run_mode(args)
    run_args.product = technology
    runtime = ensure_runtime_profile(
        profile_name, technology=technology,
        save_credentials=not run_args.no_save_credentials,
    )
    return run_assessment(run_args, status, runtime)


def _select_connection_profile(
    technology: str, label: str, status: StatusPrinter,
) -> str | None:
    names = sorted(set(load_profile_names_for_technology(technology)) | set(load_profile_names()))
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


def _prompt_run_mode(args: argparse.Namespace) -> argparse.Namespace:
    run_args = argparse.Namespace(**vars(args))
    diagnostic = _yes_no(
        "Capture diagnostic evidence and export a review ZIP?", default=True,
    )
    run_args.diagnostic_capture = diagnostic
    run_args.export_review_zip = diagnostic
    if diagnostic:
        run_args.no_logs = False
        run_args.no_artifacts = False
    return run_args


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
    args: argparse.Namespace, status: StatusPrinter, run_assessment: RunAssessment,
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
