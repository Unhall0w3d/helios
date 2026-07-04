"""Interactive menu flow for Helios CLI runs."""

from __future__ import annotations

import argparse
from collections.abc import Callable

from cisco_collab_health.config import RuntimeProfile, ensure_runtime_profile, load_profile_names
from cisco_collab_health.status import StatusPrinter

RunAssessment = Callable[[argparse.Namespace, StatusPrinter, RuntimeProfile | None], int]


def run_menu(args: argparse.Namespace, status: StatusPrinter, run_assessment: RunAssessment) -> int:
    """Run the interactive Helios menu."""

    while True:
        print()
        print("Helios Main Menu")
        print("================")
        print("L. Load Profile")
        print("N. New Profile")
        print("G. Generate Report")
        print("T. TEMP Test Options")
        print("Q. Quit")
        print()

        choice = input("Selection: ").strip().lower()
        if choice == "l":
            result = _menu_load_profile(args, status, run_assessment)
            if result is not None:
                return result
        elif choice == "n":
            result = _menu_new_profile(args, status, run_assessment)
            if result is not None:
                return result
        elif choice == "g":
            _menu_generate_report(status)
        elif choice == "t":
            result = _menu_temp_options(args, status, run_assessment)
            if result is not None:
                return result
        elif choice == "q":
            status.info("Exiting Helios")
            return 0
        else:
            status.warn("Invalid selection")


def _menu_load_profile(
    args: argparse.Namespace,
    status: StatusPrinter,
    run_assessment: RunAssessment,
) -> int | None:
    profile_names = load_profile_names()
    if not profile_names:
        status.warn("No saved profiles found. Starting new profile creation.")
        return _menu_new_profile(args, status, run_assessment)

    print()
    print("Saved Profiles")
    print("==============")
    for index, name in enumerate(profile_names, start=1):
        print(f"{index}. {name}")
    print("R. Return")
    print()

    while True:
        choice = input("Profile number/name: ").strip()
        if choice.lower() == "r":
            return None
        if choice.isdigit():
            index = int(choice)
            if 1 <= index <= len(profile_names):
                runtime_profile = ensure_runtime_profile(
                    profile_names[index - 1],
                    save_credentials=not args.no_save_credentials,
                )
                return _menu_profile_action(args, status, runtime_profile, run_assessment)
        if choice in profile_names:
            runtime_profile = ensure_runtime_profile(
                choice,
                save_credentials=not args.no_save_credentials,
            )
            return _menu_profile_action(args, status, runtime_profile, run_assessment)
        status.warn("Invalid profile selection")


def _menu_new_profile(
    args: argparse.Namespace,
    status: StatusPrinter,
    run_assessment: RunAssessment,
) -> int | None:
    profile_name = _prompt_new_menu_profile_name(load_profile_names(), status)
    runtime_profile = ensure_runtime_profile(
        profile_name,
        save_credentials=not args.no_save_credentials,
    )
    return _menu_profile_action(args, status, runtime_profile, run_assessment)


def _menu_profile_action(
    args: argparse.Namespace,
    status: StatusPrinter,
    runtime_profile: RuntimeProfile,
    run_assessment: RunAssessment,
) -> int | None:
    while True:
        choice = input("Run (H)ealth Assessment or (R)eturn to main menu: ").strip().lower()
        if choice == "h":
            return run_assessment(args, status, runtime_profile)
        if choice == "r":
            return None
        status.warn("Enter H to run the assessment or R to return")


def _menu_generate_report(status: StatusPrinter) -> None:
    status.warn("Report generation from existing artifacts is not implemented yet.")
    status.info(
        "Run a Health Assessment to generate the current Executive Summary and HTML report."
    )


def _menu_temp_options(
    args: argparse.Namespace,
    status: StatusPrinter,
    run_assessment: RunAssessment,
) -> int | None:
    while True:
        print()
        print("TEMP Test Options")
        print("=================")
        print("S. Run framework smoke test")
        print("R. Return")
        print()
        choice = input("Selection: ").strip().lower()
        if choice == "s":
            return run_assessment(args, status, None)
        if choice == "r":
            return None
        status.warn("Invalid selection")


def _prompt_new_menu_profile_name(existing_names: list[str], status: StatusPrinter) -> str:
    while True:
        profile_name = input("New profile name: ").strip()
        if not profile_name:
            status.warn("Profile name cannot be empty")
            continue
        if profile_name in existing_names:
            status.warn("Profile Name In Use")
            continue
        return profile_name
