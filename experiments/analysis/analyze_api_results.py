
"""
API Experiment Results Analyzer
CS2413 - Information Security Final Project

Compares original API attack measurements with updated
measurements from the combined authentication application.

Original results are preserved.
"""

import csv
from pathlib import Path
from statistics import mean

BASE_DIR = Path(__file__).resolve().parent.parent
RESULTS_DIR = BASE_DIR / "results"

OUTPUT_FILE = RESULTS_DIR / "api_experiment_metrics_after.csv"

EXPERIMENTS = [
    ("Brute Force", "api_brute_force_results.csv",
     "api_brute_force_after_results.csv"),
    ("Dictionary", "api_dictionary_results.csv",
     "api_dictionary_after_results.csv"),
]


def read_csv(filename):
    path = RESULTS_DIR / filename

    if not path.exists():
        raise FileNotFoundError(f"Missing results file: {path}")

    with path.open("r", newline="", encoding="utf-8") as file:
        return list(csv.DictReader(file))


def get_boolean(row, possible_columns):
    for column in possible_columns:
        if column in row and row[column] != "":
            return row[column].strip().lower() == "true"

    raise ValueError(
        f"Could not find a success column. "
        f"Expected one of: {possible_columns}"
    )


def analyze_attack(filename, attack_name, phase):
    rows = read_csv(filename)

    if not rows:
        raise ValueError(f"No results found in {filename}")

    successful = sum(
        get_boolean(
            row,
            ["authenticated_access", "successful_login"]
        )
        for row in rows
    )

    total = len(rows)
    failed = total - successful

    response_times = [
        float(row["response_time_seconds"])
        for row in rows
        if row.get("response_time_seconds")
    ]

    retries = sum(
        int(row.get("rate_limit_retries", 0) or 0)
        for row in rows
    )

    blocked = sum(
        get_boolean(row, ["blocked"])
        for row in rows
        if row.get("blocked") not in (None, "")
    )

    return {
        "phase": phase,
        "experiment": "API Attack Test",
        "test": attack_name,
        "total_attempts": total,
        "successful_authenticated_access": successful,
        "failed_or_unconfirmed_attempts": failed,
        "success_rate_percent": round(successful / total * 100, 2),
        "average_response_time_seconds": round(
            mean(response_times), 6
        ) if response_times else 0,
        "rate_limit_retries": retries,
        "blocked_attempts": blocked,
    }


def analyze_password_security():
    filename = "api_password_security_results.csv"
    rows = read_csv(filename)

    if not rows:
        raise ValueError("No password-security results found.")

    passed = sum(
        row["passed"].strip().lower() == "true"
        for row in rows
    )

    total = len(rows)

    return {
        "phase": "Existing",
        "experiment": "Password Security Validation",
        "test": "Registration API",
        "total_attempts": total,
        "successful_authenticated_access": "",
        "failed_or_unconfirmed_attempts": "",
        "success_rate_percent": "",
        "average_response_time_seconds": round(
            mean(float(row["response_time_seconds"]) for row in rows),
            6
        ),
        "rate_limit_retries": "",
        "blocked_attempts": "",
        "validation_tests_passed": passed,
        "validation_tests_failed": total - passed,
        "validation_pass_rate_percent": round(
            passed / total * 100, 2
        ),
    }


def generate_report():
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)

    metrics = []

    for attack_name, before_file, after_file in EXPERIMENTS:
        metrics.append(
            analyze_attack(before_file, attack_name, "Before")
        )

        metrics.append(
            analyze_attack(after_file, attack_name, "After")
        )

    metrics.append(analyze_password_security())

    fieldnames = list(dict.fromkeys(
        key for row in metrics for key in row
    ))

    with OUTPUT_FILE.open(
        "w", newline="", encoding="utf-8"
    ) as file:
        writer = csv.DictWriter(file, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(metrics)

    print("=" * 65)
    print("BEFORE-AND-AFTER API EXPERIMENT ANALYSIS")
    print("=" * 65)

    for result in metrics:
        print(f"\nPhase: {result['phase']}")
        print(f"Experiment: {result['experiment']}")
        print(f"Test: {result['test']}")

        if result["experiment"] == "API Attack Test":
            print(f"Total attempts: {result['total_attempts']}")
            print(
                "Successful authenticated access: "
                f"{result['successful_authenticated_access']}"
            )
            print(
                "Failed or unconfirmed attempts: "
                f"{result['failed_or_unconfirmed_attempts']}"
            )
            print(f"Success rate: {result['success_rate_percent']}%")
            print(
                "Average response time: "
                f"{result['average_response_time_seconds']} seconds"
            )
            print(f"Rate-limit retries: {result['rate_limit_retries']}")
            print(f"Blocked attempts: {result['blocked_attempts']}")

        else:
            print(f"Validation tests passed: {result['validation_tests_passed']}")
            print(f"Validation tests failed: {result['validation_tests_failed']}")
            print(
                f"Validation pass rate: "
                f"{result['validation_pass_rate_percent']}%"
            )

    print("\nComparison metrics saved to:")
    print(OUTPUT_FILE)


if __name__ == "__main__":
    generate_report()