
"""
API Experiment Results Analyzer
CS2413 - Information Security Final Project

Analyzes actual local API attack tests and password-security tests.
Keeps API measurements separate from offline attack simulations.
"""

import csv
from pathlib import Path
from statistics import mean

BASE_DIR = Path(__file__).resolve().parent.parent
RESULTS_DIR = BASE_DIR / "results"

BRUTE_FORCE_FILE = RESULTS_DIR / "api_brute_force_results.csv"
DICTIONARY_FILE = RESULTS_DIR / "api_dictionary_results.csv"
PASSWORD_FILE = RESULTS_DIR / "api_password_security_results.csv"

OUTPUT_FILE = RESULTS_DIR / "api_experiment_metrics.csv"


def read_csv(file_path):
    if not file_path.exists():
        raise FileNotFoundError(f"Missing results file: {file_path}")

    with file_path.open("r", newline="", encoding="utf-8") as file:
        return list(csv.DictReader(file))


def analyze_attack(file_path, attack_name):
    rows = read_csv(file_path)

    if not rows:
        raise ValueError(f"No results found in {file_path.name}")

    total = len(rows)
    successful = sum(
        row["successful_login"].strip().lower() == "true"
        for row in rows
    )
    failed = total - successful

    response_times = [
        float(row["response_time_seconds"]) for row in rows
    ]

    return {
        "experiment": "API Attack Test",
        "test": attack_name,
        "total_requests": total,
        "successful_logins": successful,
        "failed_logins": failed,
        "login_success_rate_percent": round(
            successful / total * 100, 2
        ),
        "tests_passed": "",
        "tests_failed": "",
        "test_pass_rate_percent": "",
        "avg_response_time_seconds": round(
            mean(response_times), 6
        ),
    }


def analyze_password_security():
    rows = read_csv(PASSWORD_FILE)

    if not rows:
        raise ValueError("No password-security results found.")

    total = len(rows)
    passed = sum(
        row["passed"].strip().lower() == "true"
        for row in rows
    )
    failed = total - passed

    response_times = [
        float(row["response_time_seconds"]) for row in rows
    ]

    return {
        "experiment": "Password Security Validation",
        "test": "Registration API",
        "total_requests": total,
        "successful_logins": "",
        "failed_logins": "",
        "login_success_rate_percent": "",
        "tests_passed": passed,
        "tests_failed": failed,
        "test_pass_rate_percent": round(
            passed / total * 100, 2
        ),
        "avg_response_time_seconds": round(
            mean(response_times), 6
        ),
    }


def generate_report():
    metrics = [
        analyze_attack(BRUTE_FORCE_FILE, "Brute Force"),
        analyze_attack(DICTIONARY_FILE, "Dictionary"),
        analyze_password_security(),
    ]

    fieldnames = list(metrics[0].keys())

    with OUTPUT_FILE.open(
        "w", newline="", encoding="utf-8"
    ) as file:
        writer = csv.DictWriter(file, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(metrics)

    print("=" * 65)
    print("ACTUAL API EXPERIMENT METRICS")
    print("=" * 65)

    for result in metrics:
        print(f"\nExperiment: {result['experiment']}")
        print(f"Test: {result['test']}")

        if result["experiment"] == "API Attack Test":
            print(f"Total requests: {result['total_requests']}")
            print(f"Successful logins: {result['successful_logins']}")
            print(f"Failed logins: {result['failed_logins']}")
            print(
                f"Login success rate: "
                f"{result['login_success_rate_percent']}%"
            )
        else:
            print(f"Total validation tests: {result['total_requests']}")
            print(f"Tests passed: {result['tests_passed']}")
            print(f"Tests failed: {result['tests_failed']}")
            print(
                f"Test pass rate: "
                f"{result['test_pass_rate_percent']}%"
            )

        print(
            f"Average response time: "
            f"{result['avg_response_time_seconds']} seconds"
        )

    print("\nConsolidated metrics saved to:")
    print(OUTPUT_FILE)


if __name__ == "__main__":
    generate_report()