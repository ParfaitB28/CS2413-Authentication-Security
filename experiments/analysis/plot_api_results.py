
"""
API Experiment Results Visualization
CS2413 - Information Security Final Project

Generates charts from actual local API experiment results.
"""

import csv
from pathlib import Path

import matplotlib.pyplot as plt

BASE_DIR = Path(__file__).resolve().parent.parent
RESULTS_DIR = BASE_DIR / "results"


def read_csv(filename):
    file_path = RESULTS_DIR / filename

    if not file_path.exists():
        raise FileNotFoundError(f"Missing file: {file_path}")

    with file_path.open("r", newline="", encoding="utf-8") as file:
        return list(csv.DictReader(file))


def create_attack_outcomes_chart():
    brute = read_csv("api_brute_force_results.csv")
    dictionary = read_csv("api_dictionary_results.csv")

    attacks = ["Brute Force", "Dictionary"]

    successful = [
        sum(row["successful_login"].lower() == "true" for row in brute),
        sum(row["successful_login"].lower() == "true" for row in dictionary)
    ]

    failed = [
        len(brute) - successful[0],
        len(dictionary) - successful[1]
    ]

    fig, ax = plt.subplots(figsize=(9, 6))

    ax.bar(attacks, successful, label="Successful Logins")
    ax.bar(attacks, failed, bottom=successful, label="Failed Logins")

    ax.set_title("Actual API Attack Outcomes")
    ax.set_xlabel("Attack Type")
    ax.set_ylabel("Number of Login Attempts")
    ax.legend()

    for i in range(len(attacks)):
        ax.text(i, successful[i] / 2, str(successful[i]),
                ha="center", va="center")
        ax.text(i, successful[i] + failed[i] / 2, str(failed[i]),
                ha="center", va="center")

    fig.tight_layout()
    output = RESULTS_DIR / "api_attack_outcomes.png"
    fig.savefig(output, dpi=300)
    plt.close(fig)

    print(f"Saved: {output}")


def create_response_time_chart():
    brute = read_csv("api_brute_force_results.csv")
    dictionary = read_csv("api_dictionary_results.csv")

    attacks = ["Brute Force", "Dictionary"]

    averages = [
        sum(float(row["response_time_seconds"]) for row in brute) / len(brute),
        sum(float(row["response_time_seconds"]) for row in dictionary) / len(dictionary)
    ]

    averages_ms = [value * 1000 for value in averages]

    fig, ax = plt.subplots(figsize=(9, 6))

    bars = ax.bar(attacks, averages_ms)

    ax.set_title("Average API Response Time by Attack")
    ax.set_xlabel("Attack Type")
    ax.set_ylabel("Average Response Time (milliseconds)")

    for bar, value in zip(bars, averages_ms):
        ax.text(
            bar.get_x() + bar.get_width() / 2,
            bar.get_height(),
            f"{value:.2f} ms",
            ha="center",
            va="bottom"
        )

    fig.tight_layout()
    output = RESULTS_DIR / "api_response_times.png"
    fig.savefig(output, dpi=300)
    plt.close(fig)

    print(f"Saved: {output}")


def create_password_validation_chart():
    rows = read_csv("api_password_security_results.csv")

    passed = sum(row["passed"].lower() == "true" for row in rows)
    failed = len(rows) - passed

    labels = ["Passed", "Failed"]
    values = [passed, failed]

    fig, ax = plt.subplots(figsize=(8, 6))

    bars = ax.bar(labels, values)

    ax.set_title("Password Security Validation Results")
    ax.set_xlabel("Validation Outcome")
    ax.set_ylabel("Number of Tests")

    ax.set_ylim(0, max(values + [1]) * 1.3)

    for bar, value in zip(bars, values):
        ax.text(
            bar.get_x() + bar.get_width() / 2,
            bar.get_height(),
            str(value),
            ha="center",
            va="bottom"
        )

    fig.tight_layout()
    output = RESULTS_DIR / "password_validation_results.png"
    fig.savefig(output, dpi=300)
    plt.close(fig)

    print(f"Saved: {output}")


def main():
    print("=" * 55)
    print("API EXPERIMENT CHART GENERATION")
    print("=" * 55)

    RESULTS_DIR.mkdir(parents=True, exist_ok=True)

    create_attack_outcomes_chart()
    create_response_time_chart()
    create_password_validation_chart()

    print("\nAll three charts generated successfully.")


if __name__ == "__main__":
    main()