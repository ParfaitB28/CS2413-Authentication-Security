"""
Experiment Results Analyzer
CS2413 - Information Security Final Project

Summarizes the outcomes of the offline attack simulations.
"""

import csv
from pathlib import Path

RESULTS_DIR = Path(__file__).resolve().parent.parent / "results"
RESULTS_FILE = RESULTS_DIR / "attack_summary.csv"

# Demonstration results from the three attack simulations.
# These are offline simulation results, not measurements against
# the team's actual login application.
ATTACK_RESULTS = [
    {
        "attack": "Dictionary Attack",
        "attempts": 5,
        "successful_logins": 1,
        "password_found": True,
        "time_seconds": 0.8020
    },
    {
        "attack": "Brute Force Attack",
        "attempts": 12,
        "successful_logins": 1,
        "password_found": True,
        "time_seconds": 0.001031
    },
    {
        "attack": "Credential Stuffing",
        "attempts": 4,
        "successful_logins": 2,
        "password_found": False,
        "time_seconds": 0.000515
    }
]


def generate_report():
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)

    fieldnames = [
        "attack",
        "attempts",
        "successful_logins",
        "password_found",
        "time_seconds"
    ]

    with RESULTS_FILE.open("w", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(file, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(ATTACK_RESULTS)

    print("=" * 55)
    print("ATTACK SIMULATION SUMMARY")
    print("=" * 55)

    for result in ATTACK_RESULTS:
        print(f"\nAttack: {result['attack']}")
        print(f"Attempts: {result['attempts']}")
        print(f"Successful logins: {result['successful_logins']}")
        print(f"Password found: {result['password_found']}")
        print(f"Time: {result['time_seconds']:.6f} seconds")

    print("\nCSV report saved to:")
    print(RESULTS_FILE)


if __name__ == "__main__":
    generate_report()