"""
Attack Results Visualization
CS2413 - Information Security Final Project
"""

import csv
from pathlib import Path

import matplotlib.pyplot as plt

BASE_DIR = Path(__file__).resolve().parent.parent
CSV_FILE = BASE_DIR / "results" / "attack_summary.csv"
OUTPUT_FILE = BASE_DIR / "results" / "attack_comparison.png"


def create_chart():
    attacks = []
    attempts = []
    successful_logins = []

    with CSV_FILE.open("r", newline="", encoding="utf-8") as file:
        reader = csv.DictReader(file)

        for row in reader:
            attacks.append(row["attack"])
            attempts.append(int(row["attempts"]))
            successful_logins.append(int(row["successful_logins"]))

    x = range(len(attacks))
    width = 0.35

    fig, ax = plt.subplots(figsize=(10, 6))

    ax.bar(
        [i - width / 2 for i in x],
        attempts,
        width,
        label="Total Attempts"
    )

    ax.bar(
        [i + width / 2 for i in x],
        successful_logins,
        width,
        label="Successful Logins"
    )

    ax.set_xlabel("Attack Type")
    ax.set_ylabel("Number of Attempts")
    ax.set_title("Comparison of Offline Attack Simulations")
    ax.set_xticks(list(x))
    ax.set_xticklabels(attacks)
    ax.legend()

    fig.tight_layout()
    fig.savefig(OUTPUT_FILE, dpi=300)
    plt.show()

    print(f"Chart saved to: {OUTPUT_FILE}")


if __name__ == "__main__":
    create_chart()