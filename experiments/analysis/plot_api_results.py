
"""
API Experiment Results Visualization
CS2413 - Information Security Final Project

Generates before-and-after comparison charts.
Preserves all original charts.
"""

import csv
from pathlib import Path
import matplotlib.pyplot as plt

BASE_DIR = Path(__file__).resolve().parent.parent
RESULTS_DIR = BASE_DIR / "results"


def read_csv(filename):
    path = RESULTS_DIR / filename

    if not path.exists():
        raise FileNotFoundError(f"Missing file: {path}")

    with path.open("r", newline="", encoding="utf-8") as file:
        return list(csv.DictReader(file))


def is_successful(row):
    column = (
        "authenticated_access"
        if "authenticated_access" in row
        else "successful_login"
    )
    return row[column].strip().lower() == "true"


def load_data():
    return {
        "Brute Force": {
            "before": read_csv("api_brute_force_results.csv"),
            "after": read_csv("api_brute_force_after_results.csv")
        },
        "Dictionary": {
            "before": read_csv("api_dictionary_results.csv"),
            "after": read_csv("api_dictionary_after_results.csv")
        }
    }


def create_outcomes_chart(data):
    attacks = list(data.keys())
    positions = range(len(attacks))
    width = 0.35

    fig, ax = plt.subplots(figsize=(10, 6))

    for offset, phase, label in [
        (-width / 2, "before", "Before"),
        (width / 2, "after", "After")
    ]:
        successful = [
            sum(is_successful(row) for row in data[a][phase])
            for a in attacks
        ]

        failed = [
            len(data[a][phase]) - successful[i]
            for i, a in enumerate(attacks)
        ]

        bars = ax.bar(
            [p + offset for p in positions],
            successful,
            width,
            label=f"{label} - Successful"
        )

        ax.bar(
            [p + offset for p in positions],
            failed,
            width,
            bottom=successful,
            label=f"{label} - Failed"
        )

        for bar, success, failure in zip(bars, successful, failed):
            ax.text(
                bar.get_x() + bar.get_width() / 2,
                success / 2 if success else 0.1,
                str(success),
                ha="center",
                va="center"
            )
            ax.text(
                bar.get_x() + bar.get_width() / 2,
                success + failure / 2,
                str(failure),
                ha="center",
                va="center"
            )

    ax.set_title("API Attack Outcomes: Before vs After")
    ax.set_xlabel("Attack Type")
    ax.set_ylabel("Number of Attempts")
    ax.set_xticks(list(positions))
    ax.set_xticklabels(attacks)
    ax.legend()

    fig.tight_layout()

    output = RESULTS_DIR / "api_attack_outcomes_comparison.png"
    fig.savefig(output, dpi=300)
    plt.close(fig)
    print(f"Saved: {output}")


def create_response_time_chart(data):
    attacks = list(data.keys())
    before = []
    after = []

    for attack in attacks:
        before_rows = data[attack]["before"]
        after_rows = data[attack]["after"]

        before.append(
            sum(float(r["response_time_seconds"]) for r in before_rows)
            / len(before_rows) * 1000
        )

        after.append(
            sum(float(r["response_time_seconds"]) for r in after_rows)
            / len(after_rows) * 1000
        )

    positions = list(range(len(attacks)))
    width = 0.35

    fig, ax = plt.subplots(figsize=(10, 6))

    bars_before = ax.bar(
        [p - width / 2 for p in positions],
        before,
        width,
        label="Before"
    )

    bars_after = ax.bar(
        [p + width / 2 for p in positions],
        after,
        width,
        label="After"
    )

    ax.set_title("Average API Response Time: Before vs After")
    ax.set_xlabel("Attack Type")
    ax.set_ylabel("Average Login Response Time (ms)")
    ax.set_xticks(positions)
    ax.set_xticklabels(attacks)
    ax.legend()

    for bars in (bars_before, bars_after):
        for bar in bars:
            ax.text(
                bar.get_x() + bar.get_width() / 2,
                bar.get_height(),
                f"{bar.get_height():.2f} ms",
                ha="center",
                va="bottom"
            )

    fig.tight_layout()

    output = RESULTS_DIR / "api_response_times_comparison.png"
    fig.savefig(output, dpi=300)
    plt.close(fig)
    print(f"Saved: {output}")


def create_rate_limit_chart(data):
    attacks = list(data.keys())
    before = []
    after = []

    for attack in attacks:
        before.append(
            sum(
                int(row.get("rate_limit_retries", 0) or 0)
                for row in data[attack]["before"]
            )
        )

        after.append(
            sum(
                int(row.get("rate_limit_retries", 0) or 0)
                for row in data[attack]["after"]
            )
        )

    positions = list(range(len(attacks)))
    width = 0.35

    fig, ax = plt.subplots(figsize=(10, 6))

    bars_before = ax.bar(
        [p - width / 2 for p in positions],
        before,
        width,
        label="Before"
    )

    bars_after = ax.bar(
        [p + width / 2 for p in positions],
        after,
        width,
        label="After"
    )

    ax.set_title("Rate-Limit Retry Activity: Before vs After")
    ax.set_xlabel("Attack Type")
    ax.set_ylabel("Number of Rate-Limit Retries")
    ax.set_xticks(positions)
    ax.set_xticklabels(attacks)
    ax.legend()

    for bars in (bars_before, bars_after):
        for bar in bars:
            ax.text(
                bar.get_x() + bar.get_width() / 2,
                bar.get_height(),
                str(int(bar.get_height())),
                ha="center",
                va="bottom"
            )

    fig.tight_layout()

    output = RESULTS_DIR / "api_rate_limit_comparison.png"
    fig.savefig(output, dpi=300)
    plt.close(fig)
    print(f"Saved: {output}")


def main():
    print("=" * 60)
    print("API BEFORE-AND-AFTER CHART GENERATION")
    print("=" * 60)

    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    data = load_data()

    create_outcomes_chart(data)
    create_response_time_chart(data)
    create_rate_limit_chart(data)

    print("\nAll three comparison charts generated successfully.")


if __name__ == "__main__":
    main()