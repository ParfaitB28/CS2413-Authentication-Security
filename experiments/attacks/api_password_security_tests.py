
"""
Password Security API Tests
CS2413 - Information Security Final Project

Tests registration password length, weak-password rejection,
and successful registration using the integrated zxcvbn evaluator.
"""

import csv
import json
import time
import urllib.error
import urllib.request
from pathlib import Path

REGISTER_URL = "http://127.0.0.1:3000/register"

BASE_DIR = Path(__file__).resolve().parent.parent
RESULTS_DIR = BASE_DIR / "results"
OUTPUT_FILE = RESULTS_DIR / "api_password_security_results.csv"

TESTS = [
    {
        "name": "Password Below Minimum Length",
        "password": "Short123!",
        "expected_status": 400,
        "expected_text": "password between 15 and 128 characters."
    },
    {
        "name": "Weak Password",
        "password": "aaaaaaaaaaaaaaaa",
        "expected_status": 400,
        "expected_text": "Password does not meet security requirements."
    },
    {
        "name": "Strong Password",
        "password": "vT#8pR^2mNb5&xQ1zL",
        "expected_status": 201,
        "expected_text": "Account created."
    }
]


def test_registration(test, index):
    email = f"securitytest{time.time_ns()}_{index}@example.com"

    payload = json.dumps({
        "email": email,
        "password": test["password"]
    }).encode("utf-8")

    request = urllib.request.Request(
        REGISTER_URL,
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST"
    )

    start = time.perf_counter()

    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            status = response.status
            body = response.read().decode("utf-8")

    except urllib.error.HTTPError as error:
        status = error.code
        body = error.read().decode("utf-8")

    except Exception as error:
        print(f"API connection failed: {error}")
        return None

    elapsed = time.perf_counter() - start

    passed = (
        status == test["expected_status"]
        and test["expected_text"] in body
    )

    return {
        "test": test["name"],
        "http_status": status,
        "expected_status": test["expected_status"],
        "passed": passed,
        "response_time_seconds": round(elapsed, 6),
        "response": body
    }


def main():
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)

    results = []

    print("=" * 55)
    print("PASSWORD SECURITY API TESTS")
    print("=" * 55)

    for index, test in enumerate(TESTS, start=1):
        result = test_registration(test, index)

        if result is None:
            print("Stopping because the API is unavailable.")
            return

        results.append(result)

        print(
            f"{result['test']}: "
            f"HTTP {result['http_status']} | "
            f"Expected {result['expected_status']} | "
            f"{'PASS' if result['passed'] else 'FAIL'}"
        )

    with OUTPUT_FILE.open(
        "w", newline="", encoding="utf-8"
    ) as file:
        writer = csv.DictWriter(
            file,
            fieldnames=results[0].keys()
        )
        writer.writeheader()
        writer.writerows(results)

    passed = sum(result["passed"] for result in results)

    print("\n" + "=" * 55)
    print(f"Tests passed: {passed}/{len(results)}")
    print(f"Results saved to: {OUTPUT_FILE}")


if __name__ == "__main__":
    main()