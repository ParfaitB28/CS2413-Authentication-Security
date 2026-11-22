
"""
API Dictionary Attack Test
CS2413 - Information Security Final Project

Controlled testing against the combined local authentication API.
Uses fictional test credentials only.

Each password attempt uses an isolated session.
Cookies are retained between /login and /me.
Successful access is confirmed through /me, not HTTP 200 from /login.
"""

import csv
import json
import time
import urllib.error
import urllib.request
import http.cookiejar
from pathlib import Path

# Local authentication API
LOGIN_URL = "http://127.0.0.1:3000/login"
ME_URL = "http://127.0.0.1:3000/me"

# Fictional test account
TEST_EMAIL = "testuser@example.com"

# Controlled dictionary
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


def send_request(opener, request):
    """Send an HTTP request and return its status and response body."""

    try:
        with opener.open(request, timeout=10) as response:
            return response.status, response.read().decode("utf-8")

    except urllib.error.HTTPError as error:
        return error.code, error.read().decode("utf-8")

    except Exception as error:
        print(f"Connection error: {error}")
        return None, None


def attempt_login(email, password):
    """
    Attempt one password using an isolated session.
    Retain its cookies when checking authenticated access through /me.
    """

    # Create a fresh cookie jar for this password attempt.
    cookie_jar = http.cookiejar.CookieJar()

    opener = urllib.request.build_opener(
        urllib.request.HTTPCookieProcessor(cookie_jar)
    )

    payload = json.dumps({
        "email": email,
        "password": password
    }).encode("utf-8")

    login_request = urllib.request.Request(
        LOGIN_URL,
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST"
    )

    # Measure login response time.
    start_time = time.perf_counter()

    login_status, login_body = send_request(
        opener, login_request
    )

    login_elapsed = time.perf_counter() - start_time

    if login_status is None:
        return None

    # Parse login response to identify MFA-required status.
    try:
        login_data = json.loads(login_body or "{}")
    except (json.JSONDecodeError, TypeError):
        login_data = {}

    mfa_required = login_data.get("mfaRequired", False)

    # Check access using the same session and retained cookies.
    me_request = urllib.request.Request(
        ME_URL,
        headers={"Accept": "application/json"},
        method="GET"
    )

    me_status, me_body = send_request(opener, me_request)

    if me_status is None:
        return None

    # A successful /me response confirms authenticated access.
    authenticated = me_status == 200

    return {
        "login_status": login_status,
        "me_status": me_status,
        "mfa_required": mfa_required,
        "authenticated_access": authenticated,
        "response_time": login_elapsed
    }


def run_dictionary_attack():
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)

    results = []
    successful_access = 0

    print("=" * 60)
    print("API DICTIONARY ATTACK TEST")
    print("=" * 60)

    for attempt_number, password in enumerate(
        PASSWORD_CANDIDATES, start=1
    ):

        outcome = attempt_login(TEST_EMAIL, password)

        if outcome is None:
            print("Test stopped because the API is unavailable.")
            break

        success = outcome["authenticated_access"]

        if success:
            successful_access += 1

        results.append({
            "attack": "Dictionary",
            "attempt": attempt_number,
            "login_http_status": outcome["login_status"],
            "me_http_status": outcome["me_status"],
            "mfa_required": outcome["mfa_required"],
            "authenticated_access": success,
            "response_time_seconds": round(
                outcome["response_time"], 6
            )
        })

        print(
            f"Attempt {attempt_number}: "
            f"Login HTTP {outcome['login_status']}, "
            f"/me HTTP {outcome['me_status']}, "
            f"MFA required: {outcome['mfa_required']}, "
            f"Authenticated access: {success}, "
            f"Time: {outcome['response_time']:.4f}s"
        )

        if success:
            print("\nAuthenticated access confirmed!")
            break

        if outcome["mfa_required"]:
            print("Password accepted, but MFA is required.")

        time.sleep(0.2)

    # Save experiment results.
    fieldnames = [
        "attack",
        "attempt",
        "login_http_status",
        "me_http_status",
        "mfa_required",
        "authenticated_access",
        "response_time_seconds"
    ]

    with OUTPUT_FILE.open(
        "w", newline="", encoding="utf-8"
    ) as file:

        writer = csv.DictWriter(
            file,
            fieldnames=fieldnames
        )

        writer.writeheader()
        writer.writerows(results)

    print("\n" + "=" * 60)
    print("DICTIONARY ATTACK RESULTS")
    print("=" * 60)
    print(f"Total attempts: {len(results)}")
    print(f"Confirmed authenticated access: {successful_access}")
    print(f"Other attempts: {len(results) - successful_access}")
    print(f"Results saved to: {OUTPUT_FILE}")


if __name__ == "__main__":
    run_dictionary_attack()