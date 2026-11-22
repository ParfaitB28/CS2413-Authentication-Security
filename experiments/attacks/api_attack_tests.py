
"""
API Dictionary Attack Test
CS2413 - Information Security Final Project

Controlled testing against the combined local authentication API.
Uses fictional test credentials only.

Features:
- Retains session cookies.
- Verifies authenticated access through /me.
- Handles HTTP 429 and Retry-After.
- Avoids retrying indefinitely during account lockout.
- Preserves previous experiment results.
"""

import csv
import json
import time
import urllib.error
import urllib.request
import http.cookiejar
from pathlib import Path
from email.utils import parsedate_to_datetime
from datetime import datetime, timezone

LOGIN_URL = "http://127.0.0.1:3000/login"
ME_URL = "http://127.0.0.1:3000/me"

TEST_EMAIL = "testuser@example.com"

PASSWORD_CANDIDATES = [
    "password123",
    "admin123",
    "Welcome123!",
    "WrongPassword123!",
    "SecureTestPass2026!"
]

BASE_DIR = Path(__file__).resolve().parent.parent
RESULTS_DIR = BASE_DIR / "results"

OUTPUT_FILE = RESULTS_DIR / "api_dictionary_after_results.csv"

MAX_429_RETRIES = 2
MAX_WAIT_SECONDS = 65


def send_request(opener, request):
    """Return HTTP status, body and response headers."""

    try:
        with opener.open(request, timeout=15) as response:
            return (
                response.status,
                response.read().decode("utf-8"),
                response.headers
            )

    except urllib.error.HTTPError as error:
        return (
            error.code,
            error.read().decode("utf-8"),
            error.headers
        )

    except Exception as error:
        print(f"Connection error: {error}")
        return None, None, None


def get_retry_delay(headers):
    """Read Retry-After as seconds or an HTTP date."""

    value = headers.get("Retry-After") if headers else None

    if not value:
        return None

    try:
        return max(0, int(value))
    except ValueError:
        try:
            retry_time = parsedate_to_datetime(value)

            if retry_time.tzinfo is None:
                retry_time = retry_time.replace(tzinfo=timezone.utc)

            return max(
                0,
                (retry_time - datetime.now(timezone.utc)).total_seconds()
            )
        except (TypeError, ValueError):
            return None


def attempt_login(email, password):
    """Attempt login and verify access using the same session."""

    cookie_jar = http.cookiejar.CookieJar()
    opener = urllib.request.build_opener(
        urllib.request.HTTPCookieProcessor(cookie_jar)
    )

    payload = json.dumps({
        "email": email,
        "password": password
    }).encode("utf-8")

    retries = 0
    total_response_time = 0

    while True:
        request = urllib.request.Request(
            LOGIN_URL,
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST"
        )

        start = time.perf_counter()

        status, body, headers = send_request(opener, request)

        total_response_time += time.perf_counter() - start

        if status is None:
            return None

        if status != 429:
            break

        retry_delay = get_retry_delay(headers)

        if retry_delay is None:
            retry_delay = 60

        # Do not wait through a five-minute account lockout.
        if retry_delay > MAX_WAIT_SECONDS:
            return {
                "login_status": status,
                "me_status": None,
                "mfa_required": False,
                "authenticated_access": False,
                "response_time": total_response_time,
                "retries": retries,
                "blocked": True,
                "retry_after": retry_delay
            }

        if retries >= MAX_429_RETRIES:
            return {
                "login_status": status,
                "me_status": None,
                "mfa_required": False,
                "authenticated_access": False,
                "response_time": total_response_time,
                "retries": retries,
                "blocked": True,
                "retry_after": retry_delay
            }

        retries += 1
        print(f"HTTP 429. Waiting {retry_delay:.0f} seconds...")
        time.sleep(retry_delay + 0.5)

    try:
        login_data = json.loads(body or "{}")
    except (json.JSONDecodeError, TypeError):
        login_data = {}

    mfa_required = login_data.get("mfaRequired", False)

    me_request = urllib.request.Request(
        ME_URL,
        headers={"Accept": "application/json"},
        method="GET"
    )

    me_status, _, _ = send_request(opener, me_request)

    if me_status is None:
        return None

    authenticated = (
        status == 200
        and not mfa_required
        and me_status == 200
    )

    return {
        "login_status": status,
        "me_status": me_status,
        "mfa_required": mfa_required,
        "authenticated_access": authenticated,
        "response_time": total_response_time,
        "retries": retries,
        "blocked": False,
        "retry_after": 0
    }


def run_dictionary_attack():
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)

    results = []
    successful_access = 0

    print("=" * 60)
    print("API DICTIONARY ATTACK TEST")
    print("=" * 60)

    for number, password in enumerate(
        PASSWORD_CANDIDATES, start=1
    ):
        outcome = attempt_login(TEST_EMAIL, password)

        if outcome is None:
            print("Test stopped: API unavailable.")
            break

        success = outcome["authenticated_access"]

        if success:
            successful_access += 1

        results.append({
            "attack": "Dictionary",
            "attempt": number,
            "login_http_status": outcome["login_status"],
            "me_http_status": outcome["me_status"],
            "mfa_required": outcome["mfa_required"],
            "authenticated_access": success,
            "response_time_seconds": round(
                outcome["response_time"], 6
            ),
            "rate_limit_retries": outcome["retries"],
            "blocked": outcome["blocked"],
            "retry_after_seconds": outcome["retry_after"]
        })

        print(
            f"Attempt {number}: "
            f"Login HTTP {outcome['login_status']}, "
            f"/me HTTP {outcome['me_status']}, "
            f"Authenticated: {success}, "
            f"Retries: {outcome['retries']}"
        )

        if success:
            print("Authenticated access confirmed!")
            break

        if outcome["blocked"]:
            print("Testing stopped because the request was blocked.")
            break

    fields = [
        "attack",
        "attempt",
        "login_http_status",
        "me_http_status",
        "mfa_required",
        "authenticated_access",
        "response_time_seconds",
        "rate_limit_retries",
        "blocked",
        "retry_after_seconds"
    ]

    with OUTPUT_FILE.open(
        "w", newline="", encoding="utf-8"
    ) as file:
        writer = csv.DictWriter(file, fieldnames=fields)
        writer.writeheader()
        writer.writerows(results)

    print("\nDICTIONARY ATTACK SUMMARY")
    print(f"Attempts: {len(results)}")
    print(f"Confirmed access: {successful_access}")
    print(f"Results: {OUTPUT_FILE}")


if __name__ == "__main__":
    run_dictionary_attack()