
"""
Credential Stuffing Simulation
CS2413 - Information Security Final Project

Offline simulation using fictional test accounts.
"""

import time

# Fictional accounts in our test application
TEST_ACCOUNTS = {
    "user1@test.com": "Summer2025!",
    "user2@test.com": "SecurePass456!",
    "user3@test.com": "Welcome123"
}

# Previously exposed fictional credentials
STOLEN_CREDENTIALS = [
    ("user1@test.com", "Password123"),
    ("user2@test.com", "SecurePass456!"),
    ("user3@test.com", "Welcome123"),
    ("user4@test.com", "Admin123")
]


def simulate_credential_stuffing():
    print("=" * 55)
    print("CREDENTIAL STUFFING SIMULATION")
    print("=" * 55)

    attempts = 0
    successful_logins = 0

    start_time = time.perf_counter()

    for username, password in STOLEN_CREDENTIALS:
        attempts += 1

        print(f"\nAttempt {attempts}: {username}")

        # Simulated authentication against fictional accounts
        if TEST_ACCOUNTS.get(username) == password:
            successful_logins += 1
            print("[!] Login successful!")
        else:
            print("[-] Login failed")

    elapsed_time = time.perf_counter() - start_time

    print("\n" + "=" * 55)
    print("ATTACK RESULTS")
    print("=" * 55)

    print(f"Total attempts: {attempts}")
    print(f"Successful logins: {successful_logins}")
    print(f"Failed logins: {attempts - successful_logins}")
    print(f"Time taken: {elapsed_time:.6f} seconds")


if __name__ == "__main__":
    simulate_credential_stuffing()