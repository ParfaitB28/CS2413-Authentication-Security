
"""
Dictionary Attack Simulation
CS2413 - Information Security Final Project

Offline simulation using a designated test account.
"""

import time

TEST_USERNAME = "test_user"
TEST_PASSWORD = "Welcome123!"

PASSWORD_LIST = [
    "password123",
    "admin123",
    "qwerty123",
    "letmein",
    "Welcome123!",
    "StrongPassword123!"
]


def simulate_dictionary_attack():
    print("=" * 50)
    print("DICTIONARY ATTACK SIMULATION")
    print("=" * 50)

    attempts = 0
    found = False
    start_time = time.perf_counter()

    for password in PASSWORD_LIST:
        attempts += 1

        print(f"Attempt {attempts}: Trying {password}")

        if password == TEST_PASSWORD:
            found = True
            print("\n[!] Password successfully guessed!")
            break

        print("[-] Incorrect password")
        time.sleep(0.2)

    elapsed_time = time.perf_counter() - start_time

    print("\n" + "=" * 50)
    print("ATTACK RESULTS")
    print("=" * 50)

    print(f"Target account: {TEST_USERNAME}")
    print(f"Attempts made: {attempts}")
    print(f"Password found: {found}")
    print(f"Time taken: {elapsed_time:.4f} seconds")


if __name__ == "__main__":
    simulate_dictionary_attack()