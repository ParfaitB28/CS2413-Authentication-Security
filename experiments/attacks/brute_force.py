
"""
Brute Force Attack Simulation
CS2413 - Information Security Final Project

Controlled offline simulation using a toy password space.
"""

import itertools
import time

# Test password for this experiment
TEST_PASSWORD = "b2"

# Small character set for demonstration
CHARACTERS = "ab12"

# Maximum number of attempts
MAX_ATTEMPTS = 100


def simulate_brute_force():
    print("=" * 50)
    print("BRUTE FORCE ATTACK SIMULATION")
    print("=" * 50)

    attempts = 0
    found = False

    start_time = time.perf_counter()

    # Try combinations of increasing length
    for length in range(1, 4):

        for combination in itertools.product(CHARACTERS, repeat=length):

            if attempts >= MAX_ATTEMPTS:
                break

            password = "".join(combination)
            attempts += 1

            print(f"Attempt {attempts}: Trying {password}")

            # Compare with the designated test password
            if password == TEST_PASSWORD:
                found = True
                print("\n[!] Password successfully guessed!")
                break

        if found or attempts >= MAX_ATTEMPTS:
            break

    elapsed_time = time.perf_counter() - start_time

    print("\n" + "=" * 50)
    print("ATTACK RESULTS")
    print("=" * 50)

    print(f"Test password: {TEST_PASSWORD}")
    print(f"Attempts made: {attempts}")
    print(f"Password found: {found}")
    print(f"Time taken: {elapsed_time:.6f} seconds")


if __name__ == "__main__":
    simulate_brute_force()