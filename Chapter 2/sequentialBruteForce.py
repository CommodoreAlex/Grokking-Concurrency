#!/usr/bin/env python3.9

"""
Brute-force password cracker for numeric-only passwords.

This script attempts to crack a numeric password by generating every possible 
combination of digits of a given length and comparing their SHA-256 hashes 
against a known hash. It uses a sequential approach.
"""

import time       # For measuring performance
import math       # For power calculation
import hashlib    # For SHA-256 hash generation
import typing as T  # For type annotations


def get_combinations(*, length: int, min_number: int = 0, max_number: T.Optional[int] = None) -> T.List[str]:
    """
    Generate a list of zero-padded numeric strings representing all possible
    combinations from min_number to max_number (inclusive), with a fixed length.

    Args:
        length (int): The total length of the numeric strings (with leading zeros).
        min_number (int): The minimum number to start from (default is 0).
        max_number (Optional[int]): The maximum number to end at. If not provided, 
                                    it defaults to the highest number with the given length.

    Returns:
        List[str]: A list of all possible zero-padded numeric strings.
    """
    combinations = []

    if max_number is None:
        # Default maximum is the largest number with the specified number of digits
        max_number = int(math.pow(10, length) - 1)

    # Generate numbers and pad with leading zeros to match required length
    for i in range(min_number, max_number + 1):
        str_num = str(i)
        zeros = "0" * (length - len(str_num))
        combinations.append(zeros + str_num)

    return combinations


def get_crypto_hash(password: str) -> str:
    """
    Compute the SHA-256 hash of a given password string.

    Args:
        password (str): The input password.

    Returns:
        str: The hexadecimal representation of the hash.
    """
    return hashlib.sha256(password.encode()).hexdigest()


def check_password(expected_crypto_hash: str, possible_password: str) -> bool:
    """
    Compare the hash of a possible password with the expected hash.

    Args:
        expected_crypto_hash (str): The known hash to match.
        possible_password (str): The password guess.

    Returns:
        bool: True if the hash matches, False otherwise.
    """
    actual_crypto_hash = get_crypto_hash(possible_password)
    return expected_crypto_hash == actual_crypto_hash


def crack_password(crypto_hash: str, length: int) -> None:
    """
    Attempt to brute-force the password by trying all possible numeric combinations
    of a given length and checking their hash against the provided hash.

    Args:
        crypto_hash (str): The known SHA-256 hash of the password.
        length (int): The length of the numeric password to crack.
    """
    print("Processing number combinations sequentially...")

    start_time = time.perf_counter()
    combinations = get_combinations(length=length)

    for combination in combinations:
        if check_password(crypto_hash, combination):
            print(f"PASSWORD CRACKED: {combination}")
            break

    elapsed_time = time.perf_counter() - start_time
    print(f"PROCESS TIME: {elapsed_time:.4f} seconds")


if __name__ == "__main__":
    # Example SHA-256 hash for the password '00004269'
    crypto_hash = "e24df920078c3dd4e7e8d2442f00e5c9ab2a231bb3918d65cc50906e49ecaef4"
    length = 8  # Password length
    crack_password(crypto_hash, length)
