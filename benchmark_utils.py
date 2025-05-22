import time
import random
import math
import csv
from collections import Counter

# Performance measurements

def measure_latency(func, *args, iterations=100):
    """
    Measure average execution time of func(*args) over a number of iterations.
    Returns time in seconds.
    """
    t0 = time.perf_counter()
    for _ in range(iterations):
        func(*args)
    t1 = time.perf_counter()
    return (t1 - t0) / iterations


def measure_throughput(func, data, iterations=50):
    """
    Measure throughput (bytes per second) of func(data).
    Returns bytes/sec.
    """
    total_bytes = len(data) * iterations
    t0 = time.perf_counter()
    for _ in range(iterations):
        func(data)
    t1 = time.perf_counter()
    seconds = t1 - t0
    return total_bytes / seconds

# Avalanche (sensitivity) metrics

def avalanche_key_sensitivity_aes(encrypt_fn, plaintext, key, iterations=10):
    """
    Compute average avalanche effect when flipping one random bit of the key.
    Returns fraction of bits changed in ciphertext.
    """
    rates = []
    for _ in range(iterations):
        flipped = bytearray(key)
        i = random.randrange(len(key) * 8)
        byte_idx, bit_idx = divmod(i, 8)
        flipped[byte_idx] ^= (1 << bit_idx)

        iv1, ct1 = encrypt_fn(plaintext, key)
        iv2, ct2 = encrypt_fn(plaintext, bytes(flipped))

        # Hamming distance / total bits
        hd = sum(bin(b1 ^ b2).count('1') for b1, b2 in zip(ct1, ct2))
        rates.append(hd / (len(plaintext) * 8))
    return sum(rates) / len(rates)


def avalanche_plaintext_sensitivity(encrypt_fn, plaintext, key, iterations=10):
    """
    Compute average avalanche effect when flipping one random bit of the plaintext.
    Returns fraction of bits changed in ciphertext.
    """
    rates = []
    for _ in range(iterations):
        p2 = bytearray(plaintext)
        i = random.randrange(len(plaintext) * 8)
        byte_idx, bit_idx = divmod(i, 8)
        p2[byte_idx] ^= (1 << bit_idx)

        iv1, ct1 = encrypt_fn(plaintext, key)
        iv2, ct2 = encrypt_fn(bytes(p2), key)

        hd = sum(bin(b1 ^ b2).count('1') for b1, b2 in zip(ct1, ct2))
        rates.append(hd / (len(plaintext) * 8))
    return sum(rates) / len(rates)

# Entropy measurement

def shannon_entropy(data: bytes) -> float:
    """
    Compute Shannon entropy in bits per byte of the given data.
    """
    cnt = Counter(data)
    length = len(data)
    return -sum((freq / length) * math.log2(freq / length) for freq in cnt.values())

# Key size introspection

def key_size_bits(key) -> int:
    """
    Returns key size in bits. For byte-based keys returns len(key)*8.
    """
    try:
        return len(key) * 8
    except Exception:
        return None


def rsa_key_size_bits(public_key) -> int:
    """
    Given an rsa.PublicKey or rsa.PrivateKey, returns modulus bit length.
    """
    # rsa.PublicKey has attribute n
    return public_key.n.bit_length()

# CSV export

def write_csv(filename: str, header: list, rows: list):
    """
    Write a header and rows to a CSV file.
    """
    with open(filename, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(header)
        writer.writerows(rows)
