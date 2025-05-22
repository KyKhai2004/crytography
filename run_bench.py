import os
import argparse
from benchmark_utils import (
    measure_latency,
    measure_throughput,
    avalanche_key_sensitivity_aes,
    avalanche_plaintext_sensitivity,
    shannon_entropy,
    key_size_bits,
    rsa_key_size_bits,
    write_csv
)
from all_function import (
    generate_aes_key,
    generate_rsa_key,
    aes_encrypt,
    aes_decrypt,
    rsa_encrypt,
    rsa_decrypt,
    sign_message,
    verify_signature
)
from packing import pack, unpack
import rsa

def parse_args():
    parser = argparse.ArgumentParser(
        description='Run benchmarks for E2EE group messaging')
    parser.add_argument(
        '--group-size', '-g',
        type=int,
        default=1,
        help='Number of recipients for group pack benchmarking (default: 1)'
    )
    return parser.parse_args()


def main():
    args = parse_args()
    # Prepare benchmarking data
    plaintext = b"The quick brown fox jumps over the lazy dog." * 100

    # 1. Key generation latency
    aes_key = generate_aes_key()
    aes_bits = key_size_bits(aes_key)
    rsa_pub, rsa_priv = rsa.newkeys(2048)
    rsa_bits = rsa_key_size_bits(rsa_pub)

    aes_keygen_time = measure_latency(generate_aes_key, iterations=100)
    rsa_keygen_time = measure_latency(generate_rsa_key, 'testuser', iterations=10)

    # 2. AES encrypt/decrypt latency
    iv, ciphertext = aes_encrypt(plaintext, aes_key)
    aes_enc_time = measure_latency(aes_encrypt, plaintext, aes_key, iterations=100)
    aes_dec_time = measure_latency(aes_decrypt, iv, ciphertext, aes_key, iterations=100)

    # 3. RSA encrypt/decrypt session key latency
    rsa_enc_time = measure_latency(rsa_encrypt, aes_key, rsa_pub, iterations=100)
    enc_key = rsa_encrypt(aes_key, rsa_pub)
    rsa_dec_time = measure_latency(rsa_decrypt, enc_key, rsa_priv, iterations=100)

    # 4. Signature gen/verify latency
    signature = sign_message(plaintext, rsa_priv)
    sign_time = measure_latency(sign_message, plaintext, rsa_priv, iterations=100)
    verify_time = measure_latency(verify_signature, plaintext, signature, rsa_pub, iterations=100)

    # 5. Pack/Unpack latency for single recipient
    sender = 'A'
    receiver = 'B'
    pack_time = measure_latency(pack, sender, receiver, plaintext, iterations=100)
    packet = pack(sender, receiver, plaintext)
    unpack_time = measure_latency(unpack, receiver, sender, packet, iterations=100)

    # 6. AES throughput for different payload sizes
    throughputs = []
    for size in [1024, 10*1024, 100*1024]:
        data = os.urandom(size)
        tp = measure_throughput(lambda d: aes_encrypt(d, aes_key), data, iterations=50)
        throughputs.append((size, tp / (1024 * 1024)))  # MB/s

    # 7. Security metrics: avalanche and entropy
    key_avalanche = avalanche_key_sensitivity_aes(aes_encrypt, plaintext, aes_key, iterations=20)
    plain_avalanche = avalanche_plaintext_sensitivity(aes_encrypt, plaintext, aes_key, iterations=20)
    entropy = shannon_entropy(ciphertext)

    # 8. Group pack latency for variable recipients
    group_size = args.group_size
    if group_size > 1:
        users = [rsa.newkeys(2048)[0] for _ in range(group_size)]
        def pack_group(data, key, pubs):
            iv, ct = aes_encrypt(data, key)
            for pk in pubs:
                _ = rsa_encrypt(key, pk)
            return iv, ct
        group_pack_time = measure_latency(
            pack_group, plaintext, aes_key, users, iterations=10
        )
    else:
        group_pack_time = None

    # Prepare CSV rows
    header = ['Metric', 'Value']
    rows = [
        ['AES Key Size (bits)', aes_bits],
        ['RSA Key Size (bits)', rsa_bits],
        ['AES KeyGen Latency (s)', aes_keygen_time],
        ['RSA KeyGen Latency (s)', rsa_keygen_time],
        ['AES Encrypt Latency (s)', aes_enc_time],
        ['AES Decrypt Latency (s)', aes_dec_time],
        ['RSA Encrypt Latency (s)', rsa_enc_time],
        ['RSA Decrypt Latency (s)', rsa_dec_time],
        ['Signature Gen Latency (s)', sign_time],
        ['Signature Verify Latency (s)', verify_time],
        ['Pack Latency Single (s)', pack_time],
        ['Unpack Latency Single (s)', unpack_time],
        ['AES Key Avalanche', key_avalanche],
        ['AES Plaintext Avalanche', plain_avalanche],
        ['Ciphertext Entropy (bits/byte)', entropy]
    ]

    if group_pack_time is not None:
        rows.append([f'Group Pack Latency ({group_size} recipients) (s)', group_pack_time])

    for size, mbps in throughputs:
        rows.append([f'AES Throughput {size} B (MB/s)', mbps])

    # Write results
    write_csv('benchmark_results.csv', header, rows)

    # Print summary
    for metric, value in rows:
        print(f"{metric}: {value}")

if __name__ == '__main__':
    main()
