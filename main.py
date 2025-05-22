from packing import *

for user in ["A", "B", "C"]:
    if not (os.path.exists(f'public_key_{user}.pem') and os.path.exists(f'private_key_{user}.pem')):
        generate_rsa_key(user)
# Sender A sends to receiver B and C
original_message = b"Hello from A"

# Pack message from A to B
packet_b = pack("A", "B", original_message)

# Pack message from A to C
packet_c = pack("A", "C", original_message)

# Unpack message at B's side
result_b = unpack("B", "A", packet_b)

# Unpack message at C's side
result_c = unpack("C", "A", packet_c)

# Print results for B
print("== B's Result ==")
print("Decrypted Message:", result_b['message'])
print("Signature Valid:", result_b['signature_valid'])
print("Timestamp:", result_b['timestamp'])

# Print results for C
print("\n== C's Result ==")
print("Decrypted Message:", result_c['message'])
print("Signature Valid:", result_c['signature_valid'])
print("Timestamp:", result_c['timestamp'])
