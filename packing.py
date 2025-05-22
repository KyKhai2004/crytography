from datetime import datetime
from all_function import *

def pack(sender, receiver, message):
    # Load sender's private key and receiver's public key
    private_key_sender = get_private_key(sender)
    public_key_receiver = get_public_key(receiver)
    
    # Generate AES key
    aes_key = generate_aes_key()

    # Sign the plaintext message with sender's private key
    signature = sign_message(message, private_key_sender)

    # Encrypt message using AES
    iv, ciphertext = aes_encrypt(message, aes_key)

    # Encrypt AES key using receiver's public RSA key
    enc_aes_key = rsa_encrypt(aes_key, public_key_receiver)

    # Generate timestamp
    timestamp = datetime.utcnow().isoformat()

    # Pack everything into a dictionary
    packet = {
        'iv': iv,
        'ciphertext': ciphertext,
        'enc_aes_key': enc_aes_key,
        'signature': signature,
        'timestamp': timestamp
    }

    return packet

def unpack(receiver, sender, packet):
    # Load receiver's private key and sender's public key
    private_key_receiver = get_private_key(receiver)
    public_key_sender = get_public_key(sender)

    # Decrypt AES key with receiver's private key
    aes_key = rsa_decrypt(packet['enc_aes_key'], private_key_receiver)

    # Decrypt message with AES key
    decrypted_message = aes_decrypt(packet['iv'], packet['ciphertext'], aes_key)

    # Verify signature
    is_valid = verify_signature(decrypted_message, packet['signature'], public_key_sender)

    return {
        'message': decrypted_message,
        'signature_valid': is_valid,
        'timestamp': packet['timestamp']
    }
