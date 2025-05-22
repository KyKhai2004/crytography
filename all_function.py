from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend

import rsa
import hashlib
import os


#AES
def generate_aes_key(length=32):
    return os.urandom(length)  # 32 bytes = 256 bits

# Function to AES encrypt a plaintext message
def aes_encrypt(plaintext, key):
    iv = os.urandom(16)  # AES block size for CBC is 16 bytes
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(plaintext) + padder.finalize()

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()

    return iv, ciphertext  # Return both IV and ciphertext

# Function to AES decrypt a ciphertext message
def aes_decrypt(iv, ciphertext, key):
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_padded_data = decryptor.update(ciphertext) + decryptor.finalize()

    unpadder = padding.PKCS7(128).unpadder()
    decrypted_data = unpadder.update(decrypted_padded_data) + unpadder.finalize()

    return decrypted_data

# RSA
def generate_rsa_key(username):
    # Generate a new 2048-bit RSA key pair
    (public_key, private_key) = rsa.newkeys(2048)
    
    # Store public key into a separate file
    public_key_filename = f'public_key_{username}.pem'
    with open(public_key_filename, 'wb') as pub_file:
        pub_file.write(public_key.save_pkcs1('PEM'))
    
    # Store private key into a separate file
    private_key_filename = f'private_key_{username}.pem'
    with open(private_key_filename, 'wb') as priv_file:
        priv_file.write(private_key.save_pkcs1('PEM'))

    return public_key_filename, private_key_filename
        
def rsa_encrypt(message, public_key):
    return rsa.encrypt(message, public_key)

def rsa_decrypt(ciphertext, private_key):
    return rsa.decrypt(ciphertext, private_key)

# RSA signing and verification
def sign_message(message, private_key):
    message_hash = hashlib.sha256(message).digest()
    signature = rsa.sign(message, private_key, 'SHA-256')
    return signature
def verify_signature(message, signature, public_key):
    try:
        rsa.verify(message, signature, public_key)
        return True
    except rsa.VerificationError:
        return False
    

# retrieve public and private keys
def get_public_key(username):
    try:
        filename = f"public_key_{username}.pem"
        with open(filename, 'rb') as file:
            public_key = rsa.PublicKey.load_pkcs1(file.read(), format='PEM')
        return public_key
    except FileNotFoundError:
        print(f"Error: Public key file '{filename}' not found.")
        return None
    except Exception as e:
        print(f"Error loading public key: {e}")
        return None


def get_private_key(username):
    try:
        filename = f"private_key_{username}.pem"
        with open(filename, 'rb') as file:
            private_key = rsa.PrivateKey.load_pkcs1(file.read(), format='PEM')
        return private_key
    except FileNotFoundError:
        print(f"Error: Private key file '{filename}' not found.")
        return None
    except Exception as e:
        print(f"Error loading private key: {e}")
        return None
