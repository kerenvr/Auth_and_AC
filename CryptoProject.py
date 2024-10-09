from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import padding as aes_padding
import os
import string

class CryptoProject:
    
    def vigenere_encrypt(self, message, keyword):
        # Your Vigenère cipher encryption code here
        return

    def vigenere_decrypt(self, ciphertext, keyword):
        # Your Vigenère cipher decryption code here
        return

    def aes_encrypt(self, plaintext, key):
        # AES encryption code here
        return

    def aes_decrypt(self, ciphertext, key):
        # AES decryption code here
        return

    def rsa_encrypt(self, plaintext, public_key_path):
        # RSA encryption code here
        return

    def rsa_decrypt(self, ciphertext, private_key_path):
        # RSA decryption code here
        return

    def generate_rsa_keys(self):
        # RSA key generation code here
        return

    def hash_string(self, input_string):
        return 
    
    def verify_integrity(self, input_string, expected_hash):
        return
