from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import padding as aes_padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
import os
import base64
import hashlib


class CryptoProject:
    def getspaceindex(self, text):
        spaces_index = []

        for i in range(len(text)):
            if list(text)[i] == " ":  # if char is a space
                # take note of the index space is located at
                spaces_index.append(i)

        return spaces_index

    def addspaces(self, list, text):

        for i in range(len(list)):
            # inserting the spaces in the index previously saved
            text.insert(list[i], " ")

        return ''.join(text)

    def vigenere_keyword(self, text, keyword):
        difference = (len(text)) - (len(keyword))

        # append remaining characters of keyword to match length of plaintext-------------------
        for i in range(difference):
            keyword.append(keyword[i])

        return keyword

    def string_to_list(self, text):
        text = list((text.lower()).replace(" ", ""))
        return text

    def vigenere_encrypt(self, message, keyword):
        alphabet = ['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l',
                    'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z']

        # get spaces index for later------------------------------------------------------------
        spaces_index = self.getspaceindex(plaintext)

        # split plaintext and keyword into a list, get the length, get the difference-----------
        plaintext = self.string_to_list(plaintext)

        # repeat keyword to match length of plaintext
        keyword = self.vigenere_keyword(
            plaintext, keyword=self.string_to_list(keyword))

        # vigenere cipher-----------------------------------------------------------------------
        encryption = []
        for i in range(len(plaintext)):
            # add the character index to find the corresponding row and column character
            sum = (alphabet.index(plaintext[i]) + alphabet.index(keyword[i]))

            # if the sum is more than 26, subtract 26 (alphabet starts over)
            if sum >= 26:
                sum -= 26
            # index the correct vigenere character
            encryption.append(alphabet[sum])

        # add the spaces again------------------------------------------------------------------

        return self.addspaces(spaces_index, encryption)

    def vigenere_decrypt(self, ciphertext, keyword):
        # Your Vigenère cipher decryption code here
        alphabet = ['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l',
                    'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z']

        # note where spaces are located
        spaces_index = self.getspaceindex(ciphertext)

        # turn string into iterable list
        ciphertext = self.string_to_list(ciphertext)

        # keyword repeats for len of ciphertexts
        keyword = self.vigenere_keyword(
            ciphertext, self.string_to_list(keyword))

        decryption = []

        for i in range(len(ciphertext)):
            # get index of each letter in keyword and ciphertext (know letters)
            keyword_index = alphabet.index(keyword[i])
            ciphertext_index = alphabet.index(ciphertext[i])

            # reverse engineer
            # example: lets say the keyword is P and the ciphertext is D, (plaintext is O)
            # that is 15 and 3
            # 15 - 26 = -11
            # - 11 + x = 3
            # x = 11 + 3 = 14
            # O = 14
            difference = abs(keyword_index - 26)
            decryption_index = difference + ciphertext_index

            if decryption_index >= 26:  # if greater than 26, subtract to get accurate number
                decryption_index -= 26

            decryption.append(alphabet[decryption_index])

            # call function to add spaces where needed
            return self.addspaces(spaces_index, decryption)

    def aes_encrypt(self, plaintext, key):
        # AES encryption code here
        # Generate a random salt and IV
        salt = os.urandom(16)
        iv = os.urandom(16)
        # Derive a 32-byte key using PBKDF2
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        derived_key = kdf.derive(key.encode())
        # Encrypt the plaintext using AES in CBC mode, pad the text to be a multiple of 16 bytes
        # create the cipher object, encryptor object and padder object
        cipher = Cipher(algorithms.AES(derived_key),
                        modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        padder = aes_padding.PKCS7(128).padder()
        # pad the data
        padded_data = padder.update(plaintext.encode()) + padder.finalize()
        # encrypt the padded data
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()
        # convert the ciphertext to hex
        ciphertext = ciphertext.hex()
        # convert the salt to hex
        salt = salt.hex()
        # convert the iv to hex
        iv = iv.hex()
        # build a string to return that includes the salt, iv and ciphertext hex values, clearly delimited
        return f"{salt}|{iv}|{ciphertext}"

    def aes_decrypt(self, ciphertext, key):
        # AES decryption code here
        return

    def rsa_encrypt(self, plaintext, public_key_path):
        # RSA encryption code here
        plaintext_encoded = plaintext.encode('utf-8')  # encode to bytes
        # read from the file and get public key
        with open(public_key_path, "rb") as key_file:
            public_key = serialization.load_pem_public_key(
                key_file.read(),
            )
        # TODO: Encrypt a string using RSA public key
        ciphertext = public_key.encrypt(  # encrypt cipher text using public_key
            plaintext_encoded,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        # return an encoded base 64 so user can then input this into the decrypt function
        return base64.b64encode(ciphertext).decode('utf-8')
        return

    def rsa_decrypt(self, ciphertext, private_key_path):
        # decode the base64 encoded from the encrypt function
        ciphertext = base64.b64decode(ciphertext)
        password = b'mypassword'  # password used during encryption
        with open(private_key_path, "rb") as key_file:  # read private key
            private_key = serialization.load_pem_private_key(
                key_file.read(),
                password=password,
            )
        # TODO: Decrypt a string using RSA private key
        plaintext = private_key.decrypt(  # decrypt using private key
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return plaintext.decode('utf-8')  # decode to get full plain text

    def generate_rsa_keys(self, private_key_path, public_key_path):
        # RSA key generation code here
        private_key = rsa.generate_private_key(  # gen private key
            public_exponent=65537,
            key_size=2048,
        )

        public_key = private_key.public_key()  # create public key from private key

        public_pem = public_key.public_bytes(  # prepare to write public key on file (serialization)
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        private_pem = private_key.private_bytes(  # prepare to write public key on file (serialization)
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.BestAvailableEncryption(
                b'mypassword')
        )

        with open(public_key_path, "wb") as key_file:  # write to file
            key_file.write(public_pem)

        with open(private_key_path, "wb") as key_file:
            key_file.write(private_pem)
        return

    def hash_string(self, input_string):
        # Create a new SHA-256 hash object
        sha256_hash = hashlib.sha256()

        # Update the hash object with the bytes of the input string
        sha256_hash.update(input_string.encode('utf-8'))

        # Return the hexadecimal digest of the hash
        return sha256_hash.hexdigest()

    def verify_integrity(self, input_string, expected_hash):
        # Calculate the hash of the input string
        calculated_hash = self.hash_string(input_string)

        # Compare it with the expected hash
        return calculated_hash == expected_hash
