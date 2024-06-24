import string
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import os
import base64

# Caesar cipher functions
def caesar_encrypt(message, key):
    shift = (key % 26)
    cipher = str.maketrans(string.ascii_lowercase, string.ascii_lowercase[shift:] + string.ascii_lowercase[:shift])
    encrypted_message = message.lower().translate(cipher)
    return encrypted_message

def caesar_decrypt(encrypted_message, key):
    shift = 26 - (key % 26)
    cipher = str.maketrans(string.ascii_lowercase, string.ascii_lowercase[shift:] + string.ascii_lowercase[:shift])
    message = encrypted_message.translate(cipher)
    return message

# AES-GCM encryption functions
def generate_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

def encrypt_message(message: str, password: str) -> tuple:
    salt = os.urandom(16)
    key = generate_key(password, salt)
    iv = os.urandom(12)
    encryptor = Cipher(
        algorithms.AES(key),
        modes.GCM(iv),
        backend=default_backend()
    ).encryptor()
    encrypted_message = encryptor.update(message.encode()) + encryptor.finalize()
    return (base64.b64encode(salt).decode(), base64.b64encode(iv).decode(), base64.b64encode(encrypted_message).decode(), base64.b64encode(encryptor.tag).decode())

def decrypt_message(salt: str, iv: str, encrypted_message: str, tag: str, password: str) -> str:
    salt = base64.b64decode(salt)
    iv = base64.b64decode(iv)
    encrypted_message = base64.b64decode(encrypted_message)
    tag = base64.b64decode(tag)
    key = generate_key(password, salt)
    decryptor = Cipher(
        algorithms.AES(key),
        modes.GCM(iv, tag),
        backend=default_backend()
    ).decryptor()
    decrypted_message = decryptor.update(encrypted_message) + decryptor.finalize()
    return decrypted_message.decode()

print(""" 
 ▄████████  ▄█     ▄███████▄    ▄█    █▄       ▄████████    ▄████████         ▄████████ ███    █▄     ▄████████  ▄█   ▄██████▄  ███▄▄▄▄   
███    ███ ███    ███    ███   ███    ███     ███    ███   ███    ███        ███    ███ ███    ███   ███    ███ ███  ███    ███ ███▀▀▀██▄ 
███    █▀  ███▌   ███    ███   ███    ███     ███    █▀    ███    ███        ███    █▀  ███    ███   ███    █▀  ███▌ ███    ███ ███   ███ 
███        ███▌   ███    ███  ▄███▄▄▄▄███▄▄  ▄███▄▄▄      ▄███▄▄▄▄██▀       ▄███▄▄▄     ███    ███   ███        ███▌ ███    ███ ███   ███ 
███        ███▌ ▀█████████▀  ▀▀███▀▀▀▀███▀  ▀▀███▀▀▀     ▀▀███▀▀▀▀▀        ▀▀███▀▀▀     ███    ███ ▀███████████ ███▌ ███    ███ ███   ███ 
███    █▄  ███    ███          ███    ███     ███    █▄  ▀███████████        ███        ███    ███          ███ ███  ███    ███ ███   ███ 
███    ███ ███    ███          ███    ███     ███    ███   ███    ███        ███        ███    ███    ▄█    ███ ███  ███    ███ ███   ███ 
████████▀  █▀    ▄████▀        ███    █▀      ██████████   ███    ███        ███        ████████▀   ▄████████▀  █▀    ▀██████▀   ▀█   █▀  
                                                           ███    ███                                                                     """)

print("""Welcome to Cipher Fusion!
1. Ancient Encryption (Caesar Cipher)
2. Modern Encryption (AES-GCM)
""")

choice = input("Choose the encryption method (1 or 2): ")

if choice == "1":
    action = input("Do you want to (E)ncrypt or (D)ecrypt? ").upper()
    if action == "E":
        message = input("What message would you like to hide? ")
        key = int(input("What is the key? "))
        encrypted_message = caesar_encrypt(message, key)
        print(f'Your encrypted message is {encrypted_message}')
    elif action == "D":
        encrypted_message = input("What is the encrypted message? ")
        key = int(input("What is the key? "))
        decrypted_message = caesar_decrypt(encrypted_message, key)
        print(f'Your decrypted message is {decrypted_message}')
    else:
        print("Invalid choice. Please select 'E' or 'D'.")

elif choice == "2":
    action = input("Do you want to (E)ncrypt or (D)ecrypt? ").upper()
    if action == "E":
        password = input("Enter the password for encryption: ")
        message = input("What message would you like to hide? ")
        salt, iv, encrypted_message, tag = encrypt_message(message, password)
        print(f'Your encrypted message is {encrypted_message}')
        print(f'Salt: {salt}')
        print(f'IV: {iv}')
        print(f'Tag: {tag}')
    elif action == "D":
        encrypted_message = input("Enter the encrypted message: ")
        salt = input("Enter the salt: ")
        iv = input("Enter the IV: ")
        tag = input("Enter the tag: ")
        password = input("Enter the password for decryption: ")
        try:
                decrypted_message = decrypt_message(salt, iv, encrypted_message, tag, password)
                print(f'Your decrypted message is {decrypted_message}')
        except Exception as e:
                print(f'Decryption failed: {str(e)}')
    else:
        print("Invalid choice. Please select 'E' or 'D'.")

else:
    print("Invalid choice. Please select 1 or 2.")