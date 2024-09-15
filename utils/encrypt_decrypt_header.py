import argparse
import base64

import nacl.utils
from nacl.secret import SecretBox


def encrypt_header(header, key):
    box = SecretBox(key)
    encrypted_header = box.encrypt(header)
    return encrypted_header

def decrypt_header(encrypted_header, key):
    box = SecretBox(key)
    decrypted_header = box.decrypt(encrypted_header)
    return decrypted_header

def main():
    parser = argparse.ArgumentParser(description="Encrypt or Decrypt a header.")
    subparsers = parser.add_subparsers(dest="command", help="encrypt or decrypt")

    encrypt_parser = subparsers.add_parser("encrypt", help="Encrypt a message")
    encrypt_parser.add_argument("--header", type=str, required=True, help="Header to encrypt")
    encrypt_parser.add_argument("--key", type=str, required=True, help="Encryption key")

    decrypt_parser = subparsers.add_parser("decrypt", help="Decrypt a message")
    decrypt_parser.add_argument("--encrypted_header", type=str, required=True, help="Encrypted header")
    decrypt_parser.add_argument("--key", type=str, required=True, help="Decryption key")

    args = parser.parse_args()

    if args.command == "encrypt":
        header = args.header.encode()
        key = args.key.encode()

        encrypted_header = encrypt_header(header, key)
        print(encrypted_header)
        print(len(encrypted_header))
        print("Encrypted header (base 64):", base64.b64encode(encrypted_header))
        print("Encrypted header (base 64):", base64.b64encode(encrypted_header.ciphertext))
        print("Encrypted header (base 64):", base64.b64encode(encrypted_header.nonce))

    elif args.command == "decrypt":
        encrypted_header = base64.b64decode(args.encrypted_header)
        key = args.key.encode()

        decrypted_header = decrypt_header(encrypted_header, key)
        print("Decrypted message:", decrypted_header.decode())

if __name__ == "__main__":
    main()