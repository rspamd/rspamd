import argparse
import base64

import nacl.encoding
from nacl.secret import SecretBox
from nacl.hash import blake2b

def create_secret_box(key):
    key = blake2b(key, encoder=nacl.encoding.RawEncoder)
    box = SecretBox(key)
    return box

def encrypt_text(header, key, nonce):
    box = create_secret_box(key)
    encrypted_header = box.encrypt(header, nonce=nonce)
    return encrypted_header

def decrypt_text(encrypted_header, key):
    box = create_secret_box(key)
    decrypted_header = box.decrypt(encrypted_header)
    return decrypted_header

def main():
    parser = argparse.ArgumentParser(description="Encrypt or Decrypt a text.")
    subparsers = parser.add_subparsers(dest="command", help="encrypt or decrypt")

    encrypt_parser = subparsers.add_parser("encrypt", help="Encrypt a text")
    encrypt_parser.add_argument("--text", type=str, required=True, help="Text to encrypt")
    encrypt_parser.add_argument("--key", type=str, required=True, help="Encryption key")
    encrypt_parser.add_argument("--nonce", type=str, required=True, help="Encryption nonce")

    decrypt_parser = subparsers.add_parser("decrypt", help="Decrypt a text")
    decrypt_parser.add_argument("--encrypted_text", type=str, required=True, help="Encrypted text")
    decrypt_parser.add_argument("--key", type=str, required=True, help="Decryption key")

    args = parser.parse_args()

    if args.command == "encrypt":
        text = args.text.encode()
        key = args.key.encode()
        nonce = base64.b64decode(args.nonce)

        encrypted_text = encrypt_text(text, key, nonce)
        print("Encrypted text (base 64):", base64.b64encode(encrypted_text))

    elif args.command == "decrypt":
        encrypted_text = base64.b64decode(args.encrypted_text)
        key = args.key.encode()

        decrypted_text = decrypt_text(encrypted_text, key)
        print("Decrypted text:", decrypted_text.decode())

if __name__ == "__main__":
    main()