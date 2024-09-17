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
    if nonce is not None:
        encrypted_header = box.encrypt(header, nonce=nonce)
    else:
        encrypted_header = box.encrypt(header)
    return encrypted_header

def decrypt_text(encrypted_header, key):
    box = create_secret_box(key)
    decrypted_header = box.decrypt(encrypted_header)
    return decrypted_header

def set_encoding(enc, type_, text):
    output = text
    if type_ == 'encode':
        if enc == 'hex':
            output = base64.b16encode(text)
        elif enc == 'base32':
            output = base64.b32encode(text)
        elif enc == 'base64':
            output = base64.b64encode(text)
    elif type_ == 'decode':
        if enc == 'hex':
            output = base64.b16decode(text)
        elif enc == 'base32':
            output = base64.b32decode(text)
        elif enc == 'base64':
            output = base64.b64decode(text)
    return output


def main():
    parser = argparse.ArgumentParser(description="Encrypt or Decrypt a text.")
    parser.add_argument("--encoding", type=str, required=True,
                                help="Encoding of provided data(raw, hex, base32, base64)")
    subparsers = parser.add_subparsers(dest="command", help="encrypt or decrypt")

    encrypt_parser = subparsers.add_parser("encrypt", help="Encrypt a text")
    encrypt_parser.add_argument("--text", type=str, required=True, help="Text to encrypt")
    encrypt_parser.add_argument("--key", type=str, required=True, help="Encryption key")
    encrypt_parser.add_argument("--nonce", type=str, required=False, help="Encryption nonce")

    decrypt_parser = subparsers.add_parser("decrypt", help="Decrypt a text")
    decrypt_parser.add_argument("--encrypted_text", type=str, required=True, help="Encrypted text")
    decrypt_parser.add_argument("--key", type=str, required=True, help="Decryption key")

    args = parser.parse_args()

    if args.command == "encrypt":
        text = args.text.encode()
        key = args.key.encode()
        if args.nonce is not None:
            nonce = set_encoding(args.encoding, 'decode', args.nonce)
        else:
            nonce = None

        encrypted_text = encrypt_text(text, key, nonce)
        if args.encoding != 'raw':
            print(set_encoding(args.encoding, 'encode', encrypted_text).decode())
        else:
            print(set_encoding(args.encoding, 'encode', encrypted_text))

    elif args.command == "decrypt":
        encrypted_text = set_encoding(args.encoding, 'decode', args.encrypted_text)
        key = args.key.encode()

        decrypted_text = decrypt_text(encrypted_text, key)
        print(decrypted_text.decode())

if __name__ == "__main__":
    main()