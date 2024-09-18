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

def set_encoding(args, type_, text):
    output = text
    if type_ == 'encode':
        if args.hex:
            output = base64.b16encode(text)
        elif args.base32:
            output = base64.b32encode(text)
        elif args.base64:
            output = base64.b64encode(text)
    elif type_ == 'decode':
        if args.hex:
            output = base64.b16decode(text)
        elif args.base32:
            output = base64.b32decode(text)
        elif args.base64:
            output = base64.b64decode(text)
    return output

def set_up_parser_args():
    new_parser = argparse.ArgumentParser(description="Encrypt or Decrypt a text.")
    enc_group = new_parser.add_mutually_exclusive_group()

    enc_group.add_argument("-r", "--raw", help="Raw encoding", action="store_true")
    enc_group.add_argument("-H", "--hex", help="Hex encoding", action="store_true")
    enc_group.add_argument("-b", "--base32", help="Base32 encoding", action="store_true")
    enc_group.add_argument("-B", "--base64", help="Base64 encoding", action="store_true")

    subparsers = new_parser.add_subparsers(dest="command", help="encrypt or decrypt")

    encrypt_parser = subparsers.add_parser("encrypt", help="Encrypt a text")
    encrypt_parser.add_argument("-t", "--text", type=str, required=True, help="Text to encrypt")
    encrypt_parser.add_argument("-k", "--key", type=str, required=True, help="Encryption key")
    encrypt_parser.add_argument("-n", "--nonce", type=str, required=False, help="Encryption nonce")

    decrypt_parser = subparsers.add_parser("decrypt", help="Decrypt a text")
    decrypt_parser.add_argument("-t", "--encrypted_text", type=str, required=True, help="Encrypted text")
    decrypt_parser.add_argument("-k", "--key", type=str, required=True, help="Decryption key")

    args = new_parser.parse_args()
    return args

def main():
    args = set_up_parser_args()

    if args.command == "encrypt":
        text = args.text.encode()
        key = args.key.encode()
        if args.nonce is not None:
            nonce = set_encoding(args, 'decode', args.nonce)
        else:
            nonce = None

        encrypted_text = encrypt_text(text, key, nonce)
        if args.raw:
            print(set_encoding(args, 'encode', encrypted_text))
        else:
            print(set_encoding(args, 'encode', encrypted_text).decode())

    elif args.command == "decrypt":
        encrypted_text = set_encoding(args, 'decode', args.encrypted_text)
        key = args.key.encode()

        decrypted_text = decrypt_text(encrypted_text, key)
        print(decrypted_text.decode())

if __name__ == "__main__":
    main()