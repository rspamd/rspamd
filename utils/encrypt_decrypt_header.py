import nacl.utils
from nacl.secret import SecretBox


def encrypt_message(header, key):
    box = SecretBox(key)
    nonce = nacl.utils.random(nacl.secret.SecretBox.NONCE_SIZE)
    encrypted_header = box.encrypt(header, nonce)
    return encrypted_header, nonce

def decrypt_message(encrypted_header, key, nonce):
    box = SecretBox(key)
    decrypted_header = box.decrypt(encrypted_header, nonce)
    return decrypted_header

def test_encrypt_decrypt():
    message = b"The president will be exiting through the lower levels"
    key = nacl.utils.random(nacl.secret.SecretBox.KEY_SIZE)
    encrypted_message, nonce = encrypt_message(message, key)
    decrypted_message = decrypt_message(encrypted_message, key, nonce)
    if encrypted_message == decrypted_message:
        return True
    else:
        return False
