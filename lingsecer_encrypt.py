from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5
import base64

def encrypt_with_public_key(plaintext, pubkey_path='public.pem'):
    with open(pubkey_path, 'rb') as f:
        pubkey = RSA.import_key(f.read())
    cipher = PKCS1_v1_5.new(pubkey)
    ciphertext = cipher.encrypt(plaintext.encode('utf-8'))
    return base64.b64encode(ciphertext).decode('utf-8')

def ling_encrypt(text, pubkey_path='public.pem'):
    encrypted = encrypt_with_public_key(text, pubkey_path)
    return encrypted