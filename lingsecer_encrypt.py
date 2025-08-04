from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5
import base64

__mainame__ = "LingSecer_Encrypt"
__version__ = "250804"
__author__ = "DONGFANG Lingye"
__email__ = "ly@lingye.online"

def encrypt_with_public_key(plaintext, pubkey_str):
    pubkey = RSA.import_key(pubkey_str)
    cipher = PKCS1_v1_5.new(pubkey)
    ciphertext = cipher.encrypt(plaintext.encode('utf-8'))
    return base64.b64encode(ciphertext).decode('utf-8')

def decrypt_with_private_key(ciphertext_b64, privkey_str):
    privkey = RSA.import_key(privkey_str)
    cipher = PKCS1_v1_5.new(privkey)
    ciphertext = base64.b64decode(ciphertext_b64)
    sentinel = b'error'
    plaintext = cipher.decrypt(ciphertext, sentinel)
    if plaintext == sentinel:
        raise ValueError("解密失败，私钥不匹配或数据损坏")
    return plaintext.decode('utf-8')

def ling_encrypt(file_text, pubkey_str):
    encrypted_text = encrypt_with_public_key(file_text, pubkey_str)
    return encrypted_text

def ling_decrypt(ciphertext_b64, privkey_str):
    try:
        decrypted_text = decrypt_with_private_key(ciphertext_b64, privkey_str)
    except Exception as e:
        print("解密失败：", e)
    return decrypted_text
