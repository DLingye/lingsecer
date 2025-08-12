MAINAME = "LingSecer_Encrypt"
VERSION = "250812"
AUTHOR = "DONGFANG Lingye"
EMAIL = "ly@lingye.online"

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Random import get_random_bytes
import base64

def encrypt_with_public_key(plaintext, pubkey_str):
    pubkey = RSA.import_key(pubkey_str)
    cipher = PKCS1_OAEP.new(pubkey)
    ciphertext = cipher.encrypt(plaintext.encode('utf-8'))
    return base64.b85encode(ciphertext).decode('utf-8')

def decrypt_with_private_key(ciphertext_b64, privkey_str):
    privkey = RSA.import_key(privkey_str)
    cipher = PKCS1_OAEP.new(privkey)
    ciphertext = base64.b85decode(ciphertext_b64.encode('utf-8'))
    sentinel = b'error'
    plaintext = cipher.decrypt(ciphertext)
    if plaintext == sentinel:
        raise ValueError("解密失败，私钥不匹配或数据损坏")
    return plaintext.decode('utf-8')

def ling_encrypt(file_data, pubkey_str):
    # 生成随机的256位(32字节)AES密钥
    aes_key = get_random_bytes(32)
    # 使用AES-256加密文件内容
    cipher = AES.new(aes_key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(file_data)  # 直接处理二进制数据
    # 使用RSA公钥加密AES密钥
    encrypted_aes_key = encrypt_with_public_key(base64.b85encode(aes_key).decode('utf-8'), pubkey_str)
    # 组合加密后的数据：encrypted_aes_key:::nonce:::tag:::ciphertext
    return f"{encrypted_aes_key}:::{base64.b85encode(cipher.nonce).decode('utf-8')}:::{base64.b85encode(tag).decode('utf-8')}:::{base64.b85encode(ciphertext).decode('utf-8')}"


def ling_decrypt(ciphertext_b64, privkey_str):
    # 分离加密后的数据
    parts = ciphertext_b64.split(':::')
    if len(parts) != 4:
        raise ValueError("无效的加密数据格式")
    encrypted_aes_key, nonce_b64, tag_b64, ciphertext_b64 = parts
    # 使用RSA私钥解密AES密钥
    aes_key_b64 = decrypt_with_private_key(encrypted_aes_key, privkey_str)
    aes_key = base64.b85decode(aes_key_b64)
    nonce = base64.b85decode(nonce_b64)
    tag = base64.b85decode(tag_b64)
    ciphertext = base64.b85decode(ciphertext_b64)
    # 使用AES解密文件内容
    cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
    decrypted_data = cipher.decrypt_and_verify(ciphertext, tag)
    return decrypted_data  # 直接返回二进制数据


