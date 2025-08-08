MAINAME = "LingSecer_Encrypt"
VERSION = "250808"
AUTHOR = "DONGFANG Lingye"
EMAIL = "ly@lingye.online"

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
#from Crypto.Hash import SHA256
import base64

def encrypt_with_public_key(plaintext, pubkey_str):
    pubkey = RSA.import_key(pubkey_str)
    cipher = PKCS1_OAEP.new(pubkey)
    ciphertext = cipher.encrypt(plaintext.encode('utf-8'))
    return base64.b64encode(ciphertext).decode('utf-8')

def decrypt_with_private_key(ciphertext_b64, privkey_str):
    privkey = RSA.import_key(privkey_str)
    cipher = PKCS1_OAEP.new(privkey)
    ciphertext = base64.b64decode(ciphertext_b64)
    sentinel = b'error'
    plaintext = cipher.decrypt(ciphertext)
    if plaintext == sentinel:
        raise ValueError("解密失败，私钥不匹配或数据损坏")
    return plaintext.decode('utf-8')

def ling_encrypt(file_text, pubkey_str, key_length=1024):
    #先计算RSA密钥位数，如果为1024位，则每块明文最大长度为62字节，如果为2048位，明文最大190字节，如果为3072位，明文最大318字节，如果为4096位，明文最大378字节，
    #计算公钥位数
    key_length_bytes = key_length // 8
    chunk_size = key_length_bytes - 2*20 - 60  # 减去两个SHA256哈希的长度和填充
    print(chunk_size)
    #chunk_size = 40
    encrypted_chunks = []
    for i in range(0, len(file_text), chunk_size):
        chunk = file_text[i:i+chunk_size]
        encrypted_chunk = encrypt_with_public_key(chunk, pubkey_str)
        encrypted_chunks.append(encrypted_chunk)
    # 用特殊分隔符拼接
    return ':::'.join(encrypted_chunks)

def ling_decrypt(ciphertext_b64, privkey_str):
    decrypted_chunks = []
    for enc_chunk in ciphertext_b64.split(':::'):
        if not enc_chunk:
            continue
        decrypted_chunk = decrypt_with_private_key(enc_chunk, privkey_str)
        decrypted_chunks.append(decrypted_chunk)
    return ''.join(decrypted_chunks)
