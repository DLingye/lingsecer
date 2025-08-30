from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from nacl.public import PrivateKey, PublicKey, SealedBox
import base64

import lingsecer_metadata

MAINAME = lingsecer_metadata.MAINAME
VERSION = lingsecer_metadata.VERSION
AUTHOR = lingsecer_metadata.AUTHOR
EMAIL = lingsecer_metadata.EMAIL


def encrypt_with_public_key(plaintext: bytes, pubkey_b85: str) -> str:
    """用 cv25519 公钥加密数据 (SealedBox)，返回 Base85"""
    try:
        pubkey_raw = base64.b85decode(pubkey_b85.encode("utf-8"))
        pubkey = PublicKey(pubkey_raw)
        encrypt_box = SealedBox(pubkey)
        ciphertext = encrypt_box.encrypt(plaintext)
        return base64.b85encode(ciphertext).decode("utf-8")
    except base64.binascii.Error as e:
        print(f"Base85 decoding error in public key: {e}")
        return ""
    except Exception as e:
        print(f"Unexpected error during public key encryption: {e}")
        return ""


def decrypt_with_private_key(ciphertext_b85: str, privkey_b85: str) -> bytes:
    """用 cv25519 私钥解密数据 (SealedBox)，返回原始字节"""
    try:
        privkey_raw = base64.b85decode(privkey_b85.encode("utf-8"))
        privkey = PrivateKey(privkey_raw)
        decrypt_box = SealedBox(privkey)
        ciphertext = base64.b85decode(ciphertext_b85.encode("utf-8"))
        plaintext = decrypt_box.decrypt(ciphertext)
        return plaintext
    except base64.binascii.Error as e:
        print(f"Base85 decoding error in private key or ciphertext: {e}")
        return b""
    except Exception as e:
        print(f"Unexpected error during private key decryption: {e}")
        return b""


def ling_encrypt(file_data: bytes, pubkey_b85: str, lkid: str) -> str:
    """主加密函数：AES-GCM + cv25519 封装的 AES key"""
    try:
        # 生成随机的256位(32字节)AES密钥
        aes_key = get_random_bytes(32)

        # 使用AES-256-GCM加密文件内容
        cipher = AES.new(aes_key, AES.MODE_GCM)
        ciphertext, tag = cipher.encrypt_and_digest(file_data)

        # 使用cv25519公钥加密AES密钥（AES密钥先直接加密，不需要再转base85）
        encrypted_aes_key = encrypt_with_public_key(aes_key, pubkey_b85)
        if not encrypted_aes_key:
            raise ValueError("Failed to encrypt AES key with public key")

        # 拼接加密后的数据
        return f"{lkid}:::{encrypted_aes_key}:::{base64.b85encode(cipher.nonce).decode()}:::{base64.b85encode(tag).decode()}:::{base64.b85encode(ciphertext).decode()}"
    except Exception as e:
        print(f"Error during encryption: {e}")
        return ""


def ling_decrypt(encrypted_aes_key_b85: str, nonce_b85: str, tag_b85: str,
                 ciphertext_b85: str, privkey_b85: str) -> bytes:
    """解密函数：还原AES密钥 -> 解密文件内容"""
    try:
        # 解密AES密钥
        aes_key = decrypt_with_private_key(encrypted_aes_key_b85, privkey_b85)
        if not aes_key:
            raise ValueError("Failed to decrypt AES key")

        # 解码各部分
        nonce = base64.b85decode(nonce_b85.encode("utf-8"))
        tag = base64.b85decode(tag_b85.encode("utf-8"))
        ciphertext = base64.b85decode(ciphertext_b85.encode("utf-8"))

        # 使用AES解密文件内容
        cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
        decrypted_data = cipher.decrypt_and_verify(ciphertext, tag)
        return decrypted_data
    except base64.binascii.Error as e:
        print(f"Base85 decoding error in ciphertext, tag, or nonce: {e}")
        return b""
    except ValueError as e:
        print(f"ValueError: {e}")
        return b""
    except Exception as e:
        print(f"Unexpected error during decryption: {e}")
        return b""
