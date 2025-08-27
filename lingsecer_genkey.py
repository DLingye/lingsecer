from nacl.public import PrivateKey
from nacl.signing import SigningKey
import base64

import lingsecer_metadata

MAINAME = lingsecer_metadata.MAINAME
VERSION = lingsecer_metadata.VERSION
AUTHOR = lingsecer_metadata.AUTHOR
EMAIL = lingsecer_metadata.EMAIL

def deterministic_cv25519_key():
    # 生成 cv25519 (X25519) 私钥
    sk = PrivateKey.generate()
    pk = sk.public_key

    sk_raw = bytes(sk)   # 32 字节
    pk_raw = bytes(pk)   # 32 字节

    return sk_raw, pk_raw

def ed25519_keypair():
    """生成 ed25519 密钥对"""
    signing_key = SigningKey.generate()
    verify_key = signing_key.verify_key
    
    sk_raw = bytes(signing_key)  # 32 字节
    pk_raw = bytes(verify_key)   # 32 字节
    
    return sk_raw, pk_raw

def ling_genkey(algo=None, key_length=None):
    # 生成 cv25519 密钥对
    cv_priv, cv_pub = deterministic_cv25519_key()
    # 生成 ed25519 密钥对
    ed_priv, ed_pub = ed25519_keypair()
    
    # 使用 Base85 编码输出
    cv_priv_b85 = base64.b85encode(cv_priv).decode("latin1")
    cv_pub_b85 = base64.b85encode(cv_pub).decode("latin1")
    ed_priv_b85 = base64.b85encode(ed_priv).decode("latin1")
    ed_pub_b85 = base64.b85encode(ed_pub).decode("latin1")
    
    return {
        "cv25519": (cv_priv_b85, cv_pub_b85),
        "ed25519": (ed_priv_b85, ed_pub_b85)
    }
