from nacl.public import PrivateKey
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

def ling_genkey(algo=None, key_length=None):
    priv_key, pub_key = deterministic_cv25519_key()
    # 使用 Base85 编码输出，latin1 保证可逆
    priv_b85 = base64.b85encode(priv_key).decode("latin1")
    pub_b85 = base64.b85encode(pub_key).decode("latin1")
    return priv_b85, pub_b85
