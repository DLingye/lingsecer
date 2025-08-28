from nacl.public import PrivateKey
import base64

def gen_cv25519(encode_b85=True):
    """Generate cv25519 (X25519) key pair"""
    sk = PrivateKey.generate()
    pk = sk.public_key

    sk_raw = bytes(sk)   # 32 bytes
    pk_raw = bytes(pk)   # 32 bytes

    if encode_b85:
        cv_priv_b85 = base64.b85encode(sk_raw).decode("latin1")
        cv_pub_b85 = base64.b85encode(pk_raw).decode("latin1")
        return cv_priv_b85, cv_pub_b85
    elif not encode_b85:
        return sk_raw, pk_raw

