from nacl.signing import SigningKey
import base64

def gen_ed25519(encode_b85=True):
    """Generate ed25519 key pair"""
    signing_key = SigningKey.generate()
    verify_key = signing_key.verify_key
    
    sk_raw = bytes(signing_key)  # 32 bytes
    pk_raw = bytes(verify_key)   # 32 bytes
    
    if encode_b85:
        ed_priv_b85 = base64.b85encode(sk_raw).decode("latin1")
        ed_pub_b85 = base64.b85encode(pk_raw).decode("latin1")
        return ed_priv_b85, ed_pub_b85
    elif not encode_b85:
        return sk_raw, pk_raw
