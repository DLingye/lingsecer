import base64
import json
from nacl.signing import SigningKey, VerifyKey
from pathlib import Path

import lingsecer_metadata
from lingsecer_localkey import load_key

MAINAME = lingsecer_metadata.MAINAME
VERSION = lingsecer_metadata.VERSION
AUTHOR = lingsecer_metadata.AUTHOR
EMAIL = lingsecer_metadata.EMAIL

def ling_sign(file_name:str, file_data: bytes, lkid:str, ed_priv_b85: str) -> str:
    """对文件内容进行 Ed25519 签名，生成分离签名 JSON 文件"""
    # 还原私钥
    privkey_raw = base64.b85decode(ed_priv_b85.encode("utf-8"))
    signing_key = SigningKey(privkey_raw)
    verify_key = signing_key.verify_key
    # 签名
    signed = signing_key.sign(file_data)
    signature = signed.signature  # 64字节签名
    # Base85 编码
    signature_b85 = base64.b85encode(signature).decode("utf-8")
    #pubkey_b85 = base64.b85encode(bytes(verify_key)).decode("utf-8")
    # 生成 JSON 数据
    sign_data = {
        "version": VERSION,
        "lkid": lkid,
        "filename": file_name,
        "signature": signature_b85,
    }

    return sign_data


def ling_vsign(data:bytes, filename:str) -> bool:
    """验证文件内容与签名文件是否匹配"""
    # 读取签名文件
    sign_filename = filename + "_sign.lssd"
    try:
        with open(sign_filename, "r", encoding="utf-8") as f:
            sig_data = json.load(f)

        signature = base64.b85decode(sig_data["signature"].encode("utf-8"))
        lkid = sig_data["lkid"]
        key_data = load_key(lkid=str(lkid))
        pubkey_b85 = key_data.get("pub_sign", "")
        pubkey_raw = base64.b85decode(pubkey_b85.encode("utf-8"))

        # 验证签名
        verify_key = VerifyKey(pubkey_raw)
        verify_key.verify(data, signature)

        name = key_data.get("name", "")
        verify = True
        return verify, name
    except Exception:
        return False, ""
