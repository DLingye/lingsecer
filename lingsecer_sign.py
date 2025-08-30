import base64
import json
from nacl.signing import SigningKey, VerifyKey

import lingsecer_metadata
from lingsecer_localkey import load_key

MAINAME = lingsecer_metadata.MAINAME
VERSION = lingsecer_metadata.VERSION
AUTHOR = lingsecer_metadata.AUTHOR
EMAIL = lingsecer_metadata.EMAIL

def ling_sign(file_name: str, file_data: bytes, lkid: str, ed_priv_b85: str) -> dict:
    """对文件内容进行 Ed25519 签名，生成分离签名 JSON 文件"""
    try:
        # 还原私钥
        privkey_raw = base64.b85decode(ed_priv_b85.encode("utf-8"))
        signing_key = SigningKey(privkey_raw)
        # 签名
        signed = signing_key.sign(file_data)
        signature = signed.signature  # 64字节签名

        # Base85 编码签名
        signature_b85 = base64.b85encode(signature).decode("utf-8")

        # 生成签名数据 JSON
        sign_data = {
            "version": VERSION,
            "lkid": lkid,
            "filename": file_name,
            "signature": signature_b85,
        }

        return sign_data

    except ValueError as e:
        print(f"Error in signing data: {e}")
        return {"error": f"Error in signing data: {e}"}
    except base64.binascii.Error as e:
        print(f"Error in base85 decoding the private key: {e}")
        return {"error": f"Error in base85 decoding the private key: {e}"}
    except Exception as e:
        print(f"Unexpected error during signing: {e}")
        return {"error": f"Unexpected error during signing: {e}"}


def ling_vsign(data: bytes, filename: str) -> bool:
    """验证文件内容与签名文件是否匹配"""
    try:
        # 读取签名文件
        sign_filename = filename + "_sign.lssd"
        try:
            with open(sign_filename, "r", encoding="utf-8") as f:
                sig_data = json.load(f)

            signature = base64.b85decode(sig_data["signature"].encode("utf-8"))
            lkid = sig_data["lkid"]

            # 加载公钥
            key_data = load_key(lkid=str(lkid))
            if key_data in ("NoLocalKeyFile", "NoLocalKey", "ErrNoMatchKey"):
                print(f"Error: {key_data}")
                return False, ""

            pubkey_b85 = key_data.get("pub_sign", "")
            if not pubkey_b85:
                raise ValueError(f"Public key not found for lkid: {lkid}")

            pubkey_raw = base64.b85decode(pubkey_b85.encode("utf-8"))

            # 验证签名
            verify_key = VerifyKey(pubkey_raw)
            verify_key.verify(data, signature)

            # 返回验证结果和签名者姓名
            name = key_data.get("name", "")
            return True, name

        except FileNotFoundError:
            print(f"Error: Signature file '{sign_filename}' not found.")
            return False, ""
        except json.JSONDecodeError:
            print(f"Error: Failed to parse JSON from the signature file '{sign_filename}'.")
            return False, ""
        except base64.binascii.Error:
            print("Error: Invalid base85 encoded signature.")
            return False, ""
        except ValueError as e:
            print(f"Error: {e}")
            return False, ""
        except Exception as e:
            print(f"Unexpected error during signature verification: {e}")
            return False, ""

    except Exception as e:
        print(f"Unexpected error during signature verification: {e}")
        return False, ""
