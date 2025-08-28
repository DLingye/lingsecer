import os
import json
import base64
from Crypto.Cipher import AES
import hashlib
import datetime, time

from lingsecer_encrypt import ling_encrypt, ling_decrypt
from lingsecer_localkey import import_key, list_key, del_key, load_key, export_key
from lingsecer_todata import key_to_json
from lingsecer_compress import compress_data, decompress_data
from lingsecer_sign import ling_sign, ling_vsign
from lingsecer_cv25519 import gen_cv25519
from lingsecer_ed25519 import gen_ed25519
import lingsecer_metadata

MAINAME = lingsecer_metadata.MAINAME
VERSION = lingsecer_metadata.VERSION
AUTHOR = lingsecer_metadata.AUTHOR
EMAIL = lingsecer_metadata.EMAIL

l_time = datetime.datetime.now().strftime("%Y-%m-%d_%H:%M:%S")
timezone = time.strftime('%Z', time.localtime())

def encrypted_file_to_data(plaintext_file, ciphertext):
    output_json = plaintext_file + ".lsed"
    time=timezone+'_'+l_time
    lfid = hashlib.sha512(ciphertext if isinstance(ciphertext, bytes) else ciphertext.encode('utf-8')).hexdigest().upper()
    out_data = {
        "version": VERSION,
        "lfid": lfid,
        "plaintext_file": plaintext_file,
        "time": time,
        "mode": "encrypt",
        "ciphertext": base64.b64encode(ciphertext).decode('utf-8') if isinstance(ciphertext, bytes) else ciphertext
    }
    json_str = json.dumps(out_data, ensure_ascii=False, indent=4)
    compressed = compress_data(json_str)
    with open(output_json, "wb") as f:
        f.write(compressed)
    print("OK.")

def aes_encrypt(data, password):
    key = password.encode('utf-8')
    key = key[:32].ljust(32, b'\0')  # AES-256
    cipher = AES.new(key, AES.MODE_GCM)
    nonce = cipher.nonce  # 12字节随机IV
    ct_bytes, tag = cipher.encrypt_and_digest(data.encode('utf-8'))
    # 拼接 nonce + tag + ciphertext，均为base64编码后用“:”分隔，返回单一字符串
    result = (
        base64.b64encode(nonce).decode('utf-8') + ":" +
        base64.b64encode(tag).decode('utf-8') + ":" +
        base64.b64encode(ct_bytes).decode('utf-8')
    )
    return result

def aes_decrypt(enc_data, password):
    key = password.encode('utf-8')
    key = key[:32].ljust(32, b'\0')
    try: # 拆分字符串
        nonce_b64, tag_b64, ct_b64 = enc_data.split(":")
        nonce = base64.b64decode(nonce_b64)
        tag = base64.b64decode(tag_b64)
        ct = base64.b64decode(ct_b64)
    except Exception:
        raise ValueError("ErrBadFormat")
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    return cipher.decrypt_and_verify(ct, tag).decode('utf-8')

def text_to_base64(s):
    sha256 = hashlib.sha256(s.encode('utf-8')).digest()
    return base64.b64encode(sha256).decode('utf-8')

def ling_genkey(crypt_algo:str=None, sign_algo:str=None, key_length:int=None) -> dict:
    result = {}
    
    if crypt_algo is None or crypt_algo == "cv25519":
        cv_priv_b85, cv_pub_b85 = gen_cv25519(True)
        result["cv25519"] = (cv_priv_b85, cv_pub_b85)
    
    if sign_algo is None or sign_algo == "ed25519":
        ed_priv_b85, ed_pub_b85 = gen_ed25519(True)
        result["ed25519"] = (ed_priv_b85, ed_pub_b85)
    
    return result

def gen_key():
    from lingsecer_metadata import (
        CRYPT_ALGO,
        SIGN_ALGO
    )
    # 加密算法选择
    print("\n可用的加密算法:")
    for i, algo in enumerate(CRYPT_ALGO, 1):
        print(f"{i}. {algo}")
    crypt_choice = input(f"选择加密算法 (1-{len(CRYPT_ALGO)}, 默认1): ").strip()
    crypt_algo = CRYPT_ALGO[int(crypt_choice)-1] if crypt_choice else "cv25519"
    # 签名算法选择
    print("\n可用的签名算法:")
    for i, algo in enumerate(SIGN_ALGO, 1):
        print(f"{i}. {algo}")
    sign_choice = input(f"选择签名算法 (1-{len(SIGN_ALGO)}, 默认1): ").strip()
    sign_algo = SIGN_ALGO[int(sign_choice)-1] if sign_choice else "ed25519"

    username = os.getlogin()
    owner_name = input("\nName (default {}):".format(username)).strip()
    if owner_name == "":
        owner_name = username
    owner_mail = input("Email:").strip()
    comment = input("Comment:").strip()

    key_pairs = ling_genkey('cv25519', 'ed25519', None)
    cv_priv, cv_pub = key_pairs["cv25519"]
    ed_priv, ed_pub = key_pairs["ed25519"]
    
    password = input("Passphrase (leave empty for no encryption):").strip()
    if password:
        password = text_to_base64(password)
        cv_priv = aes_encrypt(cv_priv, password)
        ed_priv = aes_encrypt(ed_priv, password)
        priv_encrypted = True
    else:
        priv_encrypted = False
    j_data = key_to_json(owner_name, owner_mail, comment, crypt_algo=crypt_algo, sign_algo=sign_algo, mode='encrypt sign',
           time=timezone+'_'+l_time, priv_encrypted=priv_encrypted, 
           pub_key=cv_pub, priv_key=cv_priv, pub_sign=ed_pub, priv_sign=ed_priv, crypt_key_length=256, sign_key_length=256)
    # 直接导入密钥库
    out = import_key(j_data)
    if out == "ErrFileNotFound":
        print("ErrFileNotFound")
    elif out == "ErrKeyAlreadyExists":
        print("ErrKeyAlreadyExists")
    else:
        output = out[0]
        #idx0, key_lkid1, key_lkid_short2, key_name3, key_email4, key_comment5, crypt_algo6, crypt_key_length7, sign_algo8, sign_key_length9, key_date10
        print(str(output[0])+". "+output[1]+"\n"+output[2]+" "+output[6]+"_"+str(output[7])+":"+output[8]+"_"+str(output[9])+"\n"+output[10]+"\n"+output[3]+" <"+output[4]+"> "+"\n"+output[5])

def decrypt_key():
    json_filename = input("File to decrypt (leave empty to use local key):").strip()
    if json_filename:
        with open(json_filename, "r", encoding="utf-8") as f:
            data = json.load(f)
    else:
        # 未指定文件，要求输入本地密钥库的lkid/lkid_short/name
        lkid = input("Input lkid (leave empty to skip):").strip()
        lkid_short = input("Input lkid_short (leave empty to skip):").strip()
        name = input("Input name (leave empty to skip):").strip()
        data = load_key(lkid=lkid, lkid_short=lkid_short, name=name)
        if data in ("NoLocalKeyFile", "NoLocalKey", "ErrNoMatchKey"):
            print(data)
            return
    priv_encrypted = data.get("priv_encrypted", False)
    priv_key = data.get("priv_key", "")
    pub_key = data.get("pub_key", "")
    if priv_encrypted:
        password = input("Passphrase for private key:").strip()
        password = text_to_base64(password)
        try:
            priv_key = aes_decrypt(priv_key, password)
            print(pub_key)
            print("Decrypted private key:")
            print(priv_key)
        except Exception as e:
            print("Err, password may be incorrect.")

def encrypt_file():
    key_identifier = input("Input key identifier (lkid/lkid_short/name):").strip()
    if not key_identifier:
        print("Key identifier cannot be empty")
        return
    data = None
    if len(key_identifier) == 64:
        data = load_key(lkid=key_identifier)
        if data in ("NoLocalKeyFile", "NoLocalKey", "ErrNoMatchKey"):
            if len(key_identifier) == 16:
                data = load_key(lkid_short=key_identifier)
                if data in ("NoLocalKeyFile", "NoLocalKey", "ErrNoMatchKey"):
                    data = load_key(name=key_identifier)
    else:
        data = load_key(name=key_identifier)
    if data in ("NoLocalKeyFile", "NoLocalKey", "ErrNoMatchKey"):
        print(data)
        return
    if not data:
        print("No key found.")
        return
    pub_key = data.get("pub_key", "")
    if not pub_key:
        print("ErrPubkeyNotFound")
        return
    plaintext_file = input("File to encrypt:").strip()
    with open(plaintext_file, "rb") as f:
        plaintext = f.read()
    lkid = data.get("lkid", "")
    ciphertext = ling_encrypt(plaintext, pub_key, lkid)
    compressed_ciphertext = compress_data(ciphertext)
    print(compressed_ciphertext)
    encrypted_file_to_data(plaintext_file, compressed_ciphertext)

def decrypt_file():
    ciphertext_json = input("File containing ciphertext:").strip()
    if ciphertext_json.endswith('.lsed'):
        with open(ciphertext_json, "rb") as f:
            compressed_data = f.read()
        json_str = decompress_data(compressed_data)
        cipher_data = json.loads(json_str)
    else:
        print("ErrBadFormat")
        return
    ciphertext_compressed = cipher_data.get("ciphertext", "")
    ciphertext_b64 = decompress_data(ciphertext_compressed)
    plaintext_file = cipher_data.get("plaintext_file", "")
    if not ciphertext_b64 or not plaintext_file:
        print("ErrCiphertextOrPlaintextFileNotFound")
        return
    parts = ciphertext_b64.split(':::')
    if len(parts) != 5:
        raise ValueError("无效的加密数据格式")
    lkid, encrypted_aes_key, nonce_b64, tag_b64, ciphertext_b64 = parts
    key_data = load_key(lkid=lkid)
    priv_encrypted = key_data.get("priv_encrypted", False)
    priv_key = key_data.get("priv_key", "")
    if key_data in ("NoLocalKeyFile", "NoLocalKey", "ErrNoMatchKey"):
        print(key_data)
        return
    if priv_encrypted:
        password = input("Passphrase for private key:").strip()
        password = text_to_base64(password)
        try:
            priv_key = aes_decrypt(priv_key, password)
            if not priv_key:
                print("ErrPrivkeyNotFound")
                return

        except Exception as e:
            print("Err, password may be incorrect.")
            return
    try:
        plaintext = ling_decrypt(encrypted_aes_key, nonce_b64, tag_b64, ciphertext_b64, privkey_b85=priv_key)
        print("Decryption result:")
        print(plaintext)
        with open(plaintext_file, "wb") as f:
            f.write(plaintext)
        print(f"OK.")
    except Exception as e:
        print("ErrDecryptFailed", e)

def local_key(command):
    if command == "import":
        key_file = input("Import from:").strip()
        if os.path.isfile(key_file):
            with open(key_file, "r", encoding="utf-8") as f:
                key_data = json.load(f)
        else:
            print("ErrFileNotFound")
            return
        out=import_key(key_data)
        if out == "ErrFileNotFound":
            return "ErrFileNotFound"
        elif out == "ErrKeyAlreadyExists":
            return "ErrKeyAlreadyExists"
        else:
            output=out[0]
            #idx0, key_lkid1, key_lkid_short2, key_name3, key_email4, key_comment5, crypt_algo6, crypt_key_length7, sign_algo8, sign_key_length9, key_date10
            print(str(output[0])+". "+output[1]+"\n"+output[2]+" "+output[6]+"_"+str(output[7])+":"+output[8]+"_"+str(output[9])+"\n"+output[10]+"\n"+output[3]+" <"+output[4]+"> "+"\n"+output[5])
    elif command == "list":
        out=list_key()
        if out == "NoLocalKeyFile":
            return "NoLocalKeyFile"
        elif out == "NoLocalKey":
            return "NoLocalKey"
        elif out == "ErrNoMatchKey":
            return "ErrNoMatchKey"
        else:
            result = []
            for output in out:
                #idx0, key_lkid1, key_lkid_short2, key_name3, key_email4, key_comment5, crypt_algo6, crypt_key_length7, sign_algo8, sign_key_length9, key_date10
                print(str(output[0])+". "+output[1]+"\n"+output[2]+" "+output[6]+"_"+str(output[7])+":"+output[8]+"_"+str(output[9])+"\n"+output[10]+"\n"+output[3]+" <"+output[4]+"> "+"\n"+output[5])
    elif command == "del":
        key_identifier = input("Input key identifier (lkid/lkid_short/name):").strip()
        if not key_identifier:
            print("Key identifier cannot be empty")
            return
        elif len(key_identifier) == 64:
            out=del_key(lkid=key_identifier)
        elif len(key_identifier) == 16:
            out=del_key(lkid_short=key_identifier)
        else:
            out=del_key(name=key_identifier)
        
        if out == "NoLocalKeyFile":
            return "NoLocalKeyFile"
        elif out == "NoLocalKey":
            return "NoLocalKey"
        elif out == "ErrNoMatchKey":
            return "ErrNoMatchKey"
        elif out == 0:
            print("OK.")
    else:
        return "ErrBadCommand"
    
def exportkey(cmd):
    parts = cmd.split()
    if len(parts) != 3:
        print("Usage: outkey [pub/priv] [lkid/lkid_short/name]")
        return
    elif len(parts) == 3:
        mode = parts[1]
        identifier = parts[2]
        if mode not in ("pub", "priv"):
            print("ErrBadMode: must be 'pub' or 'priv'")
            return
    result = export_key(mode, identifier)
    if result.startswith("Err"):
        print(result)
    else:
        print(f"OK. Key exported to {result}")

def sign_file():
    """处理签名命令"""
    key_identifier = input("Input key identifier (lkid/lkid_short/name):").strip()
    data = None
    if len(key_identifier) == 64:
        data = load_key(lkid=key_identifier)
    elif len(key_identifier) == 16:
        data = load_key(lkid_short=key_identifier)
    else:
        data = load_key(name=key_identifier)
    if data in ("NoLocalKeyFile", "NoLocalKey", "ErrNoMatchKey"):
        print(data)
        return
    if not data:
        print("No key found.")
        return
    
    lkid = data.get("lkid", "")
    priv_encrypted = data.get("priv_encrypted", False)
    priv_key = data.get("priv_sign", "")
    if priv_encrypted:
        password = input("Passphrase for private key:").strip()
        password = text_to_base64(password)
        try:
            priv_key = aes_decrypt(priv_key, password)
        except:
            print("ErrBadPassphrase")
            return
    
    from pathlib import Path
    filename = input("File to sign:").strip()
    file_path = Path(filename)
    file_data = file_path.read_bytes()
    try:
        sign_data = ling_sign(filename, file_data, lkid, priv_key)
        # 写入签名文件
        sign_filename = filename + "_sign.lssd"
        with open(sign_filename, "w", encoding="utf-8") as f:
            json.dump(sign_data, f, ensure_ascii=False, indent=2)
        print(f"Signature saved to: {sign_filename}")
    except Exception as e:
        print(f"ErrSignFailed: {str(e)}")

def verify_sign():
    """处理验证签名命令"""
    filename = input("File to verify:").strip()
    if not filename:
        print("File cannot be empty")
        return
    from pathlib import Path
    file_path = Path(filename)
    data = file_path.read_bytes()
    
    try:
        valid, name = ling_vsign(data, filename)
        if valid:
            print(f"Good Signature from {name}")
        else:
            print(f"Signature verification failed")
    except Exception as e:
        print(f"ErrVerifyFailed: {str(e)}")

def main():
    print(MAINAME+" Ver "+VERSION)
    while True:
        cmd = input("lingsecer>").strip().lower()
        if cmd == "quit" or cmd == "exit":
            print("Bye!")
            break
        elif cmd == "genkey":
            gen_key()
        elif cmd == "encrypt":
            encrypt_file()
        elif cmd == "decrypt":
            decrypt_file()
        elif cmd == "import":
            local_key("import")
        elif cmd == "list":
            local_key("list")
        elif cmd == "del":
            local_key("del")
        elif cmd.startswith("export"):
            exportkey(cmd)
        elif cmd == "sign":
            sign_file()
        elif cmd == "vsign":
            verify_sign()
        elif cmd == "ling":
            import ling
            ling.main()
        else:
            print("ErrCommandNotFound")

if __name__ == "__main__":
    main()