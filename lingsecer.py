MAINAME = "LingSecer"
VERSION = "250812"
AUTHOR = "DONGFANG Lingye"
EMAIL = "ly@lingye.online"

import os
import json
import base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import hashlib

from lingsecer_seed import gen_seed
from lingsecer_genkey import ling_genkey
from lingsecer_encrypt import ling_encrypt, ling_decrypt
from lingsecer_localkey import import_key, list_key, del_key, load_key
from lingsecer_todata import key_to_json, encrypted_file_to_data
import lingsecer_gettime
from lingsecer_compress import compress_data, decompress_data

l_time = lingsecer_gettime.l_time
timezone = lingsecer_gettime.timezone

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
    key = key[:32].ljust(32, b'\0')  # AES-256
    # 拆分字符串
    try:
        nonce_b64, tag_b64, ct_b64 = enc_data.split(":")
        nonce = base64.b64decode(nonce_b64)
        tag = base64.b64decode(tag_b64)
        ct = base64.b64decode(ct_b64)
    except Exception:
        raise ValueError("Invalid encrypted data format")
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    return cipher.decrypt_and_verify(ct, tag).decode('utf-8')

def text_to_base64(s):
    sha256 = hashlib.sha256(s.encode('utf-8')).digest()
    return base64.b64encode(sha256).decode('utf-8')

def gen_key():
    username = os.getlogin()
    owner_name = input("Name (default {}):".format(username)).strip()
    if owner_name == "":
        owner_name = username
    owner_mail = input("Email:").strip()
    comment = input("Comment:").strip()
    phrase = input("Seed phrase:").strip()
    strength = input("Key strength (1-64, default 64):").strip()
    key_strength = input("RSA Key strength (default 4096):").strip()
    if not key_strength.isdigit() or not (1024 <= int(key_strength) <= 16384) or key_strength == "":
        key_strength = "4096"
    key_strength = int(key_strength)
    if not strength.isdigit() or not (1 <= int(strength) <= 64) or strength == "":
        strength = "64"
    if phrase == "":
        # 留空则生成随机密钥
        priv, pub = ling_genkey(None, key_strength)
        print("Private_Key:")
        print(priv)
        print("Public_Key:")
        print(pub)
    else:
        ins = phrase + " " + "2-" + strength
        result = gen_seed(ins)
        priv, pub = ling_genkey(result[-2], key_strength)
        print("Private_Key:")
        print(priv)
        print("Public_Key:")
        print(pub)
    password = input("Passphrase (leave empty for no encryption):").strip()
    if password:
        password = text_to_base64(password)
        priv = aes_encrypt(priv, password)
        priv_encrypted = True
    else:
        priv_encrypted = False
    j_data = key_to_json(owner_name, owner_mail, comment, mode='encrypt', 
           time=timezone+'_'+l_time, priv_encrypted=priv_encrypted, 
           pub_key=pub, priv_key=priv, key_length=key_strength)
    # 直接导入密钥库
    out = import_key(j_data)
    if out == "ErrFileNotFound":
        print("ErrFileNotFound")
    elif out == "ErrKeyAlreadyExists":
        print("ErrKeyAlreadyExists")
    else:
        output = out[0]
        print(str(output[0])+" "+output[1]+"\n"+output[2]+" "+str(output[7])+"\n"+output[3]+" <"+output[4]+"> "
              +" "+output[5]+"\n"+output[6])

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
    lkid = input("Input lkid (leave empty to skip):").strip()
    lkid_short = input("Input lkid_short (leave empty to skip):").strip()
    name = input("Input name (leave empty to skip):").strip()
    data = load_key(lkid=lkid, lkid_short=lkid_short, name=name)
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
    ciphertext = ling_encrypt(plaintext, pub_key)
    compressed_ciphertext = compress_data(ciphertext)
    print(compressed_ciphertext)
    encrypted_file_to_data(plaintext_file, compressed_ciphertext)

def decrypt_file():
    lkid = input("Input lkid (leave empty to skip):").strip()
    lkid_short = input("Input lkid_short (leave empty to skip):").strip()
    name = input("Input name (leave empty to skip):").strip()
    data = load_key(lkid=lkid, lkid_short=lkid_short, name=name)
    if data in ("NoLocalKeyFile", "NoLocalKey", "ErrNoMatchKey"):
        print(data)
        return
    priv_encrypted = data.get("priv_encrypted", False)
    priv_key = data.get("priv_key", "")
    if priv_encrypted:
        password = input("Passphrase for private key:").strip()
        password = text_to_base64(password)
        try:
            priv_key = aes_decrypt(priv_key, password)
        except Exception as e:
            print("Err, password may be incorrect.")
            return
    if not priv_key:
        print("ErrPrivkeyNotFound")
        return
    # 读取加密内容的json文件(可能是压缩的.json.zst或未压缩的.json)
    ciphertext_json = input("File containing ciphertext:").strip()
    if ciphertext_json.endswith('.lsed'):
        with open(ciphertext_json, "rb") as f:
            compressed_data = f.read()
        json_str = decompress_data(compressed_data)
        cipher_data = json.loads(json_str)
    else:
        with open(ciphertext_json, "r", encoding="utf-8") as f:
            cipher_data = json.load(f)
    ciphertext_compressed = cipher_data.get("ciphertext", "")
    ciphertext_b64 = decompress_data(ciphertext_compressed)
    plaintext_file = cipher_data.get("plaintext_file", "")
    if not ciphertext_b64 or not plaintext_file:
        print("ErrCiphertextOrPlaintextFileNotFound")
        return
    try:
        plaintext = ling_decrypt(ciphertext_b64, priv_key)
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
        out=import_key(key_file)
        if out == "ErrFileNotFound":
            return "ErrFileNotFound"
        elif out == "ErrKeyAlreadyExists":
            return "ErrKeyAlreadyExists"
        else:
            output=out[0]
            print(str(output[0])+" "+output[1]+"\n"+output[2]+"\n"+output[3]+" <"+output[4]+"> "
                  +" "+output[5]+"\n"+output[6])
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
                print(str(output[0])+" "+output[1]+"\n"+output[2]+"\n"+output[3]+" <"+output[4]+"> "
                      +" "+output[5]+"\n"+output[6])
    elif command == "del":
        lkid = input("Delete by lkid (default skip):").strip()
        lkid_short = input("Delete by lkid_short (default skip):").strip()
        name = input("Delete by name:").strip()
        out=del_key(lkid=lkid, lkid_short=lkid_short, name=name)
        if out == "NoLocalKeyFile":
            return "NoLocalKeyFile"
        elif out == "NoLocalKey":
            return "NoLocalKey"
        elif out == "ErrNoMatchKey":
            return "ErrNoMatchKey"
        elif out == 0:
            return "OK."
    else:
        return "ErrBadCommand"


def main():
    print(MAINAME+" Ver "+VERSION)
    while True:
        cmd = input("]").strip().lower()
        if cmd == "quit" or cmd == "exit":
            print("Bye!")
            break
        elif cmd == "genkey":
            gen_key()
        #elif cmd == "dekey":
        #    decrypt_key()
        elif cmd == "encrypt":
            encrypt_file()
        elif cmd == "decrypt":
            decrypt_file()
        elif cmd == "importkey":
            local_key("import")
        elif cmd == "listkey":
            local_key("list")
        elif cmd == "delkey":
            local_key("del")
        else:
            print("ErrCommandNotFound")

if __name__ == "__main__":
    main()