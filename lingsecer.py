import os
import json
import datetime
import time
import base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import hashlib

from lingsecer_seed import gen_seed
from lingsecer_genkey import ling_genkey
from lingsecer_encrypt import ling_encrypt, ling_decrypt

__mainame__ = "LingSecer"
__version__ = "250804"
__author__ = "DONGFANG Lingye"
__email__ = "ly@lingye.online"

l_time = datetime.datetime.now().strftime("%Y-%m-%d_%H:%M:%S")
timezone = time.strftime('%Z', time.localtime())

def key_gen_json(owner_name, owner_mail, comment, mode, time, priv_encrypted, 
           pub_key, priv_key):
    #生成pub_key的SHA512作为唯一id,全部使用大写
    lkid = hashlib.sha512(pub_key.encode('utf-8')).hexdigest().upper()
    data = {
        "version": __version__,
        "lkid": lkid,
        "name": owner_name,
        "email": owner_mail,
        "comment": comment,
        "mode": mode,
        "time": time,
        "priv_encrypted": priv_encrypted,
        "pub_key": pub_key,
        "priv_key": priv_key
    }
    filename = input("File name (default: {}): ".format(f"{owner_name}_priv.json")).strip()
    if not filename:
        filename = f"{owner_name}_priv.json"
    with open(filename, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=4)
    print("OK.")

def encrypted_to_json(plaintext_file, ciphertext):
    output_json = plaintext_file + ".json"
    time=timezone+'_'+l_time
    lfid = hashlib.sha512(ciphertext.encode('utf-8')).hexdigest().upper()
    out_data = {
        "version": __version__,
        "lfid": lfid,
        "plaintext_file": plaintext_file,
        "time": time,
        "mode": "encrypt",
        "ciphertext": ciphertext
    }
    with open(output_json, "w", encoding="utf-8") as f:
        json.dump(out_data, f, ensure_ascii=False, indent=4)
    print("OK.")

def aes_encrypt(data, password):
    key = password.encode('utf-8')
    key = key[:32].ljust(32, b'\0')  # AES-256
    iv = b'LingSecerAESInit'  # 16字节IV
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ct_bytes = cipher.encrypt(pad(data.encode('utf-8'), AES.block_size))
    return base64.b64encode(ct_bytes).decode('utf-8')

def aes_decrypt(enc_data, password):
    key = password.encode('utf-8')
    key = key[:32].ljust(32, b'\0')  # AES-256
    iv = b'LingSecerAESInit'
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ct = base64.b64decode(enc_data)
    from Crypto.Util.Padding import unpad
    return unpad(cipher.decrypt(ct), AES.block_size).decode('utf-8')

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
    if not strength.isdigit() or not (1 <= int(strength) <= 64) or strength == "":
        strength = "64"
    if phrase == "":
        # 留空则生成随机密钥
        priv, pub = ling_genkey(None)
        print("Private_Key:")
        print(priv)
        print("Public_Key:")
        print(pub)
    else:
        ins = phrase + " " + "2-" + strength
        result = gen_seed(ins)
        #print("生成的种子片段：")
        #print(result)
        priv, pub = ling_genkey(result[-2])
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
    key_gen_json(owner_name, owner_mail, comment, mode='encrypt', 
           time=timezone+'_'+l_time, priv_encrypted=priv_encrypted, 
           pub_key=pub, priv_key=priv)
    
def decrypt_key():
    json_filename = input("File to decrypt:").strip()
    with open(json_filename, "r", encoding="utf-8") as f:
        data = json.load(f)
    priv_encrypted = data.get("priv_encrypted", False)
    priv_key = data.get("priv_key", "")
    if priv_encrypted:
        password = input("Passphrase for private key:").strip()
        password = text_to_base64(password)
        try:
            priv_key = aes_decrypt(priv_key, password)
            print("Decrypted private key:")
            print(priv_key)
        except Exception as e:
            print("Err, password may be incorrect.")
    else:
        print("Private key:")
        print(priv_key)

def encrypt_file():
    json_filename = input("File containing public key:").strip()
    with open(json_filename, "r", encoding="utf-8") as f:
        data = json.load(f)
    pub_key = data.get("pub_key", "")
    if not pub_key:
        print("ErrPubkeyNotFound")
        return
    plaintext_file = input("File to encrypt:").strip()
    with open(plaintext_file, "r", encoding="utf-8") as f:
        plaintext = f.read()
    ciphertext = ling_encrypt(plaintext, pub_key)
    print(ciphertext)
    encrypted_to_json(plaintext_file, ciphertext)

def decrypt_file():
    json_filename = input("File containing private key:").strip()
    with open(json_filename, "r", encoding="utf-8") as f:
        data = json.load(f)
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
    # 读取加密内容的json文件
    ciphertext_json = input("File containing ciphertext:").strip()
    with open(ciphertext_json, "r", encoding="utf-8") as f:
        cipher_data = json.load(f)
    ciphertext_b64 = cipher_data.get("ciphertext", "")
    plaintext_file = cipher_data.get("plaintext_file", "")
    if not ciphertext_b64 or not plaintext_file:
        print("ErrCiphertextOrPlaintextFileNotFound")
        return
    try:
        plaintext = ling_decrypt(ciphertext_b64, priv_key)
        print("Decryption result:")
        print(plaintext)
        # Write back to the original file
        with open(plaintext_file, "w", encoding="utf-8") as f:
            f.write(plaintext)
        print(f"OK.")
    except Exception as e:
        print("ErrDecryptFailed", e)


def main():
    print(__mainame__+" Ver "+__version__)
    while True:
        cmd = input("]").strip().lower()
        if cmd == "q":
            print("Bye!")
            break
        elif cmd == "genkey":
            gen_key()
        elif cmd == "dekey":
            decrypt_key()
        elif cmd == "enfile":
            encrypt_file()
        elif cmd == "defile":
            decrypt_file()
        else:
            print("ErrCommandNotFound")

if __name__ == "__main__":
    main()