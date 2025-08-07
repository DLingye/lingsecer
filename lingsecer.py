MAINAME = "LingSecer"
VERSION = "250805"
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

l_time = lingsecer_gettime.l_time
timezone = lingsecer_gettime.timezone

def encrypted_file_to_data(plaintext_file, ciphertext):
    output_json = plaintext_file + ".json"
    time=timezone+'_'+l_time
    lfid = hashlib.sha512(ciphertext.encode('utf-8')).hexdigest().upper()
    out_data = {
        "version": VERSION,
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
    key_strength = input("RSA Key strength (default 4096):").strip()
    if not key_strength.isdigit() or not (1024 <= int(key_strength) <= 16384) or key_strength == "":
        key_strength = "4096"
    key_strength = int(key_strength)
    strength = input("Key strength (1-64, default 64):").strip()
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
           pub_key=pub, priv_key=priv)
    # 直接导入密钥库
    out = import_key(j_data)
    if out == "ErrFileNotFound":
        print("ErrFileNotFound")
    elif out == "ErrKeyAlreadyExists":
        print("ErrKeyAlreadyExists")
    else:
        output = out[0]
        print(str(output[0])+" "+output[1]+"\n"+output[2]+"\n"+output[3]+" <"+output[4]+"> "
              +" "+output[5]+"\n"+output[6])

def decrypt_key():
    json_filename = input("File to decrypt (leave empty to use local key):").strip()
    if json_filename:
        # 指定了外部密钥文件
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
    #修改这个函数，使其通过load_key()加载本地密钥库,而不是通过读取外部密钥
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
    with open(plaintext_file, "r", encoding="utf-8") as f:
        plaintext = f.read()
    ciphertext = ling_encrypt(plaintext, pub_key)
    print(ciphertext)
    encrypted_file_to_data(plaintext_file, ciphertext)

def decrypt_file():
    #修改这个函数，使其通过load_key()加载本地密钥库,而不是通过读取外部密钥
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
            #输出为像上面一样的易读形式
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