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

__mainame__ = "LingSecer"
__version__ = "250803"
__author__ = "DONGFANG Lingye"
__email__ = "ly@lingye.online"

l_time = datetime.datetime.now().strftime("%Y-%m-%d_%H:%M:%S")
timezone = time.strftime('%Z', time.localtime())

def show_info():
    print(__mainame__+" Ver "+__version__)

def w_file(owner_name, owner_mail, comment, mode, time, private_encrypted, 
           pub_key, priv_key):
    data = {
        "name": owner_name,
        "email": owner_mail,
        "comment": comment,
        "mode": mode,
        "time": time,
        "private_encrypted": private_encrypted,
        "public_key": pub_key,
        "private_key": priv_key
    }
    filename = f"{owner_name}_private.json"
    with open(filename, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=4)
    print(f"已将私钥信息写入 {filename}")

def aes_encrypt(data, password):
    key = password.encode('utf-8')
    key = key[:32].ljust(32, b'\0')  # AES-256
    iv = b'LingSecerAESInit'  # 16字节IV
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ct_bytes = cipher.encrypt(pad(data.encode('utf-8'), AES.block_size))
    return base64.b64encode(ct_bytes).decode('utf-8')

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
    password = input("请输入用于AES加密私钥的密码（留空则不加密）：").strip()
    if password:
        password = text_to_base64(password)
        priv = aes_encrypt(priv, password)
        private_encrypted = True
    else:
        private_encrypted = False
    w_file(owner_name, owner_mail, comment, mode='encrypt', 
           time=timezone+'_'+l_time, private_encrypted=private_encrypted, 
           pub_key=pub, priv_key=priv)

def main():
    show_info()
    while True:
        cmd = input("]").strip().lower()
        if cmd == "q":
            print("Bye!")
            break
        elif cmd == "g":
            gen_key()
        else:
            print("ErrCommandNotFound")

if __name__ == "__main__":
    main()