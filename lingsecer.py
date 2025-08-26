import os
import json
import base64
from Crypto.Cipher import AES
import hashlib
import datetime, time

#from lingsecer_seed import gen_seed
from lingsecer_genkey import ling_genkey
from lingsecer_encrypt import ling_encrypt, ling_decrypt
from lingsecer_localkey import import_key, list_key, del_key, load_key, export_key
from lingsecer_todata import key_to_json
from lingsecer_compress import compress_data, decompress_data
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

def gen_key():
    username = os.getlogin()
    owner_name = input("Name (default {}):".format(username)).strip()
    if owner_name == "":
        owner_name = username
    owner_mail = input("Email:").strip()
    comment = input("Comment:").strip()

    #phrase = input("Seed phrase:").strip()
    #strength = input("Key strength (1-64, default 64):").strip()
    #key_strength = input("RSA Key strength (default 4096):").strip()
    #if not key_strength.isdigit() or not (1024 <= int(key_strength) <= 16384) or key_strength == "":
    #    key_strength = "4096"

    priv, pub = ling_genkey(None,None)
    #print("Private_Key:")
    #print(priv)
    #print("Public_Key:")
    #print(pub)
    
    password = input("Passphrase (leave empty for no encryption):").strip()
    if password:
        password = text_to_base64(password)
        priv = aes_encrypt(priv, password)
        priv_encrypted = True
    else:
        priv_encrypted = False
    j_data = key_to_json(owner_name, owner_mail, comment, algo="cv25519", mode='encrypt', 
           time=timezone+'_'+l_time, priv_encrypted=priv_encrypted, 
           pub_key=pub, priv_key=priv, key_length=256)
    # 直接导入密钥库
    out = import_key(j_data)
    if out == "ErrFileNotFound":
        print("ErrFileNotFound")
    elif out == "ErrKeyAlreadyExists":
        print("ErrKeyAlreadyExists")
    else:
        output = out[0]
        print(str(output[0])+". "+output[1]+"\n"+output[2]+" "+str(output[7])+"\n"+output[3]+" <"+output[4]+"> "
              +"\n"+output[6]+"\n"+output[5])

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
            print(str(output[0])+". "+output[1]+"\n"+output[2]+" "+str(output[7])+"\n"+output[3]+" <"+output[4]+"> "
              +"\n"+output[6]+"\n"+output[5])
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
                print(str(output[0])+". "+output[1]+"\n"+output[2]+" "+str(output[7])+"\n"+output[3]+" <"+output[4]+"> "
              +"\n"+output[6]+"\n"+output[5])
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
        elif cmd == "importkey":
            local_key("import")
        elif cmd == "listkey":
            local_key("list")
        elif cmd == "delkey":
            local_key("del")
        elif cmd.startswith("exportkey"):
            exportkey(cmd)
        elif cmd == "ling":
            import ling
            ling.main()
        else:
            print("ErrCommandNotFound")

if __name__ == "__main__":
    main()