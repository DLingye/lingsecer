import hashlib
import json
import datetime, time

import lingsecer_metadata

MAINAME = lingsecer_metadata.MAINAME
VERSION = lingsecer_metadata.VERSION
AUTHOR = lingsecer_metadata.AUTHOR
EMAIL = lingsecer_metadata.EMAIL

l_time = datetime.datetime.now().strftime("%Y-%m-%d_%H:%M:%S")
timezone = time.strftime('%Z', time.localtime())

def key_to_json(owner_name, owner_mail, comment, encrypt_algo, sign_algo, mode, time, priv_encrypted, 
           pub_key, priv_key, pub_sign, priv_sign, encrypt_key_length, sign_key_length):
    #生成pub_key的SHA512作为唯一id,全部使用大写
    lkid = hashlib.sha512(pub_key.encode('utf-8')).hexdigest().upper()
    data = {
        "version": VERSION,
        "lkid": lkid,
        "name": owner_name,
        "email": owner_mail,
        "comment": comment,
        "encrypt_algo": encrypt_algo,
        "sign_algo": sign_algo,
        "mode": mode,
        "time": time,
        "priv_encrypted": priv_encrypted,
        "encrypt_key_length": encrypt_key_length,
        "sign_key_length": sign_key_length,
        "pub_key": pub_key,
        "priv_key": priv_key,
        "pub_sign": pub_sign,
        "priv_sign": priv_sign
    }
    return data

def write_data(filename=None, data=None):
    #将data接收的json格式数据写入filename指定的文件
    if not filename:
        return "ErrNoFileName"
    if not data:
        return "ErrNoData"
    with open(filename, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=4)
    return 0

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