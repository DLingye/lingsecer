MAINAME = "LingSecer"
VERSION = "250805"
AUTHOR = "DONGFANG Lingye"
EMAIL = "ly@lingye.online"

import hashlib
import json

import lingsecer_gettime

def key_to_json(owner_name, owner_mail, comment, mode, time, priv_encrypted, 
           pub_key, priv_key):
    #生成pub_key的SHA512作为唯一id,全部使用大写
    lkid = hashlib.sha512(pub_key.encode('utf-8')).hexdigest().upper()
    data = {
        "version": VERSION,
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
    return data

def write_data(filename=None, data=None):
    #这个函数将data接收的json格式数据写入filename指定的文件
    if not filename:
        return "ErrNoFileName"
    if not data:
        return "ErrNoData"
    with open(filename, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=4)
    return 0

def encrypted_file_to_data(plaintext_file, ciphertext):
    timezone = lingsecer_gettime.timezone
    l_time = lingsecer_gettime.l_time
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