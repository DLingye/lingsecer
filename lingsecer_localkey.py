MAINAME = "LingSecer"
VERSION = "250805"
AUTHOR = "DONGFANG Lingye"
EMAIL = "ly@lingye.online"

import os
import json

LOCAL_KEY_FILE = "lingsecer_localkey.json"

def import_key(key_file):
    if not os.path.isfile(key_file):
        return "ErrFileNotFound"
    with open(key_file, "r", encoding="utf-8") as f:
        key_data = json.load(f)
    # 读取本地密钥库
    if os.path.isfile(LOCAL_KEY_FILE):
        with open(LOCAL_KEY_FILE, "r", encoding="utf-8") as f:
            local_keys = json.load(f)
    else:
        local_keys = []
    # 检查是否已存在相同lkid
    lkid = key_data.get("lkid")
    if any(k.get("lkid") == lkid for k in local_keys):
        return "ErrKeyAlreadyExists"
    local_keys.append(key_data)
    with open(LOCAL_KEY_FILE, "w", encoding="utf-8") as f:
        json.dump(local_keys, f, ensure_ascii=False, indent=4)
    # 导入后调用list_key，仅显示刚导入的密钥
    return list_key(lkid=lkid)

def list_key(lkid="", lkid_short="", name=""):
    if not os.path.isfile(LOCAL_KEY_FILE):
        return "NoLocalKeyFile"
    with open(LOCAL_KEY_FILE, "r", encoding="utf-8") as f:
        local_keys = json.load(f)
    if not local_keys:
        return "NoLocalKey"
    filtered_keys = []
    for key in local_keys:
        key_lkid = key.get('lkid', '')
        key_name = key.get('name', '')
        key_lkid_short = key_lkid[:8] + key_lkid[-8:] if len(key_lkid) >= 16 else key_lkid
        if (lkid and key_lkid == lkid) or \
           (lkid_short and key_lkid_short == lkid_short) or \
           (name and key_name == name):
            filtered_keys.append(key)
    if not lkid and not lkid_short and not name:
        filtered_keys = local_keys
    if not filtered_keys:
        return "ErrNoMatchKey"
    # 返回密钥信息列表
    result = []
    for idx, key in enumerate(filtered_keys, 1):
        key_lkid = key.get('lkid', '')
        key_name = key.get('name', '')
        key_email = key.get('email', '')
        key_comment = key.get('comment', '')
        key_date = key.get('time', '')
        key_lkid_short = key_lkid[:8] + key_lkid[-8:] if len(key_lkid) >= 16 else key_lkid
        result.append((idx, key_lkid, key_lkid_short, key_name, key_email, key_comment, key_date))
    return result

#通过指定的lkid或lkid_short或name删除密钥
def del_key(lkid="", lkid_short="", name=""):
    if not os.path.isfile(LOCAL_KEY_FILE):
        return "NoLocalKeyFile"
    with open(LOCAL_KEY_FILE, "r", encoding="utf-8") as f:
        local_keys = json.load(f)
    if not local_keys:
        return "NoLocalKey"
    filtered_keys = []
    for key in local_keys:
        key_lkid = key.get('lkid', '')
        key_name = key.get('name', '')
        key_lkid_short = key_lkid[:8] + key_lkid[-8:] if len(key_lkid) >= 16 else key_lkid
        if (lkid and key_lkid == lkid) or \
           (lkid_short and key_lkid_short == lkid_short) or \
           (name and key_name == name):
            continue
        filtered_keys.append(key)
    if len(filtered_keys) == len(local_keys):
        return "ErrNoMatchKey"
    with open(LOCAL_KEY_FILE, "w", encoding="utf-8") as f:
        json.dump(filtered_keys, f, ensure_ascii=False, indent=4)
    return 0

del_key(lkid_short="85D0A926C5064AAD")