import os
import json

import lingsecer_metadata

MAINAME = lingsecer_metadata.MAINAME
VERSION = lingsecer_metadata.VERSION
AUTHOR = lingsecer_metadata.AUTHOR
EMAIL = lingsecer_metadata.EMAIL
LOCAL_KEY_FILE = "lingsecer_localkey.json"

def import_key(key_data):
    if not key_data:
        return "ErrNoData"
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
        #key_length = key.get('key_length', '')
        key_algo = key.get('algo', '')
        key_lkid_short = key_lkid[:8] + key_lkid[-8:] if len(key_lkid) >= 16 else key_lkid
        result.append((idx, key_lkid, key_lkid_short, key_name, key_email, key_comment, key_date, key_algo))
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

def load_key(lkid="", lkid_short="", name=""):
    if not os.path.isfile(LOCAL_KEY_FILE):
        return "NoLocalKeyFile"
    with open(LOCAL_KEY_FILE, "r", encoding="utf-8") as f:
        local_keys = json.load(f)
    if not local_keys:
        return "NoLocalKey"
    for key in local_keys:
        key_lkid = key.get('lkid', '')
        key_name = key.get('name', '')
        #key_length = key.get('key_length', '')
        key_lkid_short = key_lkid[:8] + key_lkid[-8:] if len(key_lkid) >= 16 else key_lkid
        if (lkid and key_lkid == lkid) or \
           (lkid_short and key_lkid_short == lkid_short) or \
           (name and key_name == name):
            return key
    return "ErrNoMatchKey"

def export_key(mode, identifier):
    """Export key to .lsk file
    Args:mode: 'pub' or 'priv'
         identifier: lkid, lkid_short or name
    Returns:str: filename if success, error message if failed"""
    key_data = load_key(lkid=identifier if len(identifier) == 64 else "",
                       lkid_short=identifier if len(identifier) == 16 else "",
                       name=identifier)
    if isinstance(key_data, str):  # error message
        return key_data
    
    lkid_short = key_data.get('lkid', '')[:8] + key_data.get('lkid', '')[-8:]
    filename = f"{lkid_short}.lsk"
    
    export_data = {
        "version": VERSION,
        "lkid": key_data.get('lkid', ''),
        "name": key_data.get('name', ''),
        "email": key_data.get('email', ''),
        "comment": key_data.get('comment', ''),
        "mode": key_data.get('mode', ''),
        "time": key_data.get('time', ''),
        "encrypt_algo": "cv25519",  # 固定为cv25519
        "sign_algo": "ed25519",  # 固定为ed25519
        "key_length": "256",  # cv25519固定为256位
        "pub_key": key_data.get('pub_key', ''),
        "pub_sign": key_data.get('pub_sign', '')
    }
    
    if mode == 'priv':
        export_data["priv_encrypted"] = key_data.get('priv_encrypted', False)
        export_data["priv_key"] = key_data.get('priv_key', '')
        export_data["priv_sign"] = key_data.get('priv_sign', '')

    try:
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(export_data, f, ensure_ascii=False, indent=4)
        return filename
    except Exception as e:
        return f"ErrExportFailed: {str(e)}"
