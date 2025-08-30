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

def key_to_json(owner_name, owner_mail, comment, crypt_algo, sign_algo, mode, time, priv_encrypted, 
           pub_key, priv_key, pub_sign, priv_sign, crypt_key_length, sign_key_length):
    try:
        # 生成 pub_key 的 SHA512 作为唯一 id, 全部使用大写
        lkid = hashlib.sha512(pub_key.encode('utf-8')).hexdigest().upper()
        data = {
            "version": VERSION,
            "lkid": lkid,
            "name": owner_name,
            "email": owner_mail,
            "comment": comment,
            "crypt_algo": crypt_algo,
            "sign_algo": sign_algo,
            "mode": mode,
            "time": time,
            "priv_encrypted": priv_encrypted,
            "crypt_key_length": crypt_key_length,
            "sign_key_length": sign_key_length,
            "pub_key": pub_key,
            "priv_key": priv_key,
            "pub_sign": pub_sign,
            "priv_sign": priv_sign
        }
        return data
    except Exception as e:
        print(f"Error generating JSON data: {e}")
        return None

def write_data(filename=None, data=None):
    try:
        if not filename:
            raise ValueError("Filename is required")
        if not data:
            raise ValueError("Data is required")

        with open(filename, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=4)
        print(f"Data written successfully to {filename}")
        return 0
    except ValueError as ve:
        print(f"ValueError: {ve}")
        return f"Error: {ve}"
    except IOError as ioe:
        print(f"IOError: {ioe}")
        return f"Error: {ioe}"
    except Exception as e:
        print(f"Error writing data: {e}")
        return f"Error: {e}"

def encrypted_file_to_data(plaintext_file, ciphertext):
    try:
        if not plaintext_file or not ciphertext:
            raise ValueError("Filename and ciphertext must be provided")

        output_json = plaintext_file + ".json"
        time = timezone + '_' + l_time
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

        print(f"Encrypted file data written to {output_json} successfully.")
    except ValueError as ve:
        print(f"ValueError: {ve}")
    except IOError as ioe:
        print(f"IOError: {ioe}")
    except Exception as e:
        print(f"Error during encryption data handling: {e}")
