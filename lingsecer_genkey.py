from Crypto.PublicKey import RSA
from hashlib import sha512

__mainame__ = "LingSecer_GenKey"
__version__ = "250804"
__author__ = "DONGFANG Lingye"
__email__ = "ly@lingye.online"

def deterministic_randfunc(seed):
    # 生成一个确定性的伪随机字节流
    counter = [0]
    def randfunc(n):
        data = b''
        while len(data) < n:
            counter_bytes = counter[0].to_bytes(8, 'big')
            data += sha512(seed + counter_bytes).digest()
            counter[0] += 1
        return data[:n]
    return randfunc

def deterministic_rsa_key(seed_str=None, key_size=1024):
    if not seed_str:
        # 无种子时，使用系统随机源
        key = RSA.generate(key_size)
    else:
        seed = sha512(seed_str.encode('utf-8')).digest()
        randfunc = deterministic_randfunc(seed)
        key = RSA.generate(key_size, randfunc=randfunc)
    return key.export_key(), key.publickey().export_key()

def ling_genkey(seed_str=None, key_size=1024):
    priv_key, pub_key = deterministic_rsa_key(seed_str, key_size)
    return priv_key.decode(), pub_key.decode()

# 用法
#priv, pub = deterministic_rsa_key('a')
#print(priv.decode())
#print(pub.decode())