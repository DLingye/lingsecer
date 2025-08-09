MAINAME = "LingSecer_Seed"
VERSION = "250809"
AUTHOR = "DONGFANG Lingye"
EMAIL = "ly@lingye.online"

import hashlib
import base64

class ErrParamFormat(Exception):
    pass
class ErrSliceLen(Exception):
    pass
class ErrSliceIndexNegative(Exception):
    pass
class ErrSliceIndexOutOfRange(Exception):
    pass
class ErrMode(Exception):
    pass

def split_by_n(s, n):
    # 按n位分割，舍弃最后不足n位的部分
    return [s[i:i+n] for i in range(0, len(s) - len(s)%n, n)]

def gen_seed(ins):
    try:
        items = str(ins).strip().split()
        if len(items) < 2:
            raise ErrParamFormat("BadFormat")
        param = items[-1]
        words = items[:-1]
        joined = "_".join(words)
        value = joined.encode('utf-8')
        sha512_hex_list = []
        sha512_base64_list = []
        for i in range(1, 9):
            value = hashlib.sha512(value).digest()
            sha512_hex_list.append(value.hex())
            sha512_base64_list.append(base64.b64encode(value).decode('utf-8'))
        # 拼接所有SHA512和Base64
        all_sha512 = "".join(sha512_hex_list)
        all_base64 = "".join(sha512_base64_list)
        # 参数解析
        params = param.split('-')
        if len(params) == 2:
            mode, slice_len = params
            mode = mode
            slice_len = int(slice_len)
            if slice_len <= 0:
                raise ErrSliceLen("ErrSliceLen")
            if mode == '1':
                data = all_sha512
            elif mode == '2':
                data = all_base64
            else:
                raise ErrMode("ErrMode")
            slices = split_by_n(data, slice_len)
            result = slices + [len(slices)]
            return result
        elif len(params) == 3:
            mode, slice_len, slice_index = params
            mode = mode
            slice_len = int(slice_len)
            slice_index = int(slice_index)
            if slice_len <= 0:
                raise ErrSliceLen("ErrSliceLen")
            if slice_index < 0:
                raise ErrSliceIndexNegative("SliceIndexNegative")
            if mode == '1':
                data = all_sha512
            elif mode == '2':
                data = all_base64
            else:
                raise ErrMode("ErrMode")
            slices = split_by_n(data, slice_len)
            if slice_index >= len(slices):
                raise ErrSliceIndexOutOfRange("SliceIndexOutOfRange")
            result = [slices[slice_index], len(slices)]
            return result
        else:
            raise ErrParamFormat("BadParamFormat")
    except ErrParamFormat as e:
        print("Err:", e)
    except ErrSliceLen as e:
        print("Err:", e)
    except ErrSliceIndexNegative as e:
        print("Err:", e)
    except ErrSliceIndexOutOfRange as e:
        print("Err:", e)
    except ErrMode as e:
        print("Err:", e)
    except Exception as e:
        print("Err:", str(e))

