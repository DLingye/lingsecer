MAINAME = "LingSecer_Compress"
VERSION = "250809"
AUTHOR = "DONGFANG Lingye"
EMAIL = "ly@lingye.online"

import lzma
import base64

def compress_data(data_str):
    """使用xz格式进行极限压缩"""
    # 将字符串转换为字节
    data_bytes = data_str.encode('utf-8')
    # 使用xz格式进行极限压缩
    compressed = lzma.compress(
        data_bytes,
        format=lzma.FORMAT_XZ,
        preset=lzma.PRESET_EXTREME
    )
    # 将压缩后的数据进行base85编码，以便存储和传输
    return base64.b85encode(compressed).decode('utf-8')

def decompress_data(compressed_str):
    """解压缩xz格式的数据"""
    # 将base85字符串解码为字节
    compressed_bytes = base64.b85decode(compressed_str.encode('utf-8'))
    # 使用xz格式进行解压缩
    decompressed = lzma.decompress(
        compressed_bytes,
        format=lzma.FORMAT_XZ
    )
    # 将字节转换回字符串
    return decompressed.decode('utf-8')
