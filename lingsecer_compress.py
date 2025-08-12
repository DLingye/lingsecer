MAINAME = "LingSecer_Compress"
VERSION = "250812"
AUTHOR = "DONGFANG Lingye"
EMAIL = "ly@lingye.online"

import zstandard as zstd
import base64

def compress_data(data_str):
    """使用zstd格式进行极限压缩"""
    # 将字符串转换为字节
    data_bytes = data_str.encode('utf-8')
    # 创建zstd压缩器，使用最高压缩级别
    cctx = zstd.ZstdCompressor(level=22)
    # 使用zstd格式进行极限压缩
    compressed = cctx.compress(data_bytes)
    # 直接返回压缩后的二进制数据
    return compressed

def decompress_data(compressed_data):
    """解压缩zstd格式的数据
    支持多种输入格式:
    - 二进制数据: 直接解压
    - base64编码字符串: 先解码再解压
    - base85编码字符串: 先解码再解压
    """
    if isinstance(compressed_data, str):
        try:
            # 先尝试base64解码
            compressed_bytes = base64.b64decode(compressed_data.encode('utf-8'))
        except:
            try:
                # 如果base64失败，尝试base85解码
                compressed_bytes = base64.b85decode(compressed_data.encode('utf-8'))
            except:
                raise ValueError("Invalid compressed data format - must be base64 or base85 encoded string")
    else:
        # 处理二进制数据
        compressed_bytes = compressed_data
    
    # 创建zstd解压器
    dctx = zstd.ZstdDecompressor()
    # 使用zstd格式进行解压缩
    decompressed = dctx.decompress(compressed_bytes)
    # 将字节转换回字符串
    return decompressed.decode('utf-8')
