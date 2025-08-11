# LingSecer 安全文件加密系统

## 项目简介
LingSecer 是一个基于Python的安全文件加密系统，采用RSA+AES混合加密算法，提供完整的密钥管理、文件加密解密功能。

**版本**: 250809  
**作者**: DONGFANG Lingye  
**邮箱**: ly@lingye.online

## 功能特性
- 安全的混合加密方案(RSA+AES)
- 完整的密钥生命周期管理
- 本地密钥存储和管理
- 文件加密/解密功能
- 数据压缩传输
- 时间戳和完整性验证

## 模块说明
| 模块 | 功能 |
|------|------|
| lingsecer.py | 主程序，提供用户界面 |
| lingsecer_seed.py | 加密种子生成 |
| lingsecer_genkey.py | RSA密钥对生成 |
| lingsecer_encrypt.py | 文件加密/解密核心 |
| lingsecer_localkey.py | 本地密钥管理 |
| lingsecer_todata.py | 数据格式转换 |
| lingsecer_gettime.py | 时间信息获取 |
| lingsecer_compress.py | 数据压缩/解压 |

## 安装和使用
### 依赖安装
```bash
pip install pycryptodome
```

### 基本使用
1. 生成密钥:
```bash
genkey
```

2. 加密文件:
```bash
encrypt
```

3. 解密文件:
```bash
decrypt
```

## 加密原理
1. 使用RSA-4096加密随机生成的AES密钥
2. 使用AES-256(GCM模式)加密文件内容
3. 压缩加密后的数据
4. 添加时间戳和完整性校验

## 示例
### 生成密钥
```
Name (default user): 
Email: user@example.com
Comment: test key
Seed phrase: (可选)
Key strength (1-64, default 64): 
RSA Key strength (default 4096): 
```

### 加密文件
```
Input lkid: (可选)
File to encrypt: test.txt
```

## 依赖
- Python 3.6+
- pycryptodome

## 许可证
本项目采用GPL v3 许可证。
