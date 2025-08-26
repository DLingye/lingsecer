# LingSecer - 安全加密工具

## 功能概述

LingSecer 是一个安全加密工具，提供密钥生成、文件加密/解密、密钥管理等功能。
开发版本python 3.13.5

## 依赖

```bash
- cryptography
- pycryptodome
- zstandard
```

## 算法说明

使用cv25519进行密钥交换，AES-256-GCM进行数据加密

## 命令列表

### 基本命令
- `genkey`: 生成新的密钥对
- `encrypt`: 加密文件
- `decrypt`: 解密文件
- `quit/exit`: 退出程序

### 密钥管理命令
- `importkey`: 导入密钥
- `listkey`: 列出所有密钥
- `delkey`: 删除密钥
- `exportkey`: 导出密钥

## 导出密钥命令

### 功能
导出公钥或私钥到.lsk文件

### 语法
```
exportkey [pub/priv] [lkid/lkid_short/name]
```

### 参数
- `pub`: 仅导出公钥
- `priv`: 导出公钥和私钥
- `lkid`: 密钥完整ID (64字符)
- `lkid_short`: 密钥简短ID (16字符)
- `name`: 密钥名称

### 示例
1. 导出公钥:
```
lingsecer> exportkey pub mykey
```

2. 导出私钥:
```
lingsecer> exportkey priv 1234567890abcdef
```

## 使用示例

```bash
python lingsecer.py
lingsecer> genkey
lingsecer> listkey
lingsecer> exportkey pub mykey
```

## 作者

DONGFANG Lingye <ly@lingye.online>
