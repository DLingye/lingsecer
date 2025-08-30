# LingSecer

## Distribution

  Lingsecer is a tool for file encryption, decryption, and signature verification. 

## Dependencies

```bash
- pynacl
- pycryptodome
- zstandard
```

## How to use
```
usage: lingsecer.py [-h] [-g] [-e] [-d] [-s] [-v] [--import IMPORT_KEYFILE] [--list] [--del DEL_IDENTIFIER]
                    [--export MODE IDENTIFIER] [--name NAME] [-f FILE]

options:
  -h, --help            show this help message and exit
  -g, --genkey          Generate a new key
  -e, --encrypt         Encrypt a file
  -d, --decrypt         Decrypt a file
  -s, --sign            Sign a file
  -v, --vsign           Verify signature
  --import IMPORT_KEYFILE
                        Import key from file
  --list                List local keys
  --del DEL_IDENTIFIER  Delete key by identifier
  --export MODE IDENTIFIER
                        Export key: pub/priv + identifier
  --name NAME           Key identifier (lkid/lkid_short/name)
  -f, --file FILE       File to process

```

I'm very sorry that this software has many imperfections, but it's my first relatively complete work. You are welcome to submit an issue.
