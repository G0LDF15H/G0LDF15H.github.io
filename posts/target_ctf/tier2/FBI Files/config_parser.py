import base64
import ipaddress
import json
import sys
from construct import Struct, Int32ul, Int16ul, CString


def xor_decrypt(data):
    d = bytearray()
    key = b'\x46\x69\x56\x9c\x9a\x87\x04\x31'

    for i in range(len(data)):
        d.append(data[i] ^ key[i % len(key)])

    return d


def base64_rot13(data):
    return base64.b64decode(str(data).translate(
        str(data).maketrans(
            'NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm0123456789+/=',
            'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/='
        ))).decode()


with open(sys.argv[1], 'rb') as fd:
    enc_data = fd.read()

CONFIG = "CONFIG" / Struct(
    "ip" / Int32ul,
    "port" / Int16ul,
    "useragent" / CString('utf8'),
    "username" / CString('utf8'),
    "btc" / CString('utf8'),
    "pubkey" / CString('utf8'),
    "ext" / CString('utf8'),
    "note" / CString('utf8'),
    "exts" / CString('utf8')
)

config_data = xor_decrypt(enc_data)
config = CONFIG.parse(config_data)

scorpion = dict()
scorpion['ip'] = str(ipaddress.ip_address(config.ip))
scorpion['port'] = config.port
scorpion['user-agent'] = config.useragent
scorpion['username'] = base64_rot13(config.username)
scorpion['btc'] = config.btc
scorpion['pubkey'] = base64_rot13(config.pubkey)
scorpion['ext'] = config.ext
scorpion['note'] = base64_rot13(config.note)
scorpion['exts'] = config.exts

print(json.dumps(scorpion))
