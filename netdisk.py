import subprocess
from hashlib import sha256
import hashlib
from Crypto.Cipher import AES  # pip install pycryptodome
from Crypto.Util import Counter
import os
import shutil
import json
import secrets
from time import time, sleep
import threading


def _hash_sha256(data, upper: bool = False) -> str:
    # 对一个 block 的内容（即长度为严格 95000000 的部分）计算哈希，不是 so
    if (type(data) == type('')):
        data = data.encode('utf-8')
    if upper:
        return hashlib.sha256(data).hexdigest().upper()
    return hashlib.sha256(data).hexdigest()


def _aes_ctr_256_encrypt(key: str, data: bytes, block_id: int, start_nonce: int) -> bytes:
    # 加密针对一个 block 的内容（即长度为严格 95000000 的部分），再放进 so
    key = _hash_sha256("DO_NOT_SHOW_THE_HASH_OF_THIS_STRING_PLUS_YOUR_KEY_JTC_AES_ALGORITHM_WITH_ERROR_CHECKING_IN PYPI_NETDISK_585EA82C027802E2_" + key)
    key = bytes.fromhex(key)
    nonce = block_id * (2**27) + start_nonce
    nonce = nonce.to_bytes(8, 'big')
    ctr = Counter.new(64, prefix=nonce)
    cipher = AES.new(key, AES.MODE_CTR, counter=ctr)
    return cipher.encrypt(data)


def _json_compress(data: str) -> bytes:
    # 目前先不压缩，留着这个函数方便后期修改
    return data.encode('utf-8')


def _json_decompress(data: bytes) -> str:
    # 目前先不解压，留着这个函数方便后期修改
    return data.decode('utf-8')


class PypiNetdisk:
    def __init__(self):
        self.__name = ''
        self.__passwd = ''
        self.__pypi_token = ''
        self.__nonce = 0
        self.__json = {}
        self.__lock = threading.Lock()
        self.__locked = False
        self.__valid = False

    def __require_unlocked(self) -> None:
        with self.__lock:
            assert (self.__locked == False), "Multithreading on PypiNetdisk is not allowed."
            self.__locked = True

    def __unlock(self) -> None:
        with self.__lock:
            self.__locked = False

    @property
    def name(self) -> str:
        assert (self.__valid), "Operation on a closed netdisk is not allowed."
        return self.__name

    @property
    def pypi_token(self) -> str:
        assert (self.__valid), "Operation on a closed netdisk is not allowed."
        return self.__pypi_token

    def set_pypi_token(self, pypi_token: str) -> None:
        self.__require_unlocked()
        assert (self.__valid), "Operation on a closed netdisk is not allowed."
        self.__pypi_token = pypi_token
        self.__unlock()

    def set_name(self, name: str) -> None:
        self.__require_unlocked()
        assert (self.__valid), "Operation on a closed netdisk is not allowed."
        self.__name = name
        self.__unlock()

    def save(self, path: str) -> None:
        # 这里不需要 require_unlocked，因为 save_bytes 里面会调用, 而且写入文件可能出现异常，不好释放
        assert (self.__valid), "Operation on a closed netdisk is not allowed."
        all_data = self.save_bytes()
        with open(path, 'wb') as f:
            f.write(all_data)

    def save_bytes(self) -> bytes:
        self.__require_unlocked()
        assert (self.__valid), "Operation on a closed netdisk is not allowed."
        all_data = b''
        all_data += str(self.__nonce).encode('utf-8') + b'\n'
        json_data = {}
        json_data['name'] = self.__name
        json_data['pypi_token'] = self.__pypi_token
        json_data['data'] = self.__json
        json_data = json.dumps(json_data)
        json_data = _json_compress(json_data)
        origin_hash = _hash_sha256(json_data)
        json_encrypted = _aes_ctr_256_encrypt(self.__passwd, json_data, 10**8 + 2, self.__nonce)
        encrypted_hash = _hash_sha256(json_encrypted)
        all_data += encrypted_hash.encode('utf-8') + b'\n'
        all_data += origin_hash.encode('utf-8') + b'\n'
        all_data += str(len(json_data)).encode('utf-8') + b'\n'
        all_data += json_data
        return all_data

    def close(self):
        self.__require_unlocked()
        assert (self.__valid), "Operation on a closed netdisk is not allowed."
        self.__valid = False
        self.__name = ''
        self.__passwd = ''
        self.__pypi_token = ''
        self.__nonce = 0
        self.__json = {}
        self.__locked = False
        self.__unlock()


def Create(name: str, passwd: str, pypi_token: str) -> PypiNetdisk:
    netdisk = PypiNetdisk()
    netdisk._PypiNetdisk__name = name
    netdisk._PypiNetdisk__passwd = passwd
    netdisk._PypiNetdisk__pypi_token = pypi_token
    t = str(time())
    r = str(secrets.randbelow(2**32))
    h = _hash_sha256(t + r + name)[-7:]
    nonce = int(h, 16)
    netdisk._PypiNetdisk__nonce = nonce
    netdisk._PypiNetdisk__valid = True
    netdisk._PypiNetdisk__json = {
        "files": {},
        "blocks": {},
        "packages": {}
    }
    return netdisk


def Open(path: str, passwd: str) -> PypiNetdisk:
    f = open(path, 'rb')
    data = f.read()
    f.close()
    return Open_bytes(data, passwd)


def Open_bytes(data: bytes, passwd: str) -> PypiNetdisk:
    parts = data.split(b'\n')
    nonce = int(parts[0].decode('utf-8'))
    encrypted_hash = parts[1].decode('utf-8')
    origin_hash = parts[2].decode('utf-8')
    length = int(parts[3].decode('utf-8'))
    all_length = len(parts[0]) + len(parts[1]) + len(parts[2]) + len(parts[3]) + 4
    json_encrypted = parts[all_length:all_length + length]
    assert (_hash_sha256(json_encrypted) == encrypted_hash), "Hash value doesn't match."
    json_compressed = _aes_ctr_256_encrypt(passwd, json_encrypted, 10**8 + 2, nonce)
    assert (_hash_sha256(json_compressed) == origin_hash), "Password incorrect."
    json_data = _json_decompress(json_compressed)
    json_data = json.loads(json_data)
    netdisk = PypiNetdisk()
    netdisk._PypiNetdisk__name = json_data['name']
    netdisk._PypiNetdisk__passwd = passwd
    netdisk._PypiNetdisk__pypi_token = json_data['pypi_token']
    netdisk._PypiNetdisk__nonce = nonce
    netdisk._PypiNetdisk__json = json_data['data']
    netdisk._PypiNetdisk__valid = True
    return netdisk
