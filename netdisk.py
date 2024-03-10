from typing import List
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
from copy import deepcopy
try:
    from file_name_operations import remove_continuous_slashes, name_legal, resolve_path, path_elements, src_in_dest
    from block import gen_tar_gz, _BLOCK_SIZE, upload_tar_gz
    from uploader import Uploader
except:
    from .file_name_operations import remove_continuous_slashes, name_legal, resolve_path, path_elements, src_in_dest
    from .block import gen_tar_gz, _BLOCK_SIZE, upload_tar_gz
    from .uploader import Uploader

_STR_TYPE = type('')
_DICT_TYPE = type({})
_BLOCK_CREATED = 1000001
_BLOCK_GENERATED = 1000002


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


def _size(json_data) -> int:
    if (type(json_data) == _STR_TYPE):
        file_info = str(json_data).split(',')
        return (int(file_info[1]) - int(file_info[0]))
    s = 0
    for k, v in json_data.items():
        s += _size(v)
    return s


def _file_num(json_data) -> int:
    if (type(json_data) == _STR_TYPE):
        return 1
    s = 0
    for k, v in json_data.items():
        s += _file_num(v)
    return s


def _file_dir_num(self, json_data) -> int:
    # 包括自己
    if (type(json_data) == _STR_TYPE):
        return 1
    s = 1
    for k, v in json_data.items():
        s += _file_dir_num(v)
    return s


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
        self.thread_num = 0

    def __require_unlocked(self) -> None:
        with self.__lock:
            assert (self.__locked == False), "Multithreading on PypiNetdisk is not allowed."
            self.__locked = True

    def __unlock(self) -> None:
        with self.__lock:
            self.__locked = False

    def _force_quit(self):
        '''
        仅在出现异常但未正常释放的时候使用，请勿为了多线程运行使用
        '''
        with self.__lock:
            self.__locked = False

    def exists(self, path: str) -> bool:
        '''
        任何情况均不报错（本身线程锁和 closed 不考虑）
        '''
        self.__require_unlocked()
        assert (self.__valid), "Operation on a closed netdisk is not allowed."
        path = path_elements(path)
        current_dir = self.__json['files']
        for p in path[:-1]:
            if (p not in current_dir):
                self.__unlock()
                return False
            if (type(current_dir[p]) == _STR_TYPE):
                self.__unlock()
                return False
            current_dir = current_dir[p]
        result = (path[-1] in current_dir)
        self.__unlock()
        return result

    def is_file(self, path: str) -> bool:
        '''
        任何情况均不报错（本身线程锁和 closed 不考虑）
        '''
        self.__require_unlocked()
        assert (self.__valid), "Operation on a closed netdisk is not allowed."
        path = path_elements(path)
        current_dir = self.__json['files']
        for p in path[:-1]:
            if (p not in current_dir):
                self.__unlock()
                return False
            if (type(current_dir[p]) == _STR_TYPE):
                self.__unlock()
                return False
            current_dir = current_dir[p]
        result = (path[-1] in current_dir and type(current_dir[path[-1]]) == _STR_TYPE)
        self.__unlock()
        return result

    def is_dir(self, path: str) -> bool:
        '''
        任何情况均不报错（本身线程锁和 closed 不考虑）
        '''
        self.__require_unlocked()
        assert (self.__valid), "Operation on a closed netdisk is not allowed."
        path = path_elements(path)
        current_dir = self.__json['files']
        for p in path[:-1]:
            if (p not in current_dir):
                self.__unlock()
                return False
            if (type(current_dir[p]) == _STR_TYPE):
                self.__unlock()
                return False
            current_dir = current_dir[p]
        result = (path[-1] in current_dir and type(current_dir[path[-1]]) == _DICT_TYPE)
        self.__unlock()
        return result

    def mkdir_all(self, path: str) -> None:
        '''
        如果中间一个没有，会一路创建下去
        '''
        self.__require_unlocked()
        assert (self.__valid), "Operation on a closed netdisk is not allowed."
        path = path_elements(path)
        path_str = resolve_path(path)
        try:
            for p in path:
                assert (len(p) < 256)
        except:
            self.__unlock()
            assert (False), f'Dir name is not legal.'
        if (path_str == '/'):
            self.__unlock()
            assert (False), f'Path "{path_str}" already exists.'
        current_dir = self.__json['files']
        current_dir_str = '/'
        for p in path[:-1]:
            if (p not in current_dir):
                current_dir[p] = {}
            elif (type(current_dir[p]) == _STR_TYPE):
                self.__unlock()
                current_dir_str += p
                assert (False), f'Path "{current_dir_str}" is a file.'
            current_dir = current_dir[p]
            current_dir_str += p + '/'
        if (path[-1] in current_dir):
            self.__unlock()
            assert (False), f'Path "{path_str}" already exists.'
        current_dir[path[-1]] = {}
        self.__unlock()

    def mkdir(self, base_path: str, name: str) -> None:
        '''
        base_path 必须存在
        '''
        self.__require_unlocked()
        assert (self.__valid), "Operation on a closed netdisk is not allowed."
        if (name_legal(name) == False):  # 虽然可以提前进行，但是逻辑上应该先检查其它的
            self.__unlock()
            assert (False), "Dir name is not legal."
        path = path_elements(base_path)  # base_path 的
        path_str = resolve_path(path)  # base_path 的
        current_dir = self.__json['files']
        current_dir_str = '/'
        for p in path:
            if (p not in current_dir):
                self.__unlock()
                current_dir_str += p
                assert (False), f'Path "{current_dir_str}" does not exist.'
            elif (type(current_dir[p]) == _STR_TYPE):
                self.__unlock()
                current_dir_str += p
                assert (False), f'Path "{current_dir_str}" is a file.'
            current_dir = current_dir[p]
            current_dir_str += p + '/'
        if (name in current_dir):
            self.__unlock()
            assert (False), f'Path "{path_str}/{name}" already exists.'
        current_dir[name] = {}
        self.__unlock()

    def size(self, path: str) -> int:
        '''
        文件或文件夹的总大小
        '''
        self.__require_unlocked()
        assert (self.__valid), "Operation on a closed netdisk is not allowed."
        path = path_elements(path)
        current_dir = self.__json['files']
        current_dir_str = '/'
        for p in path[:-1]:
            if (p not in current_dir):
                self.__unlock()
                current_dir_str += p
                assert (False), f'Path "{current_dir_str}" does not exist.'
            elif (type(current_dir[p]) == _STR_TYPE):
                self.__unlock()
                current_dir_str += p
                assert (False), f'Path "{current_dir_str}" is a file.'
            current_dir = current_dir[p]
            current_dir_str += p + '/'
        if (path[-1] not in current_dir):
            self.__unlock()
            current_dir_str += path[-1]
            assert (False), f'Path "{current_dir_str}" does not exist.'
        if (type(current_dir[path[-1]]) == _STR_TYPE):
            file_info = str(current_dir[path[-1]]).split(',')
            self.__unlock()
            return (int(file_info[1]) - int(file_info[0]))
        s = _size(current_dir[path[-1]])
        self.__unlock()
        return s

    def file_info(self, path: str) -> list:
        # 目前只有大小
        return [self.size(path)]

    def dir_info(self, path: str) -> list:
        # 目前有一些问题，前面的线程锁释放了之后，有可能被其它线程抢占
        return [self.size(path), self.file_num(path), self.file_dir_num(path)]

    def file_num(self, path: str) -> int:
        self.__require_unlocked()
        assert (self.__valid), "Operation on a closed netdisk is not allowed."
        path = path_elements(path)
        current_dir = self.__json['files']
        current_dir_str = '/'
        for p in path[:-1]:
            if (p not in current_dir):
                self.__unlock()
                current_dir_str += p
                assert (False), f'Path "{current_dir_str}" does not exist.'
            elif (type(current_dir[p]) == _STR_TYPE):
                self.__unlock()
                current_dir_str += p
                assert (False), f'Path "{current_dir_str}" is a file.'
            current_dir = current_dir[p]
            current_dir_str += p + '/'
        if (path[-1] not in current_dir):
            self.__unlock()
            current_dir_str += path[-1]
            assert (False), f'Path "{current_dir_str}" does not exist.'
        if (type(current_dir[path[-1]]) == _STR_TYPE):
            self.__unlock()
            current_dir_str += path[-1]
            assert (False), f'Path "{current_dir_str}" is a file.'
        s = _file_num(current_dir[path[-1]])
        self.__unlock()
        return s

    def file_dir_num(self, path: str) -> int:
        # 包括自己
        self.__require_unlocked()
        assert (self.__valid), "Operation on a closed netdisk is not allowed."
        path = path_elements(path)
        current_dir = self.__json['files']
        current_dir_str = '/'
        for p in path[:-1]:
            if (p not in current_dir):
                self.__unlock()
                current_dir_str += p
                assert (False), f'Path "{current_dir_str}" does not exist.'
            elif (type(current_dir[p]) == _STR_TYPE):
                self.__unlock()
                current_dir_str += p
                assert (False), f'Path "{current_dir_str}" is a file.'
            current_dir = current_dir[p]
            current_dir_str += p + '/'
        if (path[-1] not in current_dir):
            self.__unlock()
            current_dir_str += path[-1]
            assert (False), f'Path "{current_dir_str}" does not exist.'
        if (type(current_dir[path[-1]]) == _STR_TYPE):
            self.__unlock()
            current_dir_str += path[-1]
            assert (False), f'Path "{current_dir_str}" is a file.'
        s = _file_dir_num(current_dir[path[-1]])
        self.__unlock()
        return s

    def list(self, path: str) -> list[str]:
        self.__require_unlocked()
        assert (self.__valid), "Operation on a closed netdisk is not allowed."
        path = path_elements(path)
        current_dir = self.__json['files']
        current_dir_str = '/'
        for p in path:
            if (p not in current_dir):
                self.__unlock()
                current_dir_str += p
                assert (False), f'Path "{current_dir_str}" does not exist.'
            elif (type(current_dir[p]) == _STR_TYPE):
                self.__unlock()
                current_dir_str += p
                assert (False), f'Path "{current_dir_str}" is a file.'
            current_dir = current_dir[p]
            current_dir_str += p + '/'
        result = []
        for k, v in current_dir.items():
            if (type(v) == _STR_TYPE):
                result.append(k + '')
            else:
                result.append(k + '/')
        self.__unlock()
        return result

    def list_all(self, path) -> dict[str, List[int]]:
        '''
        文件: [大小]
        文件夹: [大小, 文件数, 文件和文件夹总数]
        '''
        self.__require_unlocked()
        assert (self.__valid), "Operation on a closed netdisk is not allowed."
        path = path_elements(path)
        current_dir = self.__json['files']
        current_dir_str = '/'
        for p in path:
            if (p not in current_dir):
                self.__unlock()
                current_dir_str += p
                assert (False), f'Path "{current_dir_str}" does not exist.'
            elif (type(current_dir[p]) == _STR_TYPE):
                self.__unlock()
                current_dir_str += p
                assert (False), f'Path "{current_dir_str}" is a file.'
            current_dir = current_dir[p]
            current_dir_str += p + '/'
        result = {}
        for k, v in current_dir.items():
            if (type(v) == _STR_TYPE):
                parts = str(v).split(',')
                result[k + ''] = [int(parts[1]) - int(parts[0])]
            else:
                result[k + '/'] = [_size(v), _file_num(v), _file_dir_num(v)]
        self.__unlock()
        return result

    def rename(self, path: str, new_name: str) -> None:
        self.__require_unlocked()
        assert (self.__valid), "Operation on a closed netdisk is not allowed."
        path = path_elements(path)
        if (name_legal(new_name) == False):  # 虽然可以提前进行，但是逻辑上应该先检查其它的
            self.__unlock()
            assert (False), "New name is not legal."
        current_dir = self.__json['files']
        current_dir_str = '/'
        for p in path[:-1]:
            if (p not in current_dir):
                self.__unlock()
                current_dir_str += p
                assert (False), f'Path "{current_dir_str}" does not exist.'
            elif (type(current_dir[p]) == _STR_TYPE):
                self.__unlock()
                current_dir_str += p
                assert (False), f'Path "{current_dir_str}" is a file.'
            current_dir = current_dir[p]
            current_dir_str += p + '/'
        if (path[-1] not in current_dir):
            self.__unlock()
            current_dir_str += path[-1]
            assert (False), f'Path "{current_dir_str}" does not exist.'
        if (new_name in current_dir):
            self.__unlock()
            assert (False), f'Path "{current_dir_str}/{new_name}" already exists.'
        current_dir[new_name] = current_dir[path[-1]]
        del current_dir[path[-1]]
        self.__unlock()

    def remove(self, path: str) -> None:
        self.__require_unlocked()
        assert (self.__valid), "Operation on a closed netdisk is not allowed."
        path = path_elements(path)
        current_dir = self.__json['files']
        current_dir_str = '/'
        for p in path[:-1]:
            if (p not in current_dir):
                self.__unlock()
                current_dir_str += p
                assert (False), f'Path "{current_dir_str}" does not exist.'
            elif (type(current_dir[p]) == _STR_TYPE):
                self.__unlock()
                current_dir_str += p
                assert (False), f'Path "{current_dir_str}" is a file.'
            current_dir = current_dir[p]
            current_dir_str += p + '/'
        if (path[-1] not in current_dir):
            self.__unlock()
            current_dir_str += path[-1]
            assert (False), f'Path "{current_dir_str}" does not exist.'
        del current_dir[path[-1]]
        self.__unlock()

    def copy_to(self, src: str, dest: str) -> None:
        '''
        /a/b/c/d/e -> /g/h/i/j
        要求 /a/b/c/d/e 存在, /g/h/i/j 存在且为文件夹, /g/h/i/j/e 不存在
        '''
        self.__require_unlocked()
        assert (self.__valid), "Operation on a closed netdisk is not allowed."
        if (src_in_dest(src, dest)):
            self.__unlock()
            assert (False), "Dest is contained in src."
        src = path_elements(src)
        dest = path_elements(dest)
        src_current_dir = self.__json['files']
        dest_current_dir = self.__json['files']
        src_current_dir_str = '/'
        dest_current_dir_str = '/'
        for p in src[:-1]:
            if (p not in src_current_dir):
                self.__unlock()
                assert (False), f'Path "{src_current_dir_str}" does not exist.'
            elif (type(src_current_dir[p]) == _STR_TYPE):
                self.__unlock()
                assert (False), f'Path "{src_current_dir_str}" is a file.'
            src_current_dir = src_current_dir[p]
            src_current_dir_str += p + '/'
        if (src[-1] not in src_current_dir):
            self.__unlock()
            assert (False), f'Path "{src_current_dir_str}/{src[-1]}" does not exist.'
        for p in dest:
            if (p not in dest_current_dir):
                self.__unlock()
                assert (False), f'Path "{dest_current_dir_str}" does not exist.'
            elif (type(dest_current_dir[p]) == _STR_TYPE):
                self.__unlock()
                assert (False), f'Path "{dest_current_dir_str}" is a file.'
            dest_current_dir = dest_current_dir[p]
            dest_current_dir_str += p + '/'
        if (src[-1] in dest_current_dir):
            self.__unlock()
            assert (False), f'Path "{dest_current_dir_str}/{src[-1]}" already exists.'
        dest_current_dir[src[-1]] = deepcopy(src_current_dir[src[-1]])
        self.__unlock()

    def copy_as(self, src: str, dest: str) -> None:
        '''
        /a/b/c/d/e -> /g/h/i/j
        要求 /a/b/c/d/e 存在, /g/h/i 存在且为文件夹, /g/h/i/j 不存在
        '''
        self.__require_unlocked()
        assert (self.__valid), "Operation on a closed netdisk is not allowed."
        if (src_in_dest(src, dest)):
            self.__unlock()
            assert (False), "Dest is contained in src."
        dest_path_str = resolve_path(dest)
        if (dest_path_str == '/'):
            self.__unlock()
            assert (False), f"Path '{dest_path_str}' already exists."
        dest_path_elements = path_elements(dest)
        if (name_legal(dest_path_elements[-1]) == False):
            self.__unlock()
            assert (False), "Target name is not legal."
        src = path_elements(src)
        dest = path_elements(dest)
        src_current_dir = self.__json['files']
        dest_current_dir = self.__json['files']
        src_current_dir_str = '/'
        dest_current_dir_str = '/'
        for p in src[:-1]:
            if (p not in src_current_dir):
                self.__unlock()
                assert (False), f'Path "{src_current_dir_str}" does not exist.'
            elif (type(src_current_dir[p]) == _STR_TYPE):
                self.__unlock()
                assert (False), f'Path "{src_current_dir_str}" is a file.'
            src_current_dir = src_current_dir[p]
            src_current_dir_str += p + '/'
        if (src[-1] not in src_current_dir):
            self.__unlock()
            assert (False), f'Path "{src_current_dir_str}/{src[-1]}" does not exist.'
        for p in dest[:-1]:
            if (p not in dest_current_dir):
                self.__unlock()
                assert (False), f'Path "{dest_current_dir_str}" does not exist.'
            elif (type(dest_current_dir[p]) == _STR_TYPE):
                self.__unlock()
                assert (False), f'Path "{dest_current_dir_str}" is a file.'
            dest_current_dir = dest_current_dir[p]
            dest_current_dir_str += p + '/'
        if (dest[-1] in dest_current_dir):
            self.__unlock()
            assert (False), f'Path "{dest_current_dir_str}/{dest[-1]}" already exists.'
        dest_current_dir[dest[-1]] = deepcopy(src_current_dir[src[-1]])
        self.__unlock()

    def move_to(self, src: str, dest: str) -> None:
        '''
        /a/b/c/d/e -> /g/h/i/j
        要求 /a/b/c/d/e 存在, /g/h/i/j 存在且为文件夹, /g/h/i/j/e 不存在
        '''
        self.__require_unlocked()
        assert (self.__valid), "Operation on a closed netdisk is not allowed."
        if (src_in_dest(src, dest)):
            self.__unlock()
            assert (False), "Dest is contained in src."
        src = path_elements(src)
        dest = path_elements(dest)
        src_current_dir = self.__json['files']
        dest_current_dir = self.__json['files']
        src_current_dir_str = '/'
        dest_current_dir_str = '/'
        for p in src[:-1]:
            if (p not in src_current_dir):
                self.__unlock()
                assert (False), f'Path "{src_current_dir_str}" does not exist.'
            elif (type(src_current_dir[p]) == _STR_TYPE):
                self.__unlock()
                assert (False), f'Path "{src_current_dir_str}" is a file.'
            src_current_dir = src_current_dir[p]
            src_current_dir_str += p + '/'
        if (src[-1] not in src_current_dir):
            self.__unlock()
            assert (False), f'Path "{src_current_dir_str}/{src[-1]}" does not exist.'
        for p in dest:
            if (p not in dest_current_dir):
                self.__unlock()
                assert (False), f'Path "{dest_current_dir_str}" does not exist.'
            elif (type(dest_current_dir[p]) == _STR_TYPE):
                self.__unlock()
                assert (False), f'Path "{dest_current_dir_str}" is a file.'
            dest_current_dir = dest_current_dir[p]
            dest_current_dir_str += p + '/'
        if (src[-1] in dest_current_dir):
            self.__unlock()
            assert (False), f'Path "{dest_current_dir_str}/{src[-1]}" already exists.'
        dest_current_dir[src[-1]] = deepcopy(src_current_dir[src[-1]])  # 应该可以不用 deepcopy
        del src_current_dir[src[-1]]
        self.__unlock()

    def move_as(self, src: str, dest: str) -> None:
        '''
        /a/b/c/d/e -> /g/h/i/j
        要求 /a/b/c/d/e 存在, /g/h/i 存在且为文件夹, /g/h/i/j 不存在
        '''
        self.__require_unlocked()
        assert (self.__valid), "Operation on a closed netdisk is not allowed."
        if (src_in_dest(src, dest)):
            self.__unlock()
            assert (False), "Dest is contained in src."
        dest_path_str = resolve_path(dest)
        if (dest_path_str == '/'):
            self.__unlock()
            assert (False), f"Path '{dest_path_str}' already exists."
        dest_path_elements = path_elements(dest)
        if (name_legal(dest_path_elements[-1]) == False):
            self.__unlock()
            assert (False), "Target name is not legal."
        src = path_elements(src)
        dest = path_elements(dest)
        src_current_dir = self.__json['files']
        dest_current_dir = self.__json['files']
        src_current_dir_str = '/'
        dest_current_dir_str = '/'
        for p in src[:-1]:
            if (p not in src_current_dir):
                self.__unlock()
                assert (False), f'Path "{src_current_dir_str}" does not exist.'
            elif (type(src_current_dir[p]) == _STR_TYPE):
                self.__unlock()
                assert (False), f'Path "{src_current_dir_str}" is a file.'
            src_current_dir = src_current_dir[p]
            src_current_dir_str += p + '/'
        if (src[-1] not in src_current_dir):
            self.__unlock()
            assert (False), f'Path "{src_current_dir_str}/{src[-1]}" does not exist.'
        for p in dest[:-1]:
            if (p not in dest_current_dir):
                self.__unlock()
                assert (False), f'Path "{dest_current_dir_str}" does not exist.'
            elif (type(dest_current_dir[p]) == _STR_TYPE):
                self.__unlock()
                assert (False), f'Path "{dest_current_dir_str}" is a file.'
            dest_current_dir = dest_current_dir[p]
            dest_current_dir_str += p + '/'
        if (dest[-1] in dest_current_dir):
            self.__unlock()
            assert (False), f'Path "{dest_current_dir_str}/{dest[-1]}" already exists.'
        dest_current_dir[dest[-1]] = deepcopy(src_current_dir[src[-1]])  # 应该可以不用 deepcopy
        del src_current_dir[src[-1]]
        self.__unlock()

    def upload_from_disk_to(self, local_path: str, netdisk_path: str):
        # 不会提供 upload_from_disk_as 函数
        pass

    def upload_bytes(self, data: bytes, path: str):
        length = len(data)
        max_index = self.__json['bocks']['max_index']
        max_block_id = self.__json['bocks']['max_block_id']
        block_num = (length + _BLOCK_SIZE - 1) // _BLOCK_SIZE
        uploader = Uploader(thread_num=self.thread_num)

    def upload_tar_bytes(self, tar: bytes, path: str):
        pass

    def download_to_disk_to(self, netdisk_path: str, local_path: str):
        # 不会提供 download_to_disk_as 函数
        pass

    def get_bytes(self, path: str) -> bytes:
        pass

    def download_tar_bytes(self, path: str) -> bytes:
        pass

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


def Create(name: str, passwd: str, pypi_token: str, thread_num: int = 5) -> PypiNetdisk:
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
        "blocks": {
            "max_index": 0,  # 实际结束位置的下一个
            "max_block_id": 0  # 实际值 + 1
        },
        "packages": {}
    }
    netdisk.thread_num = thread_num
    return netdisk


def Open(path: str, passwd: str, thread_num: int = 5) -> PypiNetdisk:
    f = open(path, 'rb')
    data = f.read()
    f.close()
    return Open_bytes(data, passwd)


def Open_bytes(data: bytes, passwd: str, thread_num: int = 5) -> PypiNetdisk:
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
    netdisk.thread_num = thread_num
    return netdisk
