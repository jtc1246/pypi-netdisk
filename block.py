try:
    from bytesio import bd
except:
    from .bytesio import bd
import tarfile
import io
import secrets

try:
    from my_twine.commands.upload import main as _twine_upload  # use "pip install twine" to install dependencies
except:
    from .my_twine.commands.upload import main as _twine_upload  # use "pip install twine" to install dependencies
try:
    from data import head as _head
    from data import tail as _tail
    from data import head_length as _head_length
    from data import tail_length as _tail_length
    from data import tar as _tar_file_list
except:
    from .data import head as _head
    from .data import tail as _tail
    from .data import head_length as _head_length
    from .data import tail_length as _tail_length
    from .data import tar as _tar_file_list


def _to_4_digits(num: int) -> str:
    num = str(num)
    return "0" * (4 - len(num)) + num


def gen_tar_gz(package_name: str, data_encrypted: bytes, block_id: int) -> tuple[str, bytes]:
    id1 = block_id // 10000
    id2 = block_id % 10000
    id1 = _to_4_digits(id1)
    id2 = _to_4_digits(id2)
    tar_stream = io.BytesIO()
    with tarfile.open(mode='w:gz', fileobj=tar_stream) as tar:
        for k, v in _tar_file_list.items():
            k = str(k).replace('$1', id1).replace('$2', id2).replace('$3', package_name)
            if (v == None and k.endswith('/')):
                dir_tarinfo = tarfile.TarInfo(k)
                dir_tarinfo.type = tarfile.DIRTYPE
                dir_tarinfo.mode = 0o777
                tar.addfile(dir_tarinfo)
                continue
            if (v == None and k.endswith('.so')):
                so = _head + data_encrypted + _tail
                file_like_object = io.BytesIO(so)
                tarinfo = tarfile.TarInfo(name=k)
                tarinfo.mode = 0o777
                tarinfo.size = len(so)
                tar.addfile(tarinfo, fileobj=file_like_object)
                continue
            v = str(v).replace('$1', id1).replace('$2', id2).replace('$3', package_name).encode('utf-8')
            file_like_object = io.BytesIO(v)
            tarinfo = tarfile.TarInfo(name=k)
            tarinfo.size = len(v)
            tarinfo.mode = 0o777
            tar.addfile(tarinfo, fileobj=file_like_object)
    tar_gz_bytes = tar_stream.getvalue()
    tar_stream.close()
    file_name = '$3-1.1$1.1$2.tar.gz'.replace('$1', id1).replace('$2', id2).replace('$3', package_name)
    return (file_name, tar_gz_bytes)


def upload_tar_gz(name: str, data: bytes, pypi_token: str):
    '''
    返回值:
    0: 成功
    1: 已存在
    2: 总大小超过上限
    3: 未知错误
    -1: pypi_token 错误
    -2: 名称不合适
    -3: 网络错误
    这里不做任何重试，只如实返回错误码
    '''
    args = ['-u', '__token__', '-p', pypi_token, '--non-interactive', '--disable-progress-bar']
    bd.register(name, data)
    args.append('/bytes-jtc/' + name)
    try:
        _twine_upload(args)
    except Exception as err:
        error_msg = str(err)
        bd.free(name)
        if (error_msg.find('non-existent authentication') >= 0):
            # pypi_token 错误
            return -1
        if (error_msg.find("isn't allowed to upload") >= 0 or error_msg.find('too similar') >= 0):
            # 名称不合适
            return -2
        if (error_msg.find('HTTPSConnectionPool') >= 0):
            # 网络错误
            return -3
        if (error_msg.find('already exists') >= 0):
            # 已存在, 但是可能不会处理这个错误
            return 1
        if (error_msg.find('size too large') >= 0):
            # 单个 project 总大小超过上限
            return 2
        print("Unknown error: " + error_msg)
        return 3
    bd.free(name)
    return 0


if __name__ == "__main__":
    for i in range(95, 120):
        n, d = gen_tar_gz('ijbqivgbeugyvbub', secrets.token_bytes(95000000), i)
        s = upload_tar_gz(n, d, 'pypi-AgEIcHlwaS5vcmcCJDkzOWE3ZDFiLWZjNTAtNDFkMC1hMDJhLTU2ODI3NzZkMDIwMgACKlszLCI1NzM1YzEwNi04M2I5LTRhMGMtYTk2OS04MWQ1MDMzNjJiMmEiXQAABiC3f83OHTvuWSIiEaQLbBOD3SvrnAQL8gLwwIzvMM_UHw')
        print(f'{i}: {s}')
