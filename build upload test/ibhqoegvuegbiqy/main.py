import ctypes
import os

_path = os.path.dirname(os.path.abspath(__file__))
_path += '/main_func_linux_x86.so'

_cpp = ctypes.CDLL(_path)


def add(a: int, b: int) -> int:
    return _cpp.plus(a, b)


def minus(a: int, b: int) -> int:
    return _cpp.minus(a, b)


def times(a: int, b: int) -> int:
    return _cpp.times(a, b)


def hello_world() -> None:
    _cpp.hello_world()
