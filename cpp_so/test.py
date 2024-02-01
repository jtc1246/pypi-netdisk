import ctypes

# cpp = ctypes.CDLL('./test_linux_x86.so')
cpp = ctypes.CDLL('./test2.so')

_ = cpp.hello_world()
print(cpp.plus(2634, 458))
print(cpp.minus(2634, 458))
print(cpp.times(2634, 458))
cpp.content()
