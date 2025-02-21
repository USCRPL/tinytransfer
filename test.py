import ctypes
c_lib = ctypes.CDLL("./libtinytransfer.dylib")

test = c_lib.test(5)
print(test)