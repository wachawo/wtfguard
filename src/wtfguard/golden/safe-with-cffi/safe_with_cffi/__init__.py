"""Loading libssl via ctypes is a normal pattern for crypto-binding libraries."""

import ctypes
import ctypes.util


def load_libssl():
    name = ctypes.util.find_library("ssl")
    if name is None:
        raise RuntimeError("libssl not found")
    return ctypes.CDLL(name)
