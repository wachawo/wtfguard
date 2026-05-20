"""A legitimate package that uses ctypes for binding to libssl — common pattern,
must not be flagged as malicious."""

import ctypes.util
from setuptools import setup


def find_lib():
    return ctypes.util.find_library("ssl")


setup(
    name="safe-with-cffi",
    version="2.0.0",
    packages=["safe_with_cffi"],
)
