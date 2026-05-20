from setuptools import find_packages, setup

with open("README.md", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="safe-flask-like",
    version="3.1.0",
    description="A web microframework",
    long_description=long_description,
    packages=find_packages(),
    install_requires=[
        "werkzeug>=3.0",
        "jinja2>=3.1",
        "itsdangerous>=2.1",
    ],
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Programming Language :: Python :: 3",
    ],
)
