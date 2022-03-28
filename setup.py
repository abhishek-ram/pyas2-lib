from setuptools import setup, find_packages

install_requires = [
    "asn1crypto==1.4.0",
    "oscrypto==1.2.1",
    "pyOpenSSL==21.0.0",
]

tests_require = [
    "pytest==6.2.5",
    "toml==0.10.2",
    "pytest-cov==2.8.1",
    "coverage==5.0.4",
    "pylint==2.12.1",
    "pylama==8.3.7",
    "pylama-pylint==3.1.1",
    "black==21.12b0",
    "pytest-black==0.3.12",
]

setup(
    name="pyas2lib",
    description="Python library for building and parsing AS2 Messages",
    license="GNU GPL v2.0",
    url="https://github.com/abhishek-ram/pyas2-lib",
    long_description="Docs for this project are maintained at "
    "https://github.com/abhishek-ram/pyas2-lib/blob/"
    "master/README.md",
    version="1.4.1",
    author="Abhishek Ram",
    author_email="abhishek8816@gmail.com",
    packages=find_packages(where=".", exclude=("test*",)),
    classifiers=[
        "Development Status :: 4 - Beta",
        "License :: OSI Approved :: GNU General Public License v3 (GPLv3)",
        "Intended Audience :: Developers",
        "Operating System :: OS Independent",
        "Programming Language :: Python",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Topic :: Security :: Cryptography",
        "Topic :: Communications",
    ],
    setup_requires=["pytest-runner"],
    install_requires=install_requires,
    tests_require=tests_require,
    extras_require={
        "tests": tests_require,
    },
)
