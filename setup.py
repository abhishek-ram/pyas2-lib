from setuptools import setup, find_packages
from pyas2lib import __versionstr__

# f = open(join(dirname(__file__), 'README.md'))
# long_description = f.read().strip()
# f.close()

install_requires = [
    'asn1crypto==0.22.0',
    'oscrypto==0.18.0'
    # 'cryptography==1.5.2',
]

tests_require = [
    'nose',
    # 'coverage',
    # 'mock',
    # 'pyaml',
    # 'nosexcover'
]

setup(
    name='pyas2lib',
    description="Python library for building and parsing AS2 Messages",
    license="GNU GPL v2.0",
    url="https://github.com/abhishek-ram/pyas2-lib",
    # long_description=long_description,
    long_description="Docs for this project are maintained at "
                     "https://github.com/abhishek-ram/pyas2-lib/blob/"
                     "master/README.md",
    version=__versionstr__,
    author="Abhishek Ram",
    author_email="abhishek8816@gmail.com",
    packages=find_packages(
        where='.',
        exclude=('test*',)
    ),
    classifiers=[
        "Development Status :: 4 - Beta",
        "License :: OSI Approved :: GNU General Public License v3 (GPLv3)",
        "Intended Audience :: Developers",
        "Operating System :: OS Independent",
        "Programming Language :: Python",
        "Programming Language :: Python :: 2.7",
        "Programming Language :: Python :: 3.2",
        "Programming Language :: Python :: 3.3",
        "Programming Language :: Python :: 3.4",
        "Programming Language :: Python :: 3.5",
        "Topic :: Security :: Cryptography",
        "Topic :: Communications",

    ],
    install_requires=install_requires,

    test_suite='nose.collector',
    tests_require=tests_require,
)
