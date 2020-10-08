"""
Flask-CloudflareRemote
----------------------
"""
import os
import re
import sys

from setuptools import find_packages, setup
from setuptools.command.test import test

BASE_PATH = os.path.dirname(__file__)
VERSION_FILE = os.path.join('flask_cloudflare_remote', 'version.py')


def read(file):
    """

    :param file:
    :return:
    """
    with open(os.path.join(BASE_PATH, file)) as f:
        return f.read()


def grep(file, name):
    """

    :param file:
    :param name:
    :return:
    """
    pattern = r"{attr}\W*=\W*'([^']+)'".format(attr=name)
    value, = re.findall(pattern, read(file))
    return value


def readme(file):
    """

    :param file:
    :return:
    """
    try:
        return read(file)
    except OSError as exc:
        print(str(exc), file=sys.stderr)


class PyTest(test):
    def finalize_options(self):
        """

        """
        test.finalize_options(self)

    def run_tests(self):
        """

        """
        import pytest
        sys.exit(pytest.main(['tests']))


setup(
    license='MIT',
    name='Flask-CloudflareRemote',
    url='https://github.com/cs91chris/flask_cloudflare_remote',
    version=grep(VERSION_FILE, '__version__'),
    author=grep(VERSION_FILE, '__author_name__'),
    author_email=grep(VERSION_FILE, '__author_email__'),
    description='Cloudflare proxy support for flask application',
    long_description=readme('README.rst'),
    packages=find_packages(),
    zip_safe=False,
    include_package_data=True,
    platforms='any',
    install_requires=[
        'Flask',
        'netaddr >= 0',
    ],
    cmdclass={'test': PyTest},
    test_suite='tests',
    classifiers=[
        'Environment :: Web Environment',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
        'Programming Language :: Python :: 3',
        'Topic :: Internet :: WWW/HTTP :: Dynamic Content',
        'Topic :: Software Development :: Libraries :: Python Modules'
    ]
)
