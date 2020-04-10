"""
Flask-CloudflareRemote
---------------------
"""
from setuptools import setup, find_packages

from flask_cloudflare_remote import author, __version__

with open("README.rst") as fh:
    long_description = fh.read()

setup(
    name='Flask-CloudflareRemote',
    version=__version__,
    url='https://github.com/cs91chris/flask_cloudflare_remote',
    license='MIT',
    author=author['name'],
    author_email=author['email'],
    description='Cloudflare proxy support for flask application',
    long_description=long_description,
    packages=find_packages(),
    zip_safe=False,
    include_package_data=True,
    platforms='any',
    install_requires=[
        'Flask',
        'netaddr==0.*',
    ],
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
