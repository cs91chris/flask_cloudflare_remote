__version_info__ = (1, 0, 0, 'beta')

author = {
    'name': 'cs91chris',
    'email': 'cs91chris@voidbrain.me'
}

__version__ = '.'.join(map(str, __version_info__))
__author__ = "{} <{}>".format(author['name'], author['email'])

__all__ = [
    '__version_info__',
    '__version__',
    '__author__',
    'author'
]
