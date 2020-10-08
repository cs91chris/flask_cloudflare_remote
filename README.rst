Flask-CloudflareRemote
======================

Cloudflare proxy support for flask application.

It gets client ip from cloudflare headers and can allow request from cloudflare ips only.
If you are behind a proxy remember to use ``werkzeug.middleware.proxy_fix.ProxyFix``, alternative you can
override ``CloudflareRemote.get_remote()`` in order to fetch the correct client ip
for example via HTTP_X_FORWARDED_FOR.

Quickstart
~~~~~~~~~~

Install ``flask_cloudflare_remote`` using ``pip``:

::

   $ pip install Flask-CloudflareRemote

.. _section-1:

Example usage
^^^^^^^^^^^^^

.. code:: python

    import flask
    from flask_cloudflare_remote import CloudflareRemote


    app = Flask(__name__)
    cf = CloudflareRemote()
    cf.init_app(app)


Configuration
^^^^^^^^^^^^^

1. ``CF_DOMAIN``: *(default: 'www.cloudflare.com')*
2. ``CF_REQ_TIMEOUT``: *(default: 10)*
3. ``CF_IPs``: *(default: None)* list of allowed cloudflare ips
4. ``CF_IP4_URI``: *(default: '/ips-v4')* ipv4 list uri
5. ``CF_IP6_URI``: *(default: '/ips-v6')* ipv6 list uri
6. ``CF_IPv6_ENABLED``: *(default: False)* enable ipv6
7. ``CF_STRICT_ACCESS``: *(default: True)* return forbidden if remote ip is not in allowed list
8. ``CF_OVERRIDE_REMOTE``: *(default: True)* override flask REMOTE_ADDR from request
9. ``CF_HDR_CLIENT_IP``: *(default: 'CF-Connecting-IP')* header key used for client ip


License MIT
