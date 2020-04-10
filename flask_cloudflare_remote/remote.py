import http.client

import flask
import netaddr as net


class Singleton(type):
    """
    Define an Instance operation that lets clients access its unique instance
    """
    def __init__(cls, name, bases, attrs):
        """

        :param name:
        :param bases:
        :param attrs:
        """
        super().__init__(name, bases, attrs)
        cls._instance = None

    def __call__(cls, *args, **kwargs):
        """

        :param args:
        :param kwargs:
        :return:
        """
        if cls._instance is None:
            cls._instance = super().__call__(*args, **kwargs)
        return cls._instance


class CloudflareRemote(metaclass=Singleton):
    def __init__(self, app=None, **kwargs):
        """

        :param app:
        :param kwargs:
        """
        self._app = None
        self._cf_ips = None
        self._cf_ipv6_enabled = None

        if app is not None:
            self.init_app(app, **kwargs)

    def init_app(self, app, cf_ips=None):
        """

        :param app:
        :param cf_ips:
        """
        self._app = app
        self._default_config()

        if not cf_ips:
            if self._app.config['CF_IPs'] is list:
                self._cf_ips = self._app.config['CF_IPs']
            else:
                self._cf_ips = self.get_ips()
        else:
            self._cf_ips = cf_ips

        self._app.logger.debug('CLOUDFLARE registered ips:\n {}'.format(self._cf_ips))

        if self._app.config['CF_STRICT_ACCESS']:
            self._app.before_request_funcs.setdefault(None, []).append(_hook_cloudflare_only)
        if self._app.config['CF_OVERRIDE_REMOTE']:
            self._app.before_request_funcs.setdefault(None, []).append(_hook_client_ip)

        if not hasattr(self._app, 'extensions'):
            self._app.extensions = dict()
        self._app.extensions['cloudflare'] = self

    def _default_config(self):
        """

        """
        self._app.config.setdefault("CF_IPs", None)
        self._app.config.setdefault("CF_REQ_TIMEOUT", 10)
        self._app.config.setdefault("CF_IP4_URI", '/ips-v4')
        self._app.config.setdefault("CF_IP6_URI", '/ips-v6')
        self._app.config.setdefault("CF_IPv6_ENABLED", False)
        self._app.config.setdefault("CF_STRICT_ACCESS", True)
        self._app.config.setdefault("CF_OVERRIDE_REMOTE", True)
        self._app.config.setdefault("CF_DOMAIN", 'www.cloudflare.com')
        self._app.config.setdefault("CF_HDR_CLIENT_IP", 'CF-Connecting-IP')

    def request(self, method='GET', uri='/'):
        """

        :param method:
        :param uri:
        :return:
        """
        conn = http.client.HTTPSConnection(
            host=self._app.config['CF_DOMAIN'],
            timeout=self._app.config['CF_REQ_TIMEOUT'],
            port=443
        )
        conn.request(method, uri)
        res = conn.getresponse()
        body = res.read()
        conn.close()

        return res.status, res.getheaders(), body

    def _get_ip_list(self, uri):
        """

        :param uri:
        :return:
        """
        if not self._cf_ips:
            status, hdr, body = self.request(uri=uri)
            if status == 200:
                self._cf_ips = body.decode().strip('\n').split('\n')
            else:
                raise http.client.HTTPException(status, hdr, body)

        return self._cf_ips

    def get_ips(self):
        """

        :return:
        """
        ip_list = self._get_ip_list(self._app.config['CF_IP4_URI'])
        if self._app.config['CF_IPv6_ENABLED']:
            ip_list += self._get_ip_list(self._app.config['CF_IP6_URI'])

        return ip_list

    def ip_in_range(self, ipaddr, netaddr):
        """

        :param ipaddr:
        :param netaddr:
        :return:
        """
        try:
            return net.IPAddress(ipaddr) in net.IPNetwork(netaddr)
        except (net.AddrConversionError, net.AddrFormatError, net.NotRegisteredError) as exc:
            self._app.logger.debug(str(exc))
            return False

    @staticmethod
    def get_remote():
        """

        :return:
        """
        if flask.request.environ.get('HTTP_X_FORWARDED_FOR'):
            return flask.request.environ['HTTP_X_FORWARDED_FOR']
        if flask.request.environ.get('HTTP_X_FORWARDED'):
            return flask.request.environ['HTTP_X_FORWARDED']
        elif flask.request.environ.get('HTTP_X_REAL_IP'):
            return flask.request.environ['HTTP_X_REAL_IP']

        return flask.request.environ['REMOTE_ADDR']

    def is_cloudflare(self, remote=None):
        """

        :param remote:
        :return:
        """
        ip_check = False
        cf_req_check = False

        if not remote:
            remote = self.get_remote()

        for r in remote.split(','):
            for ip in self._cf_ips:
                if self.ip_in_range(r.strip(), ip):
                    ip_check = True
                    break

        if self._app.config['CF_HDR_CLIENT_IP'] in flask.request.headers:
            cf_req_check = True

        return ip_check and cf_req_check

    def get_client_ip(self):
        """

        :return:
        """
        remote = self.get_remote()
        if self.is_cloudflare(remote):
            return flask.request.headers['CF-Connecting-IP']

        return remote


def _hook_client_ip():
    """

    """
    flask.request.environ['REMOTE_ADDR'] = CloudflareRemote().get_client_ip()


def _hook_cloudflare_only():
    """

    """
    if not CloudflareRemote().is_cloudflare():
        flask.abort(403, "Access Denied: only configured cloudflare IPs are allowed")
