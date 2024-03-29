import http.client

import flask
from flask import current_app as cap
import netaddr as net


class CloudflareRemote:
    def __init__(self, app=None, **kwargs):
        """

        :param app:
        :param kwargs:
        """
        self._cf_ips = None
        self._cf_ipv6_enabled = None

        if app is not None:
            self.init_app(app, **kwargs)

    def init_app(self, app, cf_ips=None):
        """

        :param app:
        :param cf_ips:
        """
        self._default_config(app)

        if not hasattr(app, 'extensions'):
            app.extensions = dict()
        app.extensions['cloudflareRemote'] = self

        if app.config['CF_STRICT_ACCESS']:
            app.before_request_funcs.setdefault(None, []).append(self._hook_cloudflare_only)
        if app.config['CF_OVERRIDE_REMOTE']:
            app.before_request_funcs.setdefault(None, []).append(self._hook_client_ip)

        if not cf_ips:
            if app.config['CF_IPs'] is list:
                self._cf_ips = app.config['CF_IPs']
            else:
                self._cf_ips = self._get_ip_list(app, app.config['CF_IP4_URI'])
                if app.config['CF_IPv6_ENABLED']:
                    self._cf_ips += self._get_ip_list(app, app.config['CF_IP6_URI'])

                return self._cf_ips
        else:
            self._cf_ips = cf_ips

        app.logger.debug('CLOUDFLARE registered ips:\n%s', self._cf_ips)

    @staticmethod
    def _default_config(app):
        app.config.setdefault("CF_IPs", None)
        app.config.setdefault("CF_REQ_TIMEOUT", 10)
        app.config.setdefault("CF_IP4_URI", '/ips-v4')
        app.config.setdefault("CF_IP6_URI", '/ips-v6')
        app.config.setdefault("CF_IPv6_ENABLED", False)
        app.config.setdefault("CF_STRICT_ACCESS", True)
        app.config.setdefault("CF_OVERRIDE_REMOTE", True)
        app.config.setdefault("CF_DOMAIN", 'www.cloudflare.com')
        app.config.setdefault("CF_HDR_CLIENT_IP", 'CF-Connecting-IP')

    @staticmethod
    def ip_in_network(ipaddr, netaddr):
        """

        :param ipaddr: ip address
        :param netaddr: network address
        :return:
        """
        net_errors = (
            net.AddrConversionError,
            net.AddrFormatError,
            net.NotRegisteredError
        )
        try:
            return net.IPAddress(ipaddr) in net.IPNetwork(netaddr)
        except net_errors as exc:
            cap.logger.exception(exc)
            return False

    @staticmethod
    def get_remote():
        return flask.request.remote_addr

    def _hook_client_ip(self):
        flask.request.environ['REMOTE_ADDR'] = self.get_client_ip()

    def _hook_cloudflare_only(self):
        if not self.is_cloudflare():
            if cap.debug:
                mess = "Access Denied: your ip is not in configured networks"
                flask.abort(403, mess, response=dict(
                    client_ip=self.get_client_ip(),
                    allowed_networks=self._cf_ips
                ))
            flask.abort(403)

    def _get_ip_list(self, app, uri):
        """

        :param app:
        :param uri:
        :return:
        """
        if not self._cf_ips:
            conn = http.client.HTTPSConnection(
                host=app.config['CF_DOMAIN'],
                timeout=app.config['CF_REQ_TIMEOUT'],
                port=443
            )
            conn.request('GET', uri)
            res = conn.getresponse()
            body = res.read()
            conn.close()

            if res.status == 200:
                self._cf_ips = body.decode().strip('\n').split('\n')
            else:
                raise http.client.HTTPException(res.status, res.getheaders(), body)

        return self._cf_ips

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
                if self.ip_in_network(r.strip(), ip):
                    ip_check = True
                    break

        if cap.config['CF_HDR_CLIENT_IP'] in flask.request.headers:
            cf_req_check = True

        return ip_check and cf_req_check

    def get_client_ip(self):
        remote = self.get_remote()
        if self.is_cloudflare(remote):
            hdr_client_ip = cap.config['CF_HDR_CLIENT_IP']
            return flask.request.headers[hdr_client_ip]

        return remote
