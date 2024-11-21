#!/usr/bin/env python3
##
# omnibus - deadbits.
# HTTP requests library
##
import requests
import warnings

from requests.packages.urllib3 import exceptions


# class HTTP:  # Python 3 style class definition
#    def __init__(self, proxy=None):
#        if proxy is not None:
#            self.proxy = {
#                'http': f'socks5://{proxy}',  # f-string
#                'https': f'socks5://{proxy}'  # f-string
#            }
#        else:
#            self.proxy = proxy


def post(*args, **kwargs):
    kwargs['verify'] = False

    with warnings.catch_warnings():
        warnings.simplefilter('ignore', exceptions.InsecureRequestWarning)
        warnings.simplefilter('ignore', exceptions.InsecurePlatformWarning)
        # if isinstance(self.proxy, dict):
        #    kwargs['proxies'] = self.proxy

        try:
            req = requests.post(*args, **kwargs)
            return (True, req) if req.status_code == 200 else (False, req)
        except requests.RequestException as err:
            return (False, None)


def get(*args, **kwargs):
    kwargs['verify'] = False

    with warnings.catch_warnings():
        warnings.simplefilter('ignore', exceptions.InsecureRequestWarning)
        warnings.simplefilter('ignore', exceptions.InsecurePlatformWarning)
        # if isinstance(self.proxy, dict):
        #    kwargs['proxies'] = self.proxy

        try:
            req = requests.get(*args, **kwargs)
            return (True, req) if req.status_code == 200 else (False, req)
        except requests.RequestException as err:
            return (False, None)
