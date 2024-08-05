import requests

class HTTPConnection:
    def __init__(self, ip):
        self._url = 'http://{}/api'.format(ip)
    def send(self, data: bytes):
        return requests.post(self._url, data=data).content