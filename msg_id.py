import time
import os

class MsgId:
    def __init__(self):
        self._last_time = 0
        self._correlation = 0
    def set_msg_id(self, server_msg_id):
        self._last_time = server_msg_id
        self._correlation = self._last_time // 2**32 - int(time.time())
    def get_msg_id(self):
        now = int(time.time())
        last_time = self._last_time // 2**32
        if now < last_time:
            now += self._correlation
        now = now * 2**32
        if now <= self._last_time:
            now += self._last_time - now
            now += int.from_bytes(os.urandom(2), byteorder='big') % 100
        if now % 4 != 0:
            now += 4 - now % 4
        self._last_time = now
        return now
    def get_correlation(self):
        return self._correlation