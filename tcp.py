import socket
import time

class TCPConnection:
    def __init__(self, hostname):
        self.hostname = hostname
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP)
    def reconnect(self):
        try:
            try:
                self.socket.close()
            except:
                pass
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP)
            self.socket.connect(self.hostname)
            #self.socket.settimeout(10)
        except OSError:
            pass
    def init_connection(self):
        pass
    def send(self, data: bytes):
        pass
    def receive(self):
        pass
    def close(self):
        self.socket.close()

class TCPIntermediate(TCPConnection):
    def __init__(self, hostname):
        super().__init__(hostname)
    def init_connection(self):
        super().reconnect()
        self.socket.send(b'\xee' * 4)
    def _try_to_reconnect(self):
        time.sleep(1)
        print('trying to reconnect...')
        try:
            try:
                self.socket.close()
            except:
                pass
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP)
            self.init_connection()
            print('connected!')
        except OSError as e:
            print(e)
            self._try_to_reconnect()
        except ConnectionResetError as e:
            self._try_to_reconnect()
    def _serialize_packet(self, data: bytes):
        return len(data).to_bytes(4, byteorder='little') + data
    def _get_length_of_packet(self, data):
        return int.from_bytes(data[:4], byteorder='little')
    def send(self, data: bytes):
        try:
            self.socket.send(self._serialize_packet(data))
        except OSError as e:
            #print(e)
            self._try_to_reconnect()
            return self.send(data)
        except ConnectionResetError as e:
            #print(e)
            self._try_to_reconnect()
            return self.send(data)
    def receive(self):
        try:
            length = self._get_length_of_packet(self.socket.recv(4))
            buffer = self.socket.recv(length)
            while len(buffer) != length:
                buffer += self.socket.recv(length-len(buffer))
            return buffer
        except OSError:
            return b''
