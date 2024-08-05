import struct

class BinaryStream:
    def __init__(self, buffer=None):
        if buffer:
            self._buffer = buffer
        else:
            self._buffer = b''
    def clear(self):
        self._buffer = b''
    def serialize(self):
        return self._buffer
    def pack_int32(self, value, byteorder='little'):
        self._buffer += value.to_bytes(4, byteorder=byteorder)
    def pack_int64(self, value, byteorder='little'):
        self._buffer += value.to_bytes(8, byteorder=byteorder)
    def pack_double(self, value: float):
        self._buffer += struct.pack('f', value)
    def pack_bytes(self, value):
        self._buffer += value
    def pack_string(self, value):
        string_size = len(value)
        if string_size < 254:
            data = bytes([string_size & 0xFF])
            data += value
            if len(data) % 4 != 0:
                data += bytes(4 - len(data) % 4)
            self._buffer += data
        else:
            data = bytes([254])
            data += string_size.to_bytes(3, byteorder='little')
            data += value
            if len(data) % 4 != 0:
                data += bytes(4 - len(data) % 4)
            self._buffer += data
    def pack_vector(self, elements: list):
        self.pack_int32(0x1cb5c415)
        self.pack_int32(len(elements))
        for elem in elements:
            if isinstance(elem, bytes):
                self.pack_bytes(elem)
            else:
                self.pack_bytes(elem.write())
    def unpack_int32(self, byteorder='little'):
        value = int.from_bytes(self._buffer[:4], byteorder)
        self._buffer = self._buffer[4:]
        return value
    def unpack_int64(self, byteorder='little'):
        value = int.from_bytes(self._buffer[:8], byteorder)
        self._buffer = self._buffer[8:]
        return value
    def unpack_bytes(self, bytes_count):
        data = self._buffer[:bytes_count]
        self._buffer = self._buffer[bytes_count:]
        return data
    def unpack_double(self):
        value = self.unpack_bytes(8)
        return struct.unpack('f', value)[0]
    def unpack_string(self):
        if self._buffer[0] < 254:
            data_size = self._buffer[0]
            data_to_skip_size = data_size + 1
            if data_to_skip_size % 4 != 0:
                data_to_skip_size += 4 - data_to_skip_size % 4
            data = self._buffer[1:data_size+1]
            self._buffer = self._buffer[data_to_skip_size:]
            return data
        else:
            data_size = int.from_bytes(self._buffer[1:4], byteorder='little')
            data_to_skip_size = data_size + 4
            if data_to_skip_size % 4 != 0:
                data_to_skip_size += 4 - data_to_skip_size % 4
            data = self._buffer[4:data_size+4]
            self._buffer = self._buffer[data_to_skip_size:]
            return data

class Flags:
    def __init__(self, flags):
        self._flags = flags

    def check_bit(self, n):
        return bool(self._flags & (1 << n))

class TLObject:
    PRIMITIVE_TYPES = [
        'int',
        'long',
        'string',
        'bytes',
        'double',
        'float',
        'int128',
        'int256',
        '#'
    ]
    def write(self, *args):
        pass
    def read(self, data: bytes):
        pass