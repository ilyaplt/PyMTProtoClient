from functions import *
import os

def kdf(msg_key, auth_key, is_from_server=False):
    x = 8 if is_from_server else 0
    sha256_a = hashlib.sha256(msg_key + auth_key[x: 36+x]).digest()
    sha256_b = hashlib.sha256(auth_key[40+x: 76+x] + msg_key).digest()
    aes_key = sha256_a[:8] + sha256_b[8:24] + sha256_a[24:32]
    aes_iv = sha256_b[:8] + sha256_a[8:24] + sha256_b[24:32]
    return aes_key, aes_iv

class Message:
    def __init__(self, auth_key_id, auth_key, object: TLPacket, server_salt, session_id, message_id, seq_no):
        self._object = object
        self._server_salt = server_salt
        self._session_id = session_id
        self._message_id = message_id
        self._seq_no = seq_no
        self._auth_key_id = auth_key_id
        self._auth_key = auth_key
    def serialize(self):
        stream = BinaryStream()
        stream.pack_int64(self._server_salt)
        stream.pack_int64(self._session_id)
        stream.pack_int64(self._message_id)
        stream.pack_int32(self._seq_no)
        data = self._object.serialize()
        stream.pack_int32(len(data))
        stream.pack_bytes(data)
        data = stream.serialize()
        data += os.urandom(12)
        if len(data) % 16 != 0:
            data += os.urandom(16 - len(data) % 16)
        return data
    def pack(self):
        encrypted_data = self.serialize()
        msg_key_large = hashlib.sha256(self._auth_key[88: 32+88] + encrypted_data).digest()
        msg_key = msg_key_large[8:24]
        aes_key, aes_iv = kdf(msg_key, self._auth_key, False)
        encrypted_data = tgcrypto.ige256_encrypt(encrypted_data, aes_key, aes_iv)
        return self._auth_key_id + msg_key + encrypted_data

class MessageResponse:
    def __init__(self, auth_key, data):
        self._data = data
        self._auth_key = auth_key
    def unpack(self):
        stream = BinaryStream(self._data[:])
        stream.unpack_bytes(8)
        msg_key = stream.unpack_bytes(16)
        content = stream.serialize()
        aes_key, aes_iv = kdf(msg_key, self._auth_key, True)
        content = tgcrypto.ige256_decrypt(content, aes_key, aes_iv)
        stream = BinaryStream(content[:])
        server_salt, session_id, message_id, seq_no, content_length = stream.unpack_int64(), stream.unpack_int64(), stream.unpack_int64(), stream.unpack_int32(), stream.unpack_int32()
        return server_salt, session_id, message_id, seq_no, content[32:32+content_length]

class PlainTextMessage:
    def __init__(self, object: TLPacket):
        self._object = object
    @staticmethod
    def skip_header_from_response(data):
        return data[20:]
    def serialize(self):
        stream = BinaryStream()
        stream.pack_int64(0)
        stream.pack_int64(MSG_ID.get_msg_id())
        buffer: bytes = self._object.serialize()
        stream.pack_int32(len(buffer))
        stream.pack_bytes(buffer)
        return stream.serialize()