import time

from msg_id import MsgId
import tgcrypto
import hashlib

class BinaryStream:
    def __init__(self, buffer=None):
        if buffer:
            self._buffer = buffer
        else:
            self._buffer = b''
    def clear(self):
        self._buffer = list()
    def serialize(self):
        return self._buffer
    def pack_int32(self, value, byteorder='little'):
        self._buffer += value.to_bytes(4, byteorder=byteorder)
    def pack_int64(self, value, byteorder='little'):
        self._buffer += value.to_bytes(8, byteorder=byteorder)
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
                self.pack_bytes(elem.serialize())
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

MSG_ID = MsgId()

class TLPacket:
    @staticmethod
    def get_id_of_packet(packet: bytes):
        return int.from_bytes(packet[:4], byteorder='little')
    def serialize(self):
        return b''

class TLResponse:
    def deserialize(self):
        return None

class BytesPacket(TLPacket):
    def __init__(self, data):
        self._data = data
    def serialize(self):
        return self._data

class ReqPQPacket(TLPacket):
    def __init__(self, nonce: bytes):
        self._nonce = nonce
    def serialize(self):
        stream = BinaryStream()
        stream.pack_int32(0xbe7e8ef1)
        stream.pack_bytes(self._nonce)
        return stream.serialize()
    
def skip_header_from_response(data):
    return data[20:]

class ResPQPacket(TLResponse):
    def __init__(self, buffer):
        self._buffer = buffer
    def deserialize(self):
        stream = BinaryStream(skip_header_from_response(self._buffer))
        packet_id, nonce, server_nonce, pq = stream.unpack_int32(), stream.unpack_bytes(16), stream.unpack_bytes(16), int.from_bytes(stream.unpack_string(), byteorder='big')
        vector_crc = stream.unpack_int32()
        if vector_crc != 0x1cb5c415:
            raise ValueError()
        vector_size = stream.unpack_int32()
        fingerprints = []
        for i in range(vector_size):
            fingerprints.append(stream.unpack_int64(byteorder='big'))
        return packet_id, nonce, server_nonce, pq, fingerprints

class PQInnerDataDC(TLPacket):
    def __init__(self, pq, p, q, nonce, server_nonce, new_nonce):
        self._pq = pq
        self._p = p
        self._q = q
        self._nonce = nonce
        self._server_nonce = server_nonce
        self._new_nonce = new_nonce
    def serialize(self):
        stream = BinaryStream()
        stream.pack_int32(0x83c95aec)
        stream.pack_string(self._pq.to_bytes(8, byteorder='big'))
        stream.pack_string(self._p.to_bytes(4, byteorder='big'))
        stream.pack_string(self._q.to_bytes(4, byteorder='big'))
        stream.pack_bytes(self._nonce)
        stream.pack_bytes(self._server_nonce)
        stream.pack_bytes(self._new_nonce)
        return stream.serialize()

class ReqDHParams(TLPacket):
    def __init__(self, nonce, server_nonce, p, q, fingerprint, encrypted_data):
        self._nonce = nonce
        self._server_nonce = server_nonce
        self._p = p
        self._q = q
        self._fingerprint = fingerprint
        self._encrypted_data = encrypted_data
    def serialize(self):
        stream = BinaryStream()
        stream.pack_int32(0xd712e4be)
        stream.pack_bytes(self._nonce)
        stream.pack_bytes(self._server_nonce)
        stream.pack_string(self._p.to_bytes(4, byteorder='big'))
        stream.pack_string(self._q.to_bytes(4, byteorder='big'))
        stream.pack_int64(self._fingerprint, byteorder='big')
        stream.pack_string(self._encrypted_data)
        return stream.serialize()

class ServerDHParamsOk(TLResponse):
    def __init__(self, data):
        self._data = data
    def deserialize(self):
        stream = BinaryStream(skip_header_from_response(self._data))
        packet_id = stream.unpack_int32()
        nonce = stream.unpack_bytes(16)
        server_nonce = stream.unpack_bytes(16)
        encrypted_data = stream.unpack_string()
        return packet_id, nonce, server_nonce, encrypted_data

class ServerInnerData(TLResponse):
    def __init__(self, data):
        self._data = data
    def deserialize(self):
        stream = BinaryStream(self._data[:])
        packet_id = stream.unpack_int32()
        nonce = stream.unpack_bytes(16)
        server_nonce = stream.unpack_bytes(16)
        g = stream.unpack_int32()
        dh_prime = int.from_bytes(stream.unpack_string(), byteorder='big')
        g_a = int.from_bytes(stream.unpack_string(), byteorder='big')
        server_time = stream.unpack_int32()
        return packet_id, nonce, server_nonce, g, dh_prime, g_a, server_time

class ClientDHInnerData(TLPacket):
    def __init__(self, nonce, server_nonce, retry_id, g_b):
        self._nonce = nonce
        self._server_nonce = server_nonce
        self._retry_id = retry_id
        self._g_b = g_b
    def serialize(self):
        stream = BinaryStream()
        stream.pack_int32(0x6643b654)
        stream.pack_bytes(self._nonce)
        stream.pack_bytes(self._server_nonce)
        stream.pack_int64(self._retry_id)
        stream.pack_string(self._g_b.to_bytes((self._g_b.bit_length() + 7) // 8, byteorder='big'))
        return stream.serialize()

class SetClientDHParams(TLPacket):
    def __init__(self, nonce, server_nonce, encrypted_data):
        self._nonce = nonce
        self._server_nonce = server_nonce
        self._encrypted_data = encrypted_data
    def serialize(self):
        stream = BinaryStream()
        stream.pack_int32(0xf5045f1f)
        stream.pack_bytes(self._nonce)
        stream.pack_bytes(self._server_nonce)
        stream.pack_string(self._encrypted_data)
        return stream.serialize()

class DHResult(TLResponse):
    def __init__(self, data):
        self._data = data
    def is_success(self):
        stream = BinaryStream(skip_header_from_response(self._data))
        return stream.unpack_int32() == 0x3bcbf734
    def deserialize(self):
        stream = BinaryStream(skip_header_from_response(self._data))
        return stream.unpack_int32(), stream.unpack_bytes(16), stream.unpack_bytes(16), stream.unpack_bytes(16)

class BadMsgNotification(TLResponse):
    def __init__(self, data):
        self._data = data
    def deserialize(self):
        binary = BinaryStream(self._data[:])
        return binary.unpack_int32(), binary.unpack_int64(), binary.unpack_int32(), binary.unpack_int32()
    def __str__(self):
        binary = BinaryStream(self._data[:])
        binary.unpack_int32()
        return 'bad_msg_notification#a7eff811 bad_msg_id:{} bad_msg_seqno:{} error_code:{} = BadMsgNotification;'.format(binary.unpack_int64(), binary.unpack_int32(), binary.unpack_int32())

class BadMsgNotificationException(Exception):
    def __init__(self, bad_msg_notification: BadMsgNotification):
        self._bad_msg_notification = bad_msg_notification
    def deserialize(self):
        return self._bad_msg_notification.deserialize()

class BadServerSalt(TLResponse):
    def __init__(self, data):
        self._data = data
    def deserialize(self):
        stream = BinaryStream(self._data)
        return stream.unpack_int32(), stream.unpack_int64(), stream.unpack_int32(), stream.unpack_int32(), stream.unpack_int64()

class MessageContainer:
    @staticmethod
    def is_message_container(data):
        return TLPacket.get_id_of_packet(data) == 0x73f1f8dc
    def deserialize(self):
        pass
    def serialize(self):
        pass

class MessageContainerResponse(MessageContainer):
    def __init__(self, data):
        self._data = data
    def deserialize(self):
        stream = BinaryStream(self._data[:])
        if stream.unpack_int32() != 0x73f1f8dc:
            raise ValueError()
        messages_count = stream.unpack_int32()
        messages = []
        for i in range(messages_count):
            msg_id, seq_no, bytes_count = stream.unpack_int64(), stream.unpack_int32(), stream.unpack_int32()
            data = stream.unpack_bytes(bytes_count)
            messages.append((msg_id, seq_no, data))
        return messages

class MessageContainerPacket(MessageContainer):
    def __init__(self, messages):
        self._messages = messages
    def serialize(self):
        stream = BinaryStream()
        stream.pack_int32(0x73f1f8dc)
        stream.pack_int32(len(self._messages))
        for k in self._messages:
            stream.pack_int64(k[0])
            stream.pack_int32(k[1])
            stream.pack_int32(len(k[2]))
            stream.pack_bytes(k[2])
        return stream.serialize()

class Ping(TLPacket):
    def __init__(self, ping_id):
        self._ping_id = ping_id
    def serialize(self):
        binary = BinaryStream()
        binary.pack_int32(0x7abe77ec)
        binary.pack_int64(self._ping_id)
        return binary.serialize()

class Pong(TLResponse):
    def __init__(self, data):
        self._data = data
        self._msg_id, self._ping_id = 0, 0
    def deserialize(self):
        stream = BinaryStream(self._data[4:])
        self._msg_id, self._ping_id = stream.unpack_int64(), stream.unpack_int64()
        return self._msg_id, self._ping_id
    def __str__(self):
        return 'pong msg_id:{} ping_id:{} = Pong;'.format(self._msg_id, self._ping_id)

class MsgAcks:
    pass

class MsgAcksPacket(MsgAcks, TLPacket):
    def __init__(self, msg_ids):
        self._msg_ids = msg_ids
    def serialize(self):
        stream = BinaryStream()
        stream.pack_int32(0x62d6b459)
        stream.pack_int32(0x1cb5c415)
        stream.pack_int32(len(self._msg_ids))
        for k in self._msg_ids:
            stream.pack_int64(k)
        return stream.serialize()

class NewSessionCreated(TLResponse):
    def __init__(self, data):
        self._data = data
    def deserialize(self):
        stream = BinaryStream(self._data[:])
        return stream.unpack_int32(), stream.unpack_int64(), stream.unpack_int64(), stream.unpack_int64()

class RpcResult(TLResponse):
    def __init__(self, data):
        self._data = data
    def deserialize(self):
        stream = BinaryStream(self._data[:])
        return stream.unpack_int32(), stream.unpack_int64(), stream.serialize()

class GZipPacked(TLResponse):
    def __init__(self, data):
        self._data = data
    def deserialize(self):
        stream = BinaryStream(self._data[:])
        return stream.unpack_int32(), stream.unpack_string()

class InvokeWithLayer(TLPacket):
    def __init__(self, layer, packet: TLPacket):
        self._packet = packet
        self._layer = layer
    def serialize(self):
        stream = BinaryStream()
        stream.pack_int32(0xda9b0d0d)
        stream.pack_int32(self._layer)
        stream.pack_bytes(self._packet.serialize())
        return stream.serialize()

class InitConnection(TLPacket):
    def __init__(self, query: TLPacket, api_id, device_model='Unknown UserAgent', system_version='Unknown UserAgent', app_version='1.0', system_lang_code='en', lang_pack='', lang_code='en'):
        self._api_id = api_id
        self._device_model = device_model
        self._system_version = system_version
        self._app_version = app_version
        self._system_lang_code = system_lang_code
        self._lang_pack = lang_pack
        self._lang_code = lang_code
        self._query = query
    def serialize(self):
        stream = BinaryStream()
        stream.pack_int32(0xc1cd5ea9)
        stream.pack_int32(0)
        stream.pack_int32(self._api_id)
        stream.pack_string(self._device_model.encode())
        stream.pack_string(self._system_version.encode())
        stream.pack_string(self._app_version.encode())
        stream.pack_string(self._system_lang_code.encode())
        stream.pack_string(self._lang_pack.encode())
        stream.pack_string(self._lang_code.encode())
        stream.pack_bytes(self._query.serialize())
        return stream.serialize()

class HttpWait(TLPacket):
    def __init__(self, max_delay, wait_after, max_wait):
        self._max_delay = max_delay
        self._wait_after = wait_after
        self._max_wait = max_wait
    def serialize(self):
        stream = BinaryStream()
        stream.pack_int32(0x9299359f)
        stream.pack_int32(self._max_delay)
        stream.pack_int32(self._wait_after)
        stream.pack_int32(self._max_wait)
        return stream.serialize()

class SendCode(TLPacket):
    def __init__(self, phone_number, api_id, api_hash):
        self._phone_number = phone_number
        self._api_id = api_id
        self._api_hash = api_hash
    def serialize(self):
        stream = BinaryStream()
        stream.pack_int32(0xa677244f)
        stream.pack_string(self._phone_number.encode())
        stream.pack_int32(self._api_id)
        stream.pack_string(self._api_hash.encode())
        stream.pack_int32(0xdebebe83)
        stream.pack_int32(0)
        return stream.serialize()

class SentCode(TLResponse):
    def __init__(self, data):
        self._data = data
    def deserialize(self):
        stream = BinaryStream(self._data[:])
        stream.unpack_int64()
        sent_code_type = stream.unpack_int32()
        if sent_code_type == 0xab03c6d9:
            stream.unpack_string()
        else:
            stream.unpack_int32()
        return stream.unpack_string()

class GetConfig(TLPacket):
    def __init__(self):
        pass
    def serialize(self):
        stream = BinaryStream()
        stream.pack_int32(0xc4f9186b)
        return stream.serialize()

class SignIn(TLPacket):
    def __init__(self, phone_number, phone_code_hash, phone_code):
        self._phone_number = phone_number
        self._phone_code_hash = phone_code_hash
        self._phone_code = phone_code
    def serialize(self):
        stream = BinaryStream()
        stream.pack_int32(0xbcd51581)
        stream.pack_string(self._phone_number.encode())
        stream.pack_string(self._phone_code_hash.encode())
        stream.pack_string(self._phone_code.encode())
        return stream.serialize()

class ImportBotAuthorization(TLPacket):
    def __init__(self, api_id, api_hash, bot_token):
        self._api_id = api_id
        self._api_hash = api_hash
        self._bot_token = bot_token
    def serialize(self):
        stream = BinaryStream()
        stream.pack_int32(0x67a3ff2c)
        stream.pack_int32(0)
        stream.pack_int32(self._api_id)
        stream.pack_string(self._api_hash.encode())
        stream.pack_string(self._bot_token.encode())
        return stream.serialize()

class RpcError(TLResponse):
    def __init__(self, data):
        self._data = data
    def deserialize(self):
        stream = BinaryStream(self._data[:])
        stream.unpack_int32()
        return stream.unpack_int32(), stream.unpack_string().decode()
    @staticmethod
    def check_for_error(data):
        return TLPacket.get_id_of_packet(data) == 0x2144ca19
    @staticmethod
    def get_error(data):
        return RpcError(data).deserialize()[1]

class DcOption(TLResponse):
    def __init__(self, data):
        stream = BinaryStream(data)
        self.packet_size = len(stream.serialize())
        if stream.unpack_int32() != 0x18b7a10d:
            raise ValueError()
        flags = stream.unpack_int32()
        self.ipv6 = True if (flags & 1) else False
        self.media_only = True if (flags & (1 << 1)) else False
        self.tcp_only = True if (flags & (1 << 2)) else False
        self.cdn = True if (flags & (1 << 3)) else False
        self.static = True if (flags & (1 << 4)) else False
        self.id = stream.unpack_int32()
        self.ip_address = stream.unpack_string()
        self.port = stream.unpack_int32()
        self.secret = stream.unpack_string() if (flags & (1 << 10)) else None
        self.packet_size = self.packet_size - len(stream.serialize())
    """@staticmethod
    def get_size_of_packet(data):
        stream = BinaryStream()
        stream.unpack_int32()
        flags = stream.unpack_int32()
        size_of_packet = 12
        stream.unpack_
        return"""
    def deserialize(self):
        pass

class Config(TLResponse):
    def __init__(self, data):
        stream = BinaryStream(data)
        if stream.unpack_int32() != 0x330b4067:
            raise ValueError()
        flags = stream.unpack_int32()
        self.phonecalls_enabled = True if (flags & (1 << 1)) else False
        self.default_p2p_contacts = True if (flags & (1 << 3)) else False
        self.preload_featured_stickers = True if (flags & (1 << 4)) else False
        self.ignore_phone_entities = True if (flags & (1 << 5)) else False
        self.revoke_pm_inbox = True if (flags & (1 << 6)) else False
        self.blocked_mode = True if (flags & (1 << 8)) else False
        self.pfs_enabled = True if (flags & (1 << 13)) else False
        self.date = stream.unpack_int32()
        self.expires = stream.unpack_int32()
        self.test_mode = True if stream.unpack_int32() == 0x997275b5 else False
        self.this_dc = stream.unpack_int32()
        vector_crc = stream.unpack_int32()
        if vector_crc != 0x1cb5c415:
            raise ValueError()
        elements_count = stream.unpack_int32()
        self.dcs_options = []
        for i in range(elements_count):
            offset = len(data) - len(stream.serialize())
            self.dcs_options.append(DcOption(stream.serialize()))
            stream = BinaryStream(data[offset + self.dcs_options[i].packet_size:])
        self.dc_txt_domain_name = stream.unpack_string()
        self.chat_size_max = stream.unpack_int32()
        self.megagroup_size_max = stream.unpack_int32()
        self.forwarded_count_max = stream.unpack_int32()
        self.online_update_period_ms = stream.unpack_int32()
        self.offline_blur_timeout_ms = stream.unpack_int32()
        self.offline_idle_timeout_ms = stream.unpack_int32()
        self.online_cloud_timeout_ms = stream.unpack_int32()
        self.notify_cloud_delay_ms = stream.unpack_int32()
        self.notify_default_delay_ms = stream.unpack_int32()
        self.push_chat_period_ms = stream.unpack_int32()
        self.push_chat_limit = stream.unpack_int32()
        self.saved_gifs_limit = stream.unpack_int32()
        self.edit_time_limit = stream.unpack_int32()
        self.revoke_time_limit  = stream.unpack_int32()
        self.revoke_pm_time_limit = stream.unpack_int32()
        self.rating_e_decay = stream.unpack_int32()
        self.stickers_recent_limit = stream.unpack_int32()
        self.stickers_faved_limit = stream.unpack_int32()
        self.channels_read_media_period = stream.unpack_int32()
        self.tmp_sessions = stream.unpack_int32() if flags & 1 else None
        self.pinned_dialogs_count_max = stream.unpack_int32()
        self.pinned_infolder_count_max = stream.unpack_int32()
        self.call_receive_timeout_ms = stream.unpack_int32()
        self.call_ring_timeout_ms = stream.unpack_int32()
        self.call_connect_timeout_ms = stream.unpack_int32()
        self.call_packet_timeout_ms = stream.unpack_int32()
        self.me_url_prefix = stream.unpack_string()
        self.autoupdate_url_prefix = stream.unpack_string() if flags & (1 << 7) else None
        self.gif_search_username = stream.unpack_string() if flags & (1 << 9) else None
        self.venue_search_username = stream.unpack_string() if flags & (1 << 10) else None
        self.img_search_username = stream.unpack_string() if flags & (1 << 11) else None
        self.static_maps_provider = stream.unpack_string() if flags & (1 << 12) else None
        self.caption_length_max = stream.unpack_int32()
        self.message_length_max = stream.unpack_int32()
        self.webfile_dc_id = stream.unpack_int32()
    def deserialize(self):
        return self

class UpdatesGetState(TLPacket):
    def __init__(self):
        pass
    def serialize(self):
        stream = BinaryStream()
        stream.pack_int32(0xedd4882a)
        return stream.serialize()

class UpdatesState(TLResponse):
    def __init__(self, data):
        stream = BinaryStream(data)
        packet_id = stream.unpack_int32()
        if packet_id != 0xa56c2a3e:
            raise ValueError('invalid packet!')
        self.pts = stream.unpack_int32()
        self.qts = stream.unpack_int32()
        self.date = stream.unpack_int32()
        self.seq = stream.unpack_int32()
        self.unread_count = stream.unpack_int32()
    def deserialize(self):
        return self

class UpdatesGetDifference(TLPacket):
    def __init__(self, pts, qts):
        self._pts = pts
        self._qts = qts
    def serialize(self):
        stream = BinaryStream()
        stream.pack_int32(0x25939651)
        stream.pack_int32(0)
        stream.pack_int32(self._pts)
        stream.pack_int32(int(time.time()))
        stream.pack_int32(self._qts)
        return stream.serialize()

class UpdatesDifferenceEmpty(TLResponse):
    def __init__(self, data):
        stream = BinaryStream(data)
        if stream.unpack_int32() != 0x5d75a138:
            raise ValueError('invalid packet!')
        self._date = stream.unpack_int32()
        self._seq = stream.unpack_int32()
    def deserialize(self):
        return self
    def __str__(self):
        return 'seq: {}, date: {}'.format(self._seq, self._date)

class BadServerSaltError(Exception):
    pass

class BoolTrue:
    @staticmethod
    def check(packet):
        return TLPacket.get_id_of_packet(packet) == 0x997275b5

class BoolFalse:
    @staticmethod
    def check(packet):
        return TLPacket.get_id_of_packet(packet) == 0xbc799737

class InvokeWithoutUpdates(TLPacket):
    def __init__(self, packet: TLPacket):
        self._packet = packet

    def serialize(self):
        stream = BinaryStream()
        stream.pack_int32(0xbf9459b7)
        stream.pack_bytes(self._packet.serialize())
        return stream.serialize()

class InvokeAfterMsg(TLPacket):
    def __init__(self, msg_id, packet: TLPacket):
        self._msg_id = msg_id
        self._packet = packet

    def serialize(self):
        stream = BinaryStream()
        stream.pack_int32(0xcb9f372d)
        stream.pack_int64(self._msg_id)
        stream.pack_bytes(self._packet.serialize())
        return stream.serialize()

class GetFutureSalts(TLPacket):
    def __init__(self, num=4):
        self._num = num
    def serialize(self):
        stream = BinaryStream()
        stream.pack_int32(0xb921bd04)
        stream.pack_int32(self._num)
        return stream.serialize()

class MsgResendAnsReq(TLPacket):
    def __init__(self, msg_ids: list):
        assert len(msg_ids) > 0
        self._msg_ids = msg_ids

    def serialize(self):
        stream = BinaryStream()
        stream.pack_int32(0x8610baeb)
        stream.pack_int32(len(self._msg_ids))
        for id in self._msg_ids:
            stream.pack_int64(id)
        return stream.serialize()