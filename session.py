import functions
from functions import *
from msg_id import MsgId
from auth_key import AuthKey
from http_connection import HTTPConnection
from tcp import *
from message import *
import dcs
import time
import os
import threading
import gzip
import queue
import logging
import gzip

class Session:

    UPDATE_CONSTRUCTORS_IDS = [
        0xe317af7e,
        0x78d4dec1,
        0x313bc7f8,
        0x4d6deea5,
        0x9015e101,
        0x725b04c3,
        0x74ae4240
    ]
    def __init__(self, dc_id, api_id, auth_key: AuthKey = None, layer=133):

        if not auth_key:
            auth_key = AuthKey.create_auth_key(dc_id)
            self._auth_key = auth_key.get_auth_key()
            self._auth_key_id = auth_key.get_auth_key_id()
        else:
            self._auth_key = auth_key.get_auth_key()
            self._auth_key_id = auth_key.get_auth_key_id()

        self._connection = TCPIntermediate((dcs.dc_ips_and_keys[dc_id]['ip'], 443))

        self._layer = layer

        self._api_id = api_id

        self._updates = queue.Queue()

        self._to_send_queue = queue.Queue()

        self._msg_id = MsgId()

        self._msg_id.set_msg_id(int(time.time()))

        self._seq_no = 0

        self._session_id = int.from_bytes(os.urandom(8), byteorder='little')

        self._server_salt = 0

        self._msg_ids = set()

        self._results = {}

        self._pending_acks = set()

        self._mutex = threading.RLock()

        self._queue_mutex = threading.RLock()

        self._disabled = threading.Event()

        self._new_session_created = threading.Event()

        self._on_session_enabled = None

        self._on_session_enabled_args = None

    def start(self):
        self._connection.init_connection()
        self._disabled = threading.Event()
        thread = threading.Thread(target=self._packet_receiver)
        thread.start()
        thread = threading.Thread(target=self._ping_worker)
        thread.start()
        thread = threading.Thread(target=self._packet_sender_from_queue)
        thread.start()
        while self._server_salt == 0:
            pass
        self.send_packet(InvokeWithLayer(layer=self._layer, packet=InitConnection(query=functions.GetConfig(), api_id=self._api_id, device_model='IBM PC/AT', system_version='DOS 6.22')))

    def stop(self):
        self._disabled.set()
        self._server_salt = 0
        self._session_id = int.from_bytes(os.urandom(8), byteorder='little')
        self._connection.close()

    def get_session(self):
        return AuthKey(self._auth_key)

    def _add_result(self, message_id: int, packet: TLResponse):
        with self._queue_mutex:
            self._results[message_id] = packet

    def _get_result(self, message_id: int):
        with self._queue_mutex:
            if message_id in self._results:
                result = self._results[message_id]
                del self._results[message_id]
                return result

    def create_msg_id(self):
        return self._msg_id.get_msg_id()

    def _create_seq_no(self, is_content_related=True):
        if not is_content_related:
            return self._seq_no * 2
        seq_no = self._seq_no * 2 + 1
        self._seq_no += 1
        return seq_no

    def set_session_enabled_callback(self, func, args=None):
        self._on_session_enabled = func
        self._on_session_enabled_args = args

    def send_packet(self, packet: TLPacket, is_content_related=True, wait_response=True, sent_from_service_thread=False):
        with self._mutex:
            message_id = self.create_msg_id()
            seq_no = self._create_seq_no(is_content_related)

            if seq_no >= 400000000:
                self.stop()
                self._seq_no = 0
                self.start()

            msg = Message(auth_key_id=self._auth_key_id, auth_key=self._auth_key, object=packet, server_salt=self._server_salt,
                          session_id=self._session_id, seq_no=seq_no, message_id=message_id)

        self._connection.send(msg.pack())

        if not wait_response:
            return

        result = self._get_result(message_id)

        i = 0

        while not result:
            if self._new_session_created.is_set() and not sent_from_service_thread:
                self._new_session_created.clear()
                return result
            result = self._get_result(message_id)
            if result:
                break
            if i < 10000:
                i += 1
            else:
                return None
            time.sleep(0.01)

        return result

    def _packet_receiver(self):
        while not self._disabled.is_set():
            try:
                response = self._connection.receive()
                if response == b'' or len(response) < 32:
                    self.reset_session()
                    time.sleep(0.1)
                    self._connection.init_connection()
                    print('invalid connection.. reconnecting')
                    self._to_send_queue.put(functions.Ping(ping_id=0xdeadbeef))
                    continue
                result = self._unpack_message(response)
                #logging.info('got packet: {}'.format(result))
                self._process_packets(result['message_id'], result['seq_no'], result['response'])
            except Exception as e:
                print('in packet receiver:', e)
                pass

    def _ping_worker(self):
        while not self._disabled.is_set():
            try:
                ping_id = int.from_bytes(os.urandom(4), byteorder='little')
                logging.info('sending ping with id {}'.format(ping_id))
                logging.info(str(self.send_packet(Ping(ping_id=ping_id), False, True)))
                time.sleep(10)
            except:
                pass

    def _packet_sender_from_queue(self):
        while not self._disabled.is_set():
            try:
                packet = self._to_send_queue.get()
                for i in range(3):
                    self.send_packet(packet, False, False)
                print('packet has sent from queue!')
            except:
                pass

    def check_for_incoming_updates(self, block=False, timeout=None):
        try:
            return self._updates.get(block=block, timeout=timeout)
        except queue.Empty:
            return None

    def reset_session(self):
        self._session_id = int.from_bytes(os.urandom(8), byteorder='little')

    def _process_packet(self, message_id, seq_no, data, check_for_msg_id=True):
        if len(self._msg_ids) > 1000:
            self._msg_ids = set(list(self._msg_ids)[500:])
        packet_id = TLPacket.get_id_of_packet(data)
        if check_for_msg_id and message_id in self._msg_ids:
            return
        elif check_for_msg_id and message_id not in self._msg_ids:
            self._msg_ids.add(message_id)

        if check_for_msg_id and seq_no % 2 == 1:
            self._pending_acks.add(seq_no)

        if packet_id == 0xedab447b: # bad server salt
            bad_server_salt = BadServerSalt(data)
            packet_id, bad_msg_id, bad_msg_seqno, error_code, new_server_salt = BadServerSalt(data).deserialize()
            self._server_salt = new_server_salt
            print('new server salt:', self._server_salt)
            self._add_result(bad_msg_id, bad_server_salt)

        elif packet_id == 0xa7eff811: # bad message notification
            bad_msg_notification = BadMsgNotification(data)
            packet_id, bad_msg_id, bad_msg_seqno, error_code = bad_msg_notification.deserialize()
            self._add_result(bad_msg_id, bad_msg_notification)

        elif packet_id == 0x9ec20908: # new session created
            print('new session created')
            if self._on_session_enabled:
                self._new_session_created.set()
                if not self._on_session_enabled_args:
                    thread = threading.Thread(target=self._on_session_enabled)
                    thread.start()
                else:
                    thread = threading.Thread(target=self._on_session_enabled, args=self._on_session_enabled_args)
                    thread.start()

        elif packet_id == 0x347773c5: # pong
            ping_msg_id, ping_id = Pong(data).deserialize()
            pong = Pong(data)
            pong.deserialize()
            self._add_result(ping_msg_id, pong)

        elif packet_id == 0x62d6b459: # msg acks
            pass

        elif packet_id == 0xf35c6d01: # rpc result
            packet_id, req_msg_id, packet = RpcResult(data).deserialize()

            if TLPacket.get_id_of_packet(packet) == 0x3072cfa1:
                packet_id, gzipped = GZipPacked(packet).deserialize()
                packet = gzip.decompress(gzipped)

            self._add_result(req_msg_id, packet)

        elif packet_id == 0x3072cfa1: # gzip packet
            packet_id, packed_data = GZipPacked(data).deserialize()
            unpacked_data = gzip.decompress(packed_data)
            self._process_packet(message_id, seq_no, unpacked_data, False)

        elif packet_id in self.UPDATE_CONSTRUCTORS_IDS: # new incoming update
            # paste handler for update handling
            self._updates.put(data)
            pass

        else:
            #print('unknown packet, ID:', hex(packet_id))
            pass

        if len(self._pending_acks) > 8:
            acks = list(self._pending_acks)
            self._pending_acks.clear()
            self.send_packet(MsgAcksPacket(msg_ids=acks), wait_response=False, sent_from_service_thread=True)

    def _process_packets(self, message_id, seq_no, data):
        if MessageContainerResponse.is_message_container(data):
            results = []
            packets = MessageContainerResponse(data).deserialize()
            for packet in packets:
                result = self._process_packet(packet[0], packet[1], packet[2])
                if result:
                    results.append(result)
        else:
            self._process_packet(message_id, seq_no, data)

    def _unpack_message(self, message: bytes):
        server_salt, session_id, message_id, seq_no, response = MessageResponse(self._auth_key, message).unpack()

        return {
            'server_salt': server_salt,
            'session_id': session_id,
            'message_id': message_id,
            'seq_no': seq_no,
            'response': response
        }

    def __enter__(self):
        self.start()

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.stop()
