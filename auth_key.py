from brent import decompose
from functions import *
from message import *
from http_connection import *
import dcs

class AuthKey:
    def __init__(self, auth_key: bytes):
        self._auth_key = auth_key
    def get_auth_key(self):
        return self._auth_key
    def save_to_file(self, filename):
        with open(filename, 'wb') as f:
            f.write(len(self._auth_key).to_bytes(4, byteorder='little'))
            f.write(self._auth_key)
    @staticmethod
    def load_from_file(filename):
        with open(filename, 'rb') as f:
            size = int.from_bytes(f.read(4), byteorder='little')
            return AuthKey(f.read(size))
    @staticmethod
    def load_from_hex_string(hex_bytes):
        return AuthKey(bytes.fromhex(hex_bytes))
    @staticmethod
    def compute_fingerprint(n, e):
        stream = BinaryStream()
        n = n.to_bytes((n.bit_length() + 7) // 8, byteorder='big')
        e = e.to_bytes((e.bit_length() + 7) // 8, byteorder='big')
        stream.pack_string(n)
        stream.pack_string(e)
        return int.from_bytes(
            hashlib.sha1(stream.serialize()).digest()[-8:],
            byteorder='big'
        )
    @staticmethod
    def create_auth_key(dc_id):
        dc_info = dcs.dc_ips_and_keys[dc_id]
        n, e = dc_info['n'], dc_info['e']
        connection = HTTPConnection(dc_info['ip'])
        nonce = os.urandom(16)
        req_pq = PlainTextMessage(ReqPQPacket(nonce=nonce)).serialize()
        res_pq = connection.send(req_pq)
        packet_id, nonce_from_server, server_nonce, pq, fingerprints = ResPQPacket(res_pq).deserialize()
        if nonce_from_server != nonce:
            raise Exception('mitm attack detected!')
        new_nonce = os.urandom(32)
        p, q = decompose(pq)
        pq_inner_data_dc = PQInnerDataDC(pq=pq, p=p, q=q, nonce=nonce, server_nonce=server_nonce,
                                         new_nonce=new_nonce).serialize()
        encrypted_data = hashlib.sha1(pq_inner_data_dc).digest() + pq_inner_data_dc
        encrypted_data += bytes(255 - len(encrypted_data))
        encrypted_data = int.from_bytes(encrypted_data, byteorder='big')
        encrypted_data = pow(encrypted_data, e, n)
        encrypted_data = encrypted_data.to_bytes(256, byteorder='big')
        req_dh_params = PlainTextMessage(ReqDHParams(nonce=nonce, server_nonce=server_nonce, p=p, q=q,
                                                     fingerprint=AuthKey.compute_fingerprint(n, e),
                                                     encrypted_data=encrypted_data)).serialize()
        server_dh_params_ok = connection.send(req_dh_params)
        packet_id, nonce_from_server2, server_nonce2, encrypted_data = ServerDHParamsOk(
            data=server_dh_params_ok).deserialize()
        if nonce_from_server2 != nonce or server_nonce2 != server_nonce:
            raise Exception('mitm attack detected!')
        tmp_aes_key = hashlib.sha1(new_nonce + server_nonce).digest() + hashlib.sha1(
            server_nonce + new_nonce).digest()[
                                                                        :12]
        tmp_aes_iv = hashlib.sha1(server_nonce + new_nonce).digest()[12:20] + hashlib.sha1(
            new_nonce + new_nonce).digest() + new_nonce[:4]
        decrypted = tgcrypto.ige256_decrypt(encrypted_data, tmp_aes_key, tmp_aes_iv)[20:]
        packet_id, nonce_from_server3, server_nonce3, g, dh_prime, g_a, server_time = ServerInnerData(
            decrypted).deserialize()
        b = int.from_bytes(os.urandom(32), byteorder='big')
        g_b = pow(g, b, dh_prime)
        auth_key = pow(g_a, b, dh_prime)
        client_dh_inner_data = ClientDHInnerData(nonce=nonce, server_nonce=server_nonce, retry_id=0,
                                                 g_b=g_b).serialize()
        encrypted_data = hashlib.sha1(client_dh_inner_data).digest() + client_dh_inner_data
        if len(encrypted_data) % 16 != 0:
            encrypted_data += os.urandom(16 - len(encrypted_data) % 16)
        encrypted_data = tgcrypto.ige256_encrypt(encrypted_data, tmp_aes_key, tmp_aes_iv)
        set_client_dh_params = PlainTextMessage(
            SetClientDHParams(nonce=nonce, server_nonce=server_nonce, encrypted_data=encrypted_data)).serialize()
        dh_gen_result = connection.send(set_client_dh_params)
        dh_gen_result = DHResult(dh_gen_result)
        packet_id, nonce_from_server4, server_nonce4, new_nonce_hash = dh_gen_result.deserialize()
        auth_key_aux_hash = hashlib.sha1(auth_key.to_bytes(256, byteorder='big')).digest()[:8]
        new_nonce_hash_computed = hashlib.sha1(new_nonce + bytes([0x01]) + auth_key_aux_hash).digest()[-16:]
        if new_nonce_hash_computed != new_nonce_hash or not dh_gen_result.is_success():
            raise Exception('dh exchange failed!')
        auth_key = auth_key.to_bytes(256, byteorder='big')
        auth_key_id = hashlib.sha1(auth_key).digest()[-8:]
        server_salt = int.from_bytes(new_nonce, byteorder='little') ^ int.from_bytes(server_nonce,
                                                                                     byteorder='little')
        server_salt &= 0xFFFFFFFFFFFFFFFF
        return AuthKey(auth_key)

    def get_auth_key_id(self):
        return hashlib.sha1(self._auth_key).digest()[-8:]