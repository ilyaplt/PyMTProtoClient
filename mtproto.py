import mtproto_impl
import functions
import dcs
from auth_key import AuthKey

class MTProto:
    def __init__(self, api_id, api_hash, dc_id=2, device_model='Unknown UserAgent', system_version='1.0', auth_key: AuthKey = None):
        if dc_id not in dcs.dc_ips_and_keys:
            raise ValueError('dc was not found!')
        dc_config = dcs.dc_ips_and_keys[dc_id]
        self._mtproto = mtproto_impl.MTProtoClient.create_client(ip=dc_config['ip'], n_part_of_key=dc_config['n'], e_part_of_key=dc_config['e'], api_id=api_id, api_hash=api_hash, device_model=device_model, system_version=system_version, auth_key=auth_key.get_auth_key() if auth_key else None)
    def send_packet(self, packet: functions.TLPacket):
        try:
            return self._mtproto.send_packet(packet)
        except OSError:
            self._mtproto.init_tcp_ip()
        except functions.BadServerSaltError:
            return self.send_packet(packet)
        except functions.BadMsgNotificationException:
            return self.send_packet(packet)
    def get_auth_key(self):
        return AuthKey(self._mtproto.get_auth_key())