from session import Session
import tl_types_all
from functions import BytesPacket, RpcError
from auth_key import AuthKey

class Auth:
    def __init__(self, session, api_id, api_hash):
        self._session = session
        self._api_id = api_id
        self._api_hash = api_hash

    def send_code(self, phone_number: str):
        response = self._session.send_packet(BytesPacket(tl_types_all.auth_sendCode(phone_number=phone_number.encode(), api_id=self._api_id, api_hash=self._api_hash.encode(),
                                                                                    settings=tl_types_all.codeSettings()).write()))
        if RpcError.check_for_error(response):
            raise Exception(RpcError.get_error(response))
        result = tl_types_all.auth_sentCode().read(response)
        self._phone_number = phone_number.encode()
        self._phone_hash = result.phone_code_hash

    def sign_in(self, phone_code: str):
        response = self._session.send_packet(BytesPacket(tl_types_all.auth_signIn(phone_code=phone_code.encode(), phone_number=self._phone_number, phone_code_hash=self._phone_hash).write()))
        if RpcError.check_for_error(response):
            raise Exception(RpcError.get_error(response))