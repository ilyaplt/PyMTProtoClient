import functions
from functions import TLPacket, TLResponse
import os

class Flags:
    def __init__(self, flags):
        self._flags = flags

    def check_bit(self, n):
        return bool(self._flags & (1 << n))

class FileLocation(TLResponse):
    def __init__(self, stream: functions.BinaryStream):
        if stream.unpack_int32() != 0xbc7fc6cd:
            raise ValueError()
        self.volume_id = stream.unpack_int64()
        self.local_dc = stream.unpack_int32()
    def deserialize(self):
        return self

class UserProfilePhoto(TLResponse):
    def __init__(self, stream: functions.BinaryStream):
        packet_id = stream.unpack_int32()
        self.empty_photo = True
        if packet_id == 0x4f11bae1:
            return
        elif packet_id == 0x69d3ab26:
            self.empty_photo = False
        else:
            raise ValueError()
        flags = Flags(stream.unpack_int32())
        self.has_video = flags.check_bit(0)
        self.photo_id = stream.unpack_int64()
        self.photo_small = FileLocation(stream)
        self.photo_big = FileLocation(stream)
        self.dc_id = stream.unpack_int32()
    def deserialize(self):
        pass

class UserStatusDescription:
    pass

class RestrictionsReason(TLResponse):
    def __init__(self, stream: functions.BinaryStream):
        if stream.unpack_int32() != 0xd072acb4:
            raise ValueError()
        self.platform = stream.unpack_string()
        self.reason = stream.unpack_string()
        self.text = stream.unpack_string()

class VectorRestrictionsReason(TLResponse):
    def __init__(self, stream: functions.BinaryStream):
        if stream.unpack_int32() != 0x1cb5c415:
            raise ValueError()
        vector_size = stream.unpack_int32()
        self.reasons = []
        for i in range(vector_size):
            self.reasons.append(RestrictionsReason(stream))

class InputUser:
    pass

class InputUserSelf(TLPacket, InputUser):
    def __init__(self):
        pass
    def serialize(self):
        return int('f7c1b13f', 16).to_bytes(4, byteorder='little')

class InputPeer(TLPacket):
    pass

class InputPeerUser(InputPeer):
    def __init__(self, user_id, access_hash):
        self._user_id = user_id
        self._access_hash = access_hash
    def serialize(self):
        stream = functions.BinaryStream()
        stream.pack_int32(0x7b8e7de6)
        stream.pack_int32(self._user_id)
        stream.pack_int64(self._access_hash)
        return stream.serialize()

class InputPeerSelf(InputPeer):
    def __init__(self):
        pass
    def serialize(self):
        return int(0x7da07ec9).to_bytes(4, byteorder='little')

class UsersGetUsers(TLPacket):
    def __init__(self, user_inputs):
        self._user_inputs = user_inputs
    def serialize(self):
        stream = functions.BinaryStream()
        stream.pack_int32(0xd91a548)
        stream.pack_int32(0x1cb5c415)
        stream.pack_int32(len(self._user_inputs))
        for k in self._user_inputs:
            if isinstance(k, InputUser) and k != InputUser:
                stream.pack_bytes(k.serialize())
            else:
                raise ValueError()
        return stream.serialize()

class UserDescription:
    def __init__(self, id: int = None, is_self=False, contact=False, mutual_contact=False,
                 deleted=False, bot=False, bot_chat_history=False, bot_nochats=False,
                 verified=False, restricted=False, min=False, bot_inline_geo=False,
                 support=False, scam=False, apply_min_photo=False, fake=False,
                 access_hash: int = None, first_name: str = None, last_name: str = None,
                 username: str = None, phone: str = None, photo: UserProfilePhoto = None,
                 status: UserStatusDescription = None, bot_info_version: int = None,
                 restriction_reason: VectorRestrictionsReason = None, bot_inline_placeholder: str = None,
                 lang_code: str = None
                 ):
        self.id = id
        self.is_self = is_self
        self.contact = contact
        self.mutual_contact = mutual_contact
        self.deleted = deleted
        self.bot = bot
        self.bot_chat_history = bot_chat_history
        self.bot_nochats = bot_nochats
        self.verified = verified
        self.restricted = restricted
        self.min = min
        self.bot_inline_geo = bot_inline_geo
        self.support = support
        self.scam = scam
        self.apply_min_photo = apply_min_photo
        self.fake = fake
        self.access_hash = access_hash
        self.first_name = first_name
        self.last_name = last_name
        self.username = username
        self.phone = phone
        self.photo = photo
        self.status = status
        self.bot_info_version = bot_info_version
        self.restriction_reason = restriction_reason
        self.bot_inline_placeholder = bot_inline_placeholder
        self.lang_code = lang_code

class UserEmpty:
    def __init__(self):
        pass

class User(TLPacket):
    def __init__(self, data):
        stream = functions.BinaryStream(data)
        packet_id = stream.unpack_int32()
        if packet_id == 0x200250ba:
            return UserEmpty()
        elif packet_id != 0x938458c1:
            raise ValueError()
        flags = Flags(stream.unpack_int32())
        is_self = flags.check_bit(10)
        contact = flags.check_bit(11)
        mutual_contact = flags.check_bit(12)
        deleted = flags.check_bit(13)
        bot = flags.check_bit(14)
        bot_chat_history = flags.check_bit(15)
        bot_no_chats = flags.check_bit(16)
        verified = flags.check_bit(17)
        restricted = flags.check_bit(18)
        min = flags.check_bit(20)
        bot_inline_geo = flags.check_bit(21)
        support = flags.check_bit(23)
        scam = flags.check_bit(24)
        apply_min_photo = flags.check_bit(25)
        user_id = stream.unpack_int32()
        access_hash = stream.unpack_int64() if flags.check_bit(0) else None
        first_name = stream.unpack_string() if flags.check_bit(1) else None
        last_name = stream.unpack_string() if flags.check_bit(2) else None
        username = stream.unpack_string() if flags.check_bit(3) else None
        phone = stream.unpack_string() if flags.check_bit(4) else None
        photo = UserProfilePhoto(stream) if flags.check_bit(5) else None
        status = UserStatus(stream, is_standard_constructor=False) if flags.check_bit(6) else None
        bot_info_version = stream.unpack_int32() if flags.check_bit(14) else None
        restrictions_reasons = VectorRestrictionsReason(stream) if flags.check_bit(18) else None
        bot_inline_placeholder = stream.unpack_string() if flags.check_bit(19) else None
        lang_code = stream.unpack_string() if flags.check_bit(22) else None
        self._user_description = UserDescription(user_id, is_self, contact, mutual_contact, deleted,
                                                 bot, bot_chat_history, bot_no_chats, verified, restricted,
                                                 min, bot_inline_geo, support, scam, apply_min_photo, user_id,
                                                 access_hash, first_name, last_name, username, phone, photo, status, bot_info_version, restrictions_reasons, bot_inline_placeholder, lang_code)
        self._least_buffer_size = len(stream.serialize())
    def deserialize(self):
        return self._user_description
    def get_least_buffer_size(self):
        return self._least_buffer_size

class UserVector(TLResponse):
    def __init__(self, data):
        stream = functions.BinaryStream(data)
        if stream.unpack_int32() != 0x1cb5c415:
            raise ValueError()
        vector_size = stream.unpack_int32()
        data = stream.serialize()
        self.users = []
        for i in range(vector_size):
            user = User(data)
            data = data[len(data) - user.get_least_buffer_size():]
            self.users.append(user)
    def deserialize(self):
        return self

class UserStatus(TLResponse):

    class UserStatusEmpty:
        pass

    class UserStatusOnline:
        pass

    class UserStatusOffline:
        def __init__(self, was_online):
            self._was_online = was_online
        def get_last_time_when_profile_was_online(self):
            return self._was_online

    class UserStatusRecently:
        pass

    class UserStatusLastWeek:
        pass

    class UserStatusLastMonth:
        pass

    def __init__(self, stream: functions.BinaryStream, is_standard_constructor=True):
        if is_standard_constructor:
            packet_id = stream.unpack_int32()
            if packet_id != 0xd3680c61:
                raise ValueError()
            self.user_id = stream.unpack_int32()
        status_packet_id = stream.unpack_int32()
        self.user_status = None
        self.packet_length = 4
        if status_packet_id == 0x9d05049:
            self.user_status = UserStatus.UserStatusEmpty
            self.packet_length += 4
        elif status_packet_id == 0xedb93949:
            self.user_status = UserStatus.UserStatusOnline
            stream.unpack_int32()
            self.packet_length += 8
        elif status_packet_id == 0x8c703f:
            self.user_status = UserStatus.UserStatusOffline(stream.unpack_int32())
            self.packet_length += 8
        elif status_packet_id == 0xe26f42f1:
            self.user_status = UserStatus.UserStatusRecently
            self.packet_length += 4
        elif status_packet_id == 0x7bf09fc:
            self.user_status = UserStatus.UserStatusLastWeek
            self.packet_length += 4
        elif status_packet_id == 0x77ebc742:
            self.user_status = UserStatus.UserStatusLastMonth
            self.packet_length += 4
    def deserialize(self):
        return self

class UserStatuses(TLResponse):
    def __init__(self, data):
        stream = functions.BinaryStream(data)
        if stream.unpack_int32() != 0x1cb5c415:
            raise ValueError()
        vector_size = stream.unpack_int32()
        self.statuses = []
        for i in range(vector_size):
            self.statuses.append(UserStatus(stream))

    def deserialize(self):
        return self

class Contact(TLResponse):
    def __init__(self, data):
        stream = functions.BinaryStream(data)
        ctor = stream.unpack_int32()
        if ctor != 0xf911c994:
            raise ValueError()
        self.user_id = stream.unpack_int32()
        is_mutual = stream.unpack_bytes(4)
        self.mutual = True if functions.BoolTrue.check(is_mutual) else False
    def deserialize(self):
        return self

class VectorContact(TLResponse):
    def __init__(self, stream: functions.BinaryStream):
        if stream.unpack_int32() != 0x1cb5c415:
            raise ValueError()
        vector_size = stream.unpack_int32()
        self.contacts = []
        for i in range(vector_size):
            contact_bytes = stream.unpack_bytes(12)
            self.contacts.append(Contact(contact_bytes))
    def deserialize(self):
        return self.contacts

class Contacts(TLResponse):
    def __init__(self, data):
        stream = functions.BinaryStream(data)
        if stream.unpack_int32() != 0xeae87e42:
            raise ValueError()
        self.contacts = VectorContact(stream)
        self.saved_count = stream.unpack_int32()
        self.users = UserVector(stream.serialize())

class ContactsGetStatuses(TLPacket):
    def __init__(self):
        pass
    def serialize(self):
        return int('c4a353ee', 16).to_bytes(4, byteorder='little')

class ContactsGetContacts(TLPacket):
    def __init__(self):
        pass
    def serialize(self):
        stream = functions.BinaryStream()
        stream.pack_int32(0xc023849f)
        stream.pack_int32(0)
        return stream.serialize()

class ContactsResolveUserName(TLPacket):
    def __init__(self, username):
        self._username = username
    def serialize(self):
        stream = functions.BinaryStream()
        stream.pack_int32(0xf93ccba3)
        stream.pack_string(self._username.encode())
        return stream.serialize()

class ContactsResolvedPeer(TLResponse):
    def __init__(self, data):
        stream = functions.BinaryStream(data)
        if stream.unpack_int32() != 0x7f077ad9:
            raise ValueError()
        stream.unpack_bytes(8)
        if stream.unpack_int32() != 0x1cb5c415:
            raise ValueError()
        while stream.unpack_int32() != 0x1cb5c415:
            pass
        stream = functions.BinaryStream(int(0x1cb5c415).to_bytes(4, byteorder='little') + stream.serialize())
        self.users = UserVector(stream.serialize())
    def deserialize(self):
        return self

class SendMessage(TLPacket):
    def __init__(self, input_peer: InputPeer, text: str):
        self._input_peer = input_peer
        self._text = text
    def serialize(self):
        stream = functions.BinaryStream()
        stream.pack_int32(0x520c3870)
        stream.pack_int32(0)
        stream.pack_bytes(self._input_peer.serialize())
        stream.pack_string(self._text.encode())
        stream.pack_int64(int.from_bytes(os.urandom(8), byteorder='little'))
        return stream.serialize()

class InputFileLocation(TLPacket):
    pass

class InputPeerPhotoFileLocation(InputFileLocation):
    def __init__(self, peer: InputPeer, volume_id, local_id, big=False):
        self._volume_id = volume_id
        self._local_id = local_id
        self._peer = peer
        self._big = big

    def serialize(self):
        stream = functions.BinaryStream()
        stream.pack_int32(0x27d69997)
        stream.pack_int32(1 if self._big else 0)
        stream.pack_bytes(self._peer.serialize())
        stream.pack_int64(self._volume_id)
        stream.pack_int32(self._local_id)
        return stream.serialize()

class UploadGetFile(TLPacket):
    def __init__(self, file: InputFileLocation, offset, mb_limit):
        self._file = file
        self._offset = offset
        self._limit = mb_limit * 1048576

    def serialize(self):
        stream = functions.BinaryStream()
        stream.pack_int32(0xb15a9afc)
        stream.pack_int32(0x0)
        stream.pack_bytes(self._file.serialize())
        stream.pack_int32(self._offset)
        stream.pack_int32(self._limit)
        return stream.serialize()

class StorageFileType:
    @staticmethod
    def resolve_file_type(packet):
        packet_id = functions.TLPacket.get_id_of_packet(packet)
        if packet_id == 0xaa963b05:
            return 'unknown'
        elif packet_id == 0x40bc6f52:
            return 'partial'
        elif packet_id == 0x7efe0e:
            return 'jpeg'
        elif packet_id == 0xcae1aadf:
            return 'gif'
        elif packet_id == 0xa4f63c0:
            return 'png'
        elif packet_id == 0xae1e508d:
            return 'pdf'
        elif packet_id == 0x528a0677:
            return 'mp3'
        elif packet_id == 0x4b09ebbc:
            return 'mov'
        elif packet_id == 0xb3cea0e4:
            return 'mp4'
        elif packet_id == 0x1081464c:
            return 'webp'
        else:
            raise ValueError()

class UploadFile(TLResponse):
    def __init__(self, data):
        stream = functions.BinaryStream(data)
        if stream.unpack_int32() != 0x96a18d5:
            raise ValueError()
        self.file_type = StorageFileType.resolve_file_type(stream.unpack_bytes(4))
        self.mtime = stream.unpack_int32()
        self.bytes = stream.unpack_string()
    def deserialize(self):
        return self

class InputContact(TLPacket):
    def __init__(self, phone_number, first_name, last_name):
        self._phone_number = phone_number
        self._first_name = first_name
        self._last_name = last_name
    def serialize(self):
        stream = functions.BinaryStream()
        stream.pack_int32(0xf392b7f4)
        stream.pack_int64(int.from_bytes(os.urandom(8), byteorder='little'))
        stream.pack_string(self._phone_number.encode())
        stream.pack_string(self._first_name.encode())
        stream.pack_string(self._last_name.encode())
        return stream.serialize()

class ContactsImportContact(TLPacket):
    def __init__(self, contact: InputContact):
        self._contact = [contact]
    def serialize(self):
        stream = functions.BinaryStream()
        stream.pack_int32(0x2c800be5)
        stream.pack_vector(self._contact)
        return stream.serialize()