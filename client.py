from session import Session
from functions import BytesPacket, RpcError, ImportBotAuthorization, BadServerSalt, BadMsgNotification
import tl_types_all
import time
import logging
import os
import functions
import threading

class TelegramError(Exception):
    def __init__(self, reason):
        self._reason = reason

    def __str__(self):
        return self._reason

class Client:
    def call_method(self, method, wait_response=True, service_call=False):
        result = self._session.send_packet(self._pack_method(method), wait_response=wait_response, sent_from_service_thread=service_call)
        if not result and wait_response:
            return self.call_method(method, wait_response)
        if isinstance(result, BadMsgNotification):
            return self.call_method(method, wait_response)
        elif isinstance(result, BadServerSalt):
            return self.call_method(method, wait_response)
        return result
    def _pack_method(self, packet):
        return BytesPacket(packet.write())

    def __init__(self, api_id, api_hash, dc_id=2, auth_key=None):
        self._api_id = api_id
        self._api_hash = api_hash
        self._session = Session(dc_id, api_id=self._api_id, auth_key=auth_key)
        self.start()
        time.sleep(1)
        self._session.set_session_enabled_callback(self._on_session_created)
        self._qts = None
        self._pts = None
        self._update_date = None
        self._get_new_update_state_in_new_session = False

    def get_new_update_state_in_new_session(self, value):
        self._get_new_update_state_in_new_session = value

    def get_updates_state(self):
        response = self.call_method(tl_types_all.updates_getState(), service_call=True)
        if RpcError.check_for_error(response):
            raise TelegramError(RpcError.get_error(response))
        return tl_types_all.updates_State().read(response)

    def set_updates_state(self):
        update_state = self.get_updates_state()
        logging.info('got new update state object: {}'.format(update_state))
        self._qts, self._pts, self._update_date = update_state.qts, update_state.pts, update_state.date

    def _get_updates(self, qts, pts, date):
        try:
            response = self.call_method(tl_types_all.updates_getDifference(qts=qts, pts=pts, date=date))
            if RpcError.check_for_error(response):
                raise TelegramError(RpcError.get_error(response))
            return tl_types_all.updates_Difference().read(response)
        except AttributeError:
            return self._get_updates(qts, pts, date)
        except TypeError:
            return self._get_updates(qts, pts, date)

    def get_updates(self):
        bot_updates = []
        if not self._qts and not self._pts and not self._update_date:
            self.set_updates_state()
        updates = self._get_updates(self._qts, self._pts, self._update_date)
        if hasattr(updates, 'state'):
            self._qts, self._pts, self._update_date = updates.state.qts, updates.state.pts, updates.state.date
        elif hasattr(updates, 'intermediate_state'):
            self._qts, self._pts, self._update_date = updates.intermediate_state.qts, updates.intermediate_state.pts, updates.intermediate_state.date
        elif hasattr(updates, 'date'):
            self._update_date = updates.date
        if isinstance(updates, tl_types_all.updates_difference):
            for message_update, user in zip(updates.new_messages, updates.users):
                if isinstance(message_update, tl_types_all.message):
                    bot_updates.append({'update': message_update, 'user': user})
                else:
                    print(message_update)
        return bot_updates

    def get_incoming_updates(self, block=False):
        updates = self._session.check_for_incoming_updates(block)
        if not updates: return None
        updates = tl_types_all.Updates().read(updates)
        bot_updates = []
        if isinstance(updates, tl_types_all.updateShortMessage):
            return updates
        if not hasattr(updates, 'updates') or not hasattr(updates, 'users'):
            return bot_updates
        for update, user in zip(updates.updates, updates.users):
            if isinstance(update, tl_types_all.updateNewMessage):
                if update.pts > self._pts and not update.message.out:
                    self._pts = update.pts
                    bot_updates.append((update.message, user))
            elif isinstance(update, tl_types_all.updateBotCallbackQuery):
                bot_updates.append((update, user))
            elif isinstance(update, tl_types_all.updatePhoneCall):
                bot_updates.append((update, user))
            else:
                print(update)
        return bot_updates

    @staticmethod
    def generate_random_id():
        return int.from_bytes(os.urandom(8), byteorder='little')

    def auth_as_bot(self, bot_token, api_id, api_hash):
        auth_response = self.get_session().send_packet(
            functions.ImportBotAuthorization(api_id=api_id, api_hash=api_hash,
                                             bot_token=bot_token))
        if functions.RpcError.check_for_error(auth_response):
            raise SystemExit

    def send_message(self, user_id, access_hash, text, keyboard_buttons=None, inline_buttons=None, remove_keyboard=False):
        request = tl_types_all.messages_sendMessage(peer=tl_types_all.inputPeerUser(user_id, access_hash),
                                                    random_id=Client.generate_random_id(), message=text.encode())
        if keyboard_buttons and inline_buttons:
            raise ValueError()
        if keyboard_buttons:
            keyboard_markup = []
            for row in keyboard_buttons:
                buttons = []
                for button in row:
                    buttons.append(tl_types_all.keyboardButton(button.encode()))
                keyboard_markup.append(tl_types_all.keyboardButtonRow(buttons=buttons))
            request.reply_markup = tl_types_all.replyKeyboardMarkup(rows=keyboard_markup)
        elif inline_buttons:
            keyboard_markup = []
            for row in inline_buttons:
                buttons = []
                for button in row:
                    buttons.append(
                        tl_types_all.keyboardButtonCallback(text=button['text'].encode(), data=button['data'].encode()))
                keyboard_markup.append(tl_types_all.keyboardButtonRow(buttons=buttons))
            keyboard_markup = tl_types_all.replyInlineMarkup(rows=keyboard_markup)
            request.reply_markup = keyboard_markup
        elif remove_keyboard:
            request.reply_markup = tl_types_all.replyKeyboardHide()
        self.call_method(request, False)

    def edit_message(self, msg_id, user_id, access_hash, text, keyboard_buttons=None, inline_buttons=None):
        request = tl_types_all.messages_editMessage(peer=tl_types_all.inputPeerUser(user_id, access_hash), id=msg_id,
                                                    message=text.encode())
        if keyboard_buttons and inline_buttons:
            raise ValueError()
        if keyboard_buttons:
            keyboard_markup = []
            for row in keyboard_buttons:
                buttons = []
                for button in row:
                    buttons.append(tl_types_all.keyboardButton(button.encode()))
                keyboard_markup.append(tl_types_all.keyboardButtonRow(buttons=buttons))
            request.reply_markup = tl_types_all.replyKeyboardMarkup(rows=keyboard_markup)
        elif inline_buttons:
            keyboard_markup = []
            for row in inline_buttons:
                buttons = []
                for button in row:
                    buttons.append(
                        tl_types_all.keyboardButtonCallback(text=button['text'].encode(), data=button['data'].encode()))
                keyboard_markup.append(tl_types_all.keyboardButtonRow(buttons=buttons))
            keyboard_markup = tl_types_all.replyInlineMarkup(rows=keyboard_markup)
            request.reply_markup = keyboard_markup
        self.call_method(request, False)

    def send_media(self, input_media, user_id, access_hash, message='', keyboard_buttons=None, inline_buttons=None, remove_keyboard=False):
        request = tl_types_all.messages_sendMedia(peer=tl_types_all.inputPeerUser(user_id, access_hash),
                                                    random_id=Client.generate_random_id(), media=input_media, message=message.encode())
        if keyboard_buttons and inline_buttons:
            raise ValueError()
        if keyboard_buttons:
            keyboard_markup = []
            for row in keyboard_buttons:
                buttons = []
                for button in row:
                    buttons.append(tl_types_all.keyboardButton(button.encode()))
                keyboard_markup.append(tl_types_all.keyboardButtonRow(buttons=buttons))
            request.reply_markup = tl_types_all.replyKeyboardMarkup(rows=keyboard_markup)
        elif inline_buttons:
            keyboard_markup = []
            for row in inline_buttons:
                buttons = []
                for button in row:
                    buttons.append(
                        tl_types_all.keyboardButtonCallback(text=button['text'].encode(), data=button['data'].encode()))
                keyboard_markup.append(tl_types_all.keyboardButtonRow(buttons=buttons))
            keyboard_markup = tl_types_all.replyInlineMarkup(rows=keyboard_markup)
            request.reply_markup = keyboard_markup
        elif remove_keyboard:
            request.reply_markup = tl_types_all.replyKeyboardHide()
        self.call_method(request, False)

    def set_typing(self, user_id, access_hash, typing_action=tl_types_all.sendMessageTypingAction):
        request = tl_types_all.messages_setTyping(peer=tl_types_all.inputPeerUser(user_id=user_id, access_hash=access_hash), action=typing_action)
        self.call_method(request, False)

    def _upload_small_file_part(self, content, file_id, file_part):
        response = self.call_method(
            tl_types_all.upload_saveFilePart(file_id=file_id, file_part=file_part, bytes=content))
        if functions.TLPacket.get_id_of_packet(response) != 0x997275b5:
            print(response)
            raise ValueError('uploading error')

    def upload_small_file(self, filename, title=None):
        with open(filename, 'rb') as f:
            content = f.read()
            if content == b'':
                raise ValueError('empty file')
            file_id = Client.generate_random_id()
            file_part = 0
            while content != b'':
                self._upload_small_file_part(content[:1024 * 512], file_id, file_part)
                file_part += 1
                content = content[1024 * 512:]
            input_file = tl_types_all.inputFile(id=file_id, parts=file_part,
                                                name=title.encode() if title else filename.encode(), md5_checksum=b'')
            return input_file

    def get_uploaded_document_from_file_input(self, input_file, mime='application/octet-stream', filename=None):
        attributes = []
        if filename:
            attributes.append(tl_types_all.documentAttributeFilename(file_name=filename.encode()))
        input_media_uploaded_document = tl_types_all.inputMediaUploadedDocument(file=input_file,
                                                                                mime_type=mime.encode(),
                                                                                attributes=attributes)
        return input_media_uploaded_document

    def get_uploaded_audio_from_file_input(self, input_file, duration, voice_sound=True):
        attributes = []
        attributes.append(tl_types_all.documentAttributeAudio(duration=duration, voice=voice_sound))
        input_media_uploaded_document = tl_types_all.inputMediaUploadedDocument(file=input_file,
                                                                                mime_type=b'audio/mpeg',
                                                                                attributes=attributes)
        return input_media_uploaded_document

    def get_uploaded_photo_from_file_input(self, input_file):
        input_media_uploaded_document = tl_types_all.inputMediaUploadedPhoto(file=input_file)
        return input_media_uploaded_document

    def check_for_document_in_message_update(self, update):
        if update.media:
            if isinstance(update.media, tl_types_all.messageMediaDocument):
                return True
        return False

    def get_file_content(self, file_location, offset=0, limit=1048576):
        response = self.call_method(
            tl_types_all.upload_getFile(precise=True, location=file_location, offset=offset, limit=limit))
        if functions.RpcError.check_for_error(response):
            raise ValueError(functions.RpcError.get_error(response))
        response = tl_types_all.upload_File().read(response)
        return response.bytes

    def download_document_from_message_update(self, media: tl_types_all.messageMediaDocument):
        document = media.document
        input_file_location = tl_types_all.inputDocumentFileLocation(id=document.id, access_hash=document.access_hash,
                                                                     file_reference=document.file_reference,
                                                                     thumb_size=b'')
        size = document.size
        content = self.get_file_content(input_file_location)
        while len(content) < size:
            content += self.get_file_content(input_file_location, offset=len(content))
        return content

    def get_filename_from_updates_document(self, media: tl_types_all.messageMediaDocument):
        for attribute in media.document.attributes:
            if isinstance(attribute, tl_types_all.documentAttributeFilename):
                return attribute.file_name.decode()

    def _on_session_created(self):
        if self._get_new_update_state_in_new_session:
            print('updating update state!')
            self.set_updates_state()
            print('new update state!')

    def start(self):
        self._session.start()

    def stop(self):
        self._session.stop()

    def get_session(self):
        return self._session

    def __del__(self):
        self._session.stop()

    def __enter__(self):
        pass

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self._session:
            self._session.stop()
