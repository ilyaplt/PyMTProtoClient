import ctypes
import os
import auth_key
import client
import tl_types_all
import time
import domru_api
import re
import subprocess
import datetime
import logging

logging.basicConfig(filename='logs.txt', filemode='a+', format='%(levelname)s - %(asctime)s - %(message)s', level=logging.ERROR)
FFMPEG_EXECUTABLE_PATH = r'/usr/bin/ffmpeg'

def record_audio_from_stream(stream_link, duration, output_filename):
    # ffmpeg -i {} -t {} -vn -ab 320 -f mp3 {}.mp3
    result = subprocess.run([FFMPEG_EXECUTABLE_PATH, '-i', stream_link, '-t', duration, '-vn',
                             '-ab', '320', '-f', 'mp3', output_filename], capture_output=True)
    if result.returncode == 0:
        return True
    return False

# API_ID & API_HASH можно взять на my.telegram.org
API_ID = 0
API_HASH = ''
TELEGRAM_BOT_TOKEN = ''
PROFILE_ID = 1 # ID Telegram аккаунта с которого будете писать боту
logging.error('bot has been ran!')
while True:
    try:
        client = client.Client(api_id=API_ID, api_hash=API_HASH)
        client.auth_as_bot(TELEGRAM_BOT_TOKEN, API_ID, API_HASH)
        client.get_new_update_state_in_new_session(True)
        client.set_updates_state()
        intercom_control = domru_api.DomRU()
        while True:
            try:
                updates = client.get_incoming_updates(True)
                if isinstance(updates, list):
                    for k in updates:
                        update = k[0]
                        if isinstance(update, tl_types_all.message):
                            if k[1].id == PROFILE_ID:
                                if update.message == b'/start':
                                    client.send_message(k[1].id, k[1].access_hash, 'Выберите действие', keyboard_buttons=[['Открыть дверь'], ['Сделать снимок'], ['Записать звук'], ['Получить ссылку на видеотрансляцию']])
                                elif update.message.decode() == 'Открыть дверь':
                                    if intercom_control.open_door():
                                        client.send_message(k[1].id, k[1].access_hash, 'Дверь была успешно открыта!')
                                    else:
                                        client.send_message(k[1].id, k[1].access_hash, 'Ошибка при взаимодействии с сервером провайдера!')
                                elif update.message.decode() == 'Сделать снимок':
                                    snapshot_filename = 'snapshots/{}.jpg'.format(int.from_bytes(os.urandom(4), byteorder='little'))
                                    try:
                                        if not intercom_control.take_snapshot(snapshot_filename):
                                            raise RuntimeError()
                                        file_input = client.upload_small_file(snapshot_filename, snapshot_filename)
                                        input_photo = client.get_uploaded_photo_from_file_input(file_input)
                                        client.send_media(input_photo, k[1].id, k[1].access_hash)
                                    except Exception:
                                        client.send_message(k[1].id, k[1].access_hash, 'Ошибка при взаимодействии с сервером провайдера!')
                                    finally:
                                        try:
                                            os.remove(snapshot_filename)
                                        except Exception:
                                            pass
                                elif update.message.decode() == 'Получить ссылку на видеотрансляцию':
                                    stream_link = intercom_control.get_video_stream_link()
                                    if not stream_link:
                                        client.send_message(k[1].id, k[1].access_hash, 'Ошибка при взаимодействии с сервером провайдера!')
                                    else:
                                        client.send_message(k[1].id, k[1].access_hash, stream_link)
                                elif update.message.decode() == 'Записать звук':
                                    reply_markup = []
                                    buttons = []
                                    for i in range(56):
                                        if i % 5 == 0 and i > 0:
                                            reply_markup.append(buttons[:])
                                            buttons.clear()
                                        buttons.append({'text': str(i+5), 'data': 'record_sound_{}'.format(i+5)})
                                    client.send_message(k[1].id, k[1].access_hash, 'Выберите продолжительность аудиозаписи в секундах:', inline_buttons=reply_markup)
                        elif isinstance(update, tl_types_all.updateBotCallbackQuery):
                            if k[1].id == 1653084190:
                                data = k[0].data
                                if data:
                                    data = data.decode()
                                    if re.search(r'record_sound_([\d]+)', data):
                                        match = re.search(r'record_sound_([\d]+)', data)
                                        sound_duration = match.group(1)
                                        stream_link = intercom_control.get_video_stream_link()
                                        if stream_link:
                                            client.edit_message(k[0].msg_id, k[1].id, k[1].access_hash, 'Началась запись звука...'.format(sound_duration))
                                            file_name = '{}.mp3'.format(int.from_bytes(os.urandom(4), byteorder='little'))
                                            now_datetime = datetime.datetime.now()
                                            result = record_audio_from_stream(stream_link, sound_duration, file_name)
                                            if result:
                                                try:
                                                    client.set_typing(k[1].id, k[1].access_hash, tl_types_all.sendMessageUploadAudioAction(progress=1))
                                                    uploaded_file = client.upload_small_file(file_name, file_name)
                                                    input_audio_file = client.get_uploaded_audio_from_file_input(uploaded_file, int(sound_duration), True)
                                                    client.send_media(input_audio_file, k[1].id, k[1].access_hash, message=now_datetime.strftime('%d.%m.%Y %H:%M'))
                                                except Exception:
                                                    pass
                                                finally:
                                                    os.remove(file_name)
                                            else:
                                                client.send_message(k[1].id, k[1].access_hash, 'Ошибка при взаимодействии с сервером провайдера!')
                                        else:
                                            client.edit_message(k[0].msg_id, k[1].id, k[1].access_hash, 'Ошибка при взаимодействии с сервером провайдера!')
            except Exception as e:
                pass
    except:
        pass
        time.sleep(1)
