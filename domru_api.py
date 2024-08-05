import requests
import logging

class DomRU:
    HEADERS = {
        'User-Agent': 'samsung SMG973N | Android 7.1.2 | erthGms | 6.5.0 (6050005) | | 8 | 2659bc8a-09c2-4f1b-96b5-883651f3758c',
        'Content-Type': 'application/json',
        'Authorization': 'Bearer uv9u5fnu8zt7hnm6ce0tzuy2up7a3u',
        'Accept-Encoding': 'gzip',
        'Operator': '8'
    }
    API_URL = 'https://myhome.novotelecom.ru/rest/v1/'
    PLACE_ID = 1153660
    DEVICE_ID = 25752
    CAMERA_ID = 38447595

    def get_cameras(self):
        return requests.get(self.API_URL + 'forpost/cameras', headers=self.HEADERS).json()['data']

    def open_door(self):
        payload = '{\n"name": "accessControlOpen"\n}'
        response = requests.post('https://myhome.novotelecom.ru/rest/v1/places/{}/accesscontrols/{}/actions'.format(self.PLACE_ID, self.DEVICE_ID), headers=self.HEADERS, data=payload)
        try:
            if response.json()['data']['status'] == True:
                return True
            logging.error('failed to open door: ' + response.text)
            return False
        except Exception:
            logging.error('failed to open door: ' + response.text)
            return False

    def take_snapshot(self, jpeg_filename, width=1920, height=1080):
        try:
            with open(jpeg_filename, 'wb') as f:
                response = requests.get('https://myhome.novotelecom.ru/rest/v1/places/{}/accesscontrols/{}/snapshots'.format(self.PLACE_ID, self.DEVICE_ID), {
                    'width': width,
                    'height': height
                }, headers=self.HEADERS)
                if len(response.content) < 500:
                    logging.error('failed to take snapshot: ' + response.text)
                    return False
                f.write(response.content)
                return True
        except Exception:
            return False

    def get_video_stream_link(self):
        response = requests.get('https://myhome.novotelecom.ru/rest/v1/forpost/cameras/{}/video'.format(self.CAMERA_ID), headers=self.HEADERS)
        try:
            return response.json()['data']['URL']
        except Exception:
            logging.error('failed to take video stream link: ' + response.text)
            pass
