import paho.mqtt.client as mqtt
import re
from functools import reduce
from collections import defaultdict
from json import dumps as json_dumps

MQTT_USERNAME = 'eunj'
MQTT_PASSWORD = '!Teatime6699'
MQTT_SERVER = '192.168.200.68'
ROOT_TOPIC_NAME = 'rs485_2mqtt'
HOMEASSISTANT_ROOT_TOPIC_NAME = 'homeassistant'

class Device:
    def __init__(self, device_name, device_id, device_subid, device_class, optional_info):
        self.device_name = device_name
        self.device_id = device_id
        self.device_subid = device_subid
        self.device_unique_id = 'rs485_' + self.device_id + '_' + self.device_subid
        self.device_class = device_class
        self.optional_info = optional_info
        self.__status_messages_map = defaultdict(list)

    def register_status(self, message_flag, attr_name, regex, topic_class, process_func=lambda v: v):
        self.__status_messages_map[message_flag].append({
            'regex': regex,
            'process_func': process_func,
            'attr_name': attr_name,
            'topic_class': topic_class
        })

    def parse_payload(self, payload_dict):
        result = {}
        for status in self.__status_messages_map.get(payload_dict['message_flag'], []):
            topic = '/'.join([ROOT_TOPIC_NAME, self.device_class, self.device_name, status['attr_name']])
            match = re.match(status['regex'], payload_dict['data'])
            if match:
                result[topic] = status['process_func'](match[1])
        return result

    def get_status_attr_list(self):
        return list(set(
            [status['attr_name'] for status_list in self.__status_messages_map.values() for status in status_list]
        ))

    def get_mqtt_discovery_payload(self):
        result = {
            '~': '/'.join([ROOT_TOPIC_NAME, self.device_class, self.device_name]),
            'name': self.device_name,
            'uniq_id': self.device_unique_id,
        }
        result.update(self.optional_info)
        for status_list in self.__status_messages_map.values():
            for status in status_list:
                result[status['topic_class']] = '/'.join(['~', status['attr_name']])
        result['device'] = {
            'identifiers': self.device_unique_id,
            'name': self.device_name
        }
        return json_dumps(result, ensure_ascii=False)

class Wallpad:
    _device_list = []

    def __init__(self):
        self.mqtt_client = mqtt.Client()
        self.mqtt_client.on_message = self.on_raw_message
        self.mqtt_client.on_disconnect = self.on_disconnect
        self.mqtt_client.username_pw_set(username=MQTT_USERNAME, password=MQTT_PASSWORD)
        self.mqtt_client.connect(MQTT_SERVER, 1883)

    def listen(self):
        self.register_mqtt_discovery()
        self.mqtt_client.subscribe([(topic, 2) for topic in
                                   [ROOT_TOPIC_NAME + '/dev/raw'] + self.get_topic_list_to_listen()])
        self.mqtt_client.loop_forever()

    def register_mqtt_discovery(self):
        for device in self._device_list:
            topic = '/'.join(
                [HOMEASSISTANT_ROOT_TOPIC_NAME, device.device_class, device.device_unique_id, 'config'])
            payload = device.get_mqtt_discovery_payload()
            self.mqtt_client.publish(topic, payload, qos=2, retain=True)

    def add_device(self, device_name, device_id, device_subid, device_class, optional_info):
        device = Device(device_name, device_id, device_subid, device_class, optional_info)
        self._device_list.append(device)
        return device

    def get_device(self, device_id, device_subid):
        return [device for device in self._device_list if
                device.device_id == device_id and device.device_subid == device_subid][0]

    def get_topic_list_to_listen(self):
        return [
            '/'.join([ROOT_TOPIC_NAME, device.device_class, device.device_name, attr_name, 'set'])
            for device in self._device_list for attr_name in device.get_status_attr_list()
        ]

    @staticmethod
    def is_valid(payload_hexstring):
        payload_hexstring_array = [payload_hexstring[i:i + 2] for i in range(0, len(payload_hexstring), 2)]
        try:
            return int(payload_hexstring_array[4], 16) + 7 == len(payload_hexstring_array)
        except:
            return False

    def on_raw_message(self, client, userdata, msg):
        ELEVATOR_CALL_PACKET = bytes.fromhex("f7 33 01 81 03 00 24 00 63 36".replace(" ", ""))
        if msg.topic == ROOT_TOPIC_NAME + '/dev/raw':
            for payload_raw_bytes in msg.payload.split(b'\xf7')[1:]:
                payload_hexstring = 'f7' + payload_raw_bytes.hex()
                try:
                    if self.is_valid(payload_hexstring):
                        m = re.match(
                            r'f7(?P<device_id>[0-9a-f]{2})(?P<device_subid>[0-9a-f]{2})(?P<message_flag>[0-9a-f]{2})(?:[0-9a-f]{2})(?P<data>[0-9a-f]*)',
                            payload_hexstring
                        )
                        if m:
                            payload_dict = m.groupdict()
                            device = self.get_device(payload_dict['device_id'], payload_dict['device_subid'])
                            for topic, value in device.parse_payload(payload_dict).items():
                                client.publish(topic, value, qos=1, retain=False)
                except Exception:
                    continue
        else:
            topic_split = msg.topic.split('/')
            # climate/엘리베이터/power/set
            if len(topic_split) > 4 and topic_split[2] == '엘리베이터' and topic_split[3] == 'power':
                if msg.payload.decode() == 'heat':
                    client.publish(ROOT_TOPIC_NAME + '/dev/command', ELEVATOR_CALL_PACKET, qos=2, retain=False)

    def on_disconnect(self, client, userdata, rc):
        raise ConnectionError

# ---- 아래는 기기 등록 ----

wallpad = Wallpad()

optional_info = {
    'modes': ['off', 'heat'],
    'temp_step': 1,
    'precision': 1,
    'min_temp': -2,
    'max_temp': 28,
    'send_if_off': 'false'
}
엘리베이터 = wallpad.add_device(
    device_name='엘리베이터',
    device_id='33',
    device_subid='01',
    device_class='climate',
    optional_info=optional_info
)

def floor_hex_to_int(v):
    v = v.lower()
    if v.startswith('f'):
        return -int(v[1:], 16)
    else:
        return int(v, 16)

# 층수 패킷(44)에서 01 XX 추출 → 현재온도로 표시
엘리베이터.register_status(
    message_flag='44',
    attr_name='currenttemp',
    topic_class='current_temperature_topic',
    regex=r'01([0-9a-fA-F]{2})',
    process_func=floor_hex_to_int
)

wallpad.listen()
