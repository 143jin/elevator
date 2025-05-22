import os
import logging
import configparser
import paho.mqtt.client as mqtt
import re
from functools import reduce
from collections import defaultdict
from json import dumps as json_dumps

# 1. 로깅 시스템 도입
logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s][%(levelname)s] %(message)s'
)

# 2. 설정 파일 관리
CONFIG_PATH = 'config.ini'
config = configparser.ConfigParser()
if not config.read(CONFIG_PATH):
    raise RuntimeError(f"설정 파일 {CONFIG_PATH} 를 찾을 수 없습니다.")

MQTT_SERVER = config['MQTT']['SERVER']
MQTT_PORT = int(config['MQTT'].get('PORT', 1883))
MQTT_USERNAME = config['MQTT']['USERNAME']
MQTT_PASSWORD = config['MQTT']['PASSWORD']

ROOT_TOPIC_NAME = config['GENERAL'].get('ROOT_TOPIC_NAME', 'rs485_2mqtt')
HOMEASSISTANT_ROOT_TOPIC_NAME = config['GENERAL'].get('HOMEASSISTANT_ROOT_TOPIC_NAME', 'homeassistant')

# 5. 매직넘버/상수화
ELEVATOR_ID         = '33'
ELEVATOR_SUBID      = '01'
ELEVATOR_CLASS      = 'climate'
ELEVATOR_DEVICE_NAME= '엘리베이터'
FLOOR_MESSAGE_FLAG  = '44'
ELEVATOR_CALL_PACKET_HEX = "f7 33 01 81 03 00 24 00 63 36"  # 실제 장비 요구사항에 맞게 조정

class Device:
    def __init__(self, device_name, device_id, device_subid, device_class, optional_info):
        self.device_name = device_name
        self.device_id = device_id
        self.device_subid = device_subid
        self.device_unique_id = f'rs485_{self.device_id}_{self.device_subid}'
        self.device_class = device_class
        self.optional_info = optional_info
        self._status_messages_map = defaultdict(list)

    def register_status(self, message_flag, attr_name, regex, topic_class, process_func=lambda v: v):
        self._status_messages_map[message_flag].append({
            'regex': regex,
            'process_func': process_func,
            'attr_name': attr_name,
            'topic_class': topic_class
        })

    def parse_payload(self, payload_dict):
        result = {}
        for status in self._status_messages_map.get(payload_dict['message_flag'], []):
            match = re.match(status['regex'], payload_dict['data'])
            if match:
                try:
                    result_value = status['process_func'](match[1])
                    topic = '/'.join([ROOT_TOPIC_NAME, self.device_class, self.device_name, status['attr_name']])
                    result[topic] = result_value
                except Exception as e:
                    logging.error(f"Payload parsing error {payload_dict} - {e}")
        return result

    def get_status_attr_list(self):
        return list(set(
            [status['attr_name'] for status_list in self._status_messages_map.values() for status in status_list]
        ))

    def get_mqtt_discovery_payload(self):
        result = {
            '~': '/'.join([ROOT_TOPIC_NAME, self.device_class, self.device_name]),
            'name': self.device_name,
            'uniq_id': self.device_unique_id,
        }
        result.update(self.optional_info)
        for status_list in self._status_messages_map.values():
            for status in status_list:
                result[status['topic_class']] = '/'.join(['~', status['attr_name']])
        result['device'] = {
            'identifiers': self.device_unique_id,
            'name': self.device_name
        }
        return json_dumps(result, ensure_ascii=False)

class Wallpad:
    def __init__(self):
        self._device_list = []  # 3. 인스턴스 변수로 변경
        self.mqtt_client = mqtt.Client()
        self.mqtt_client.on_message = self.on_raw_message
        self.mqtt_client.on_disconnect = self.on_disconnect
        self.mqtt_client.username_pw_set(username=MQTT_USERNAME, password=MQTT_PASSWORD)
        self._connect_mqtt()

    def _connect_mqtt(self):
        while True:
            try:
                self.mqtt_client.connect(MQTT_SERVER, MQTT_PORT)
                logging.info("MQTT 연결 성공")
                break
            except Exception as e:
                logging.error(f"MQTT 연결 실패: {e}, 5초 후 재시도")
                import time; time.sleep(5)

    def listen(self):
        self.register_mqtt_discovery()
        topics = [(ROOT_TOPIC_NAME + '/dev/raw', 2)] + [(t, 2) for t in self.get_topic_list_to_listen()]
        self.mqtt_client.subscribe(topics)
        self.mqtt_client.loop_start()
        while True:
            import time; time.sleep(1)

    def register_mqtt_discovery(self):
        for device in self._device_list:
            topic = '/'.join([
                HOMEASSISTANT_ROOT_TOPIC_NAME,
                device.device_class,
                device.device_unique_id,
                'config'
            ])
            payload = device.get_mqtt_discovery_payload()
            self.mqtt_client.publish(topic, payload, qos=2, retain=True)
            logging.info(f"Discovery 등록: {topic}")

    def add_device(self, device_name, device_id, device_subid, device_class, optional_info):
        device = Device(device_name, device_id, device_subid, device_class, optional_info)
        self._device_list.append(device)
        return device

    def get_device(self, device_id, device_subid):
        for device in self._device_list:
            if device.device_id == device_id and device.device_subid == device_subid:
                return device
        raise ValueError(f"Device not found: {device_id}/{device_subid}")

    def get_topic_list_to_listen(self):
        return [
            '/'.join([ROOT_TOPIC_NAME, device.device_class, device.device_name, attr_name, 'set'])
            for device in self._device_list for attr_name in device.get_status_attr_list()
        ]

    def on_raw_message(self, client, userdata, msg):
        try:
            if msg.topic == ROOT_TOPIC_NAME + '/dev/raw':
                for payload_raw_bytes in msg.payload.split(b'\xf7')[1:]:
                    payload_hexstring = 'f7' + payload_raw_bytes.hex()
                    try:
                        payload_dict = self._parse_hex_payload(payload_hexstring)
                        if not payload_dict: continue
                        device = self.get_device(payload_dict['device_id'], payload_dict['device_subid'])
                        for topic, value in device.parse_payload(payload_dict).items():
                            logging.info(f"층수(온도) publish: {topic}={value}")
                            client.publish(topic, value, qos=1, retain=False)
                    except (ValueError, IndexError, AttributeError) as e:
                        logging.error(f"패킷 파싱 실패: {payload_hexstring} / {e}")
            else:
                topic_split = msg.topic.split('/')
                if len(topic_split) > 4 and topic_split[2] == ELEVATOR_DEVICE_NAME and topic_split[3] == 'power':
                    if msg.payload.decode() == 'heat':
                        logging.info("엘리베이터 호출 패킷 전송")
                        client.publish(ROOT_TOPIC_NAME + '/dev/command',
                                       bytes.fromhex(ELEVATOR_CALL_PACKET_HEX.replace(" ", "")),
                                       qos=2, retain=False)
        except Exception as e:
            logging.error(f"on_raw_message 예외: {e}")

    def _parse_hex_payload(self, payload_hexstring):
        """
        f7 <dev_id 2> <subid 2> <flag 2> <?? 2> <data ...>
        """
        m = re.match(
            r'f7(?P<device_id>[0-9a-f]{2})(?P<device_subid>[0-9a-f]{2})(?P<message_flag>[0-9a-f]{2})(?:[0-9a-f]{2})(?P<data>[0-9a-f]*)',
            payload_hexstring)
        if m:
            return m.groupdict()
        return None

    def on_disconnect(self, client, userdata, rc):
        logging.warning(f"MQTT 연결 끊어짐(rc={rc}), 재연결 시도")
        self._connect_mqtt()

# ---- 장치 선언, 등록 ----

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
    device_name=ELEVATOR_DEVICE_NAME,
    device_id=ELEVATOR_ID,
    device_subid=ELEVATOR_SUBID,
    device_class=ELEVATOR_CLASS,
    optional_info=optional_info
)

def floor_hex_to_int(v):
    v = v.lower()
    if v.startswith('f'):
        return -int(v[1:], 16)
    return int(v, 16)

# 층수 패킷(44)에서 01 XX 추출 → 현재온도에 publish
엘리베이터.register_status(
    message_flag=FLOOR_MESSAGE_FLAG,
    attr_name='currenttemp',
    topic_class='current_temperature_topic',
    regex=r'01([0-9a-fA-F]{2})',
    process_func=floor_hex_to_int
)

wallpad.listen()
