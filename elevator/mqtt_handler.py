import paho.mqtt.client as mqtt
MQTT_USERNAME = 'eunj'
MQTT_PASSWORD = '!Teatime6699'
MQTT_BROKER = "192.168.200.68"
RAW_TOPIC = "rs485_2mqtt/dev/raw"
SWITCH_TOPIC = "homeassistant/switch/rs485_switch/set"
SENSOR_TOPIC = "homeassistant/sensor/floor"

ON_PACKET = bytes.fromhex("F7330181030024006336")
OFF_PACKET = "f7330157009214"  # 도착 패킷 (문자열 형태로 비교)

client = mqtt.Client(protocol=mqtt.MQTTv311)  # 명시적으로 프로토콜 버전 지정

def parse_floor(packet):
    """ RS485 패킷에서 층수 추출 (16진수 그대로 표시) """
    hex_data = packet.hex()
    if hex_data.startswith("f7330144"):
        floor_hex = hex_data[8:10]  # 44 01 다음 숫자 (층수)
        return floor_hex  # 변환 없이 16진수 그대로 반환
    return None

def on_message(client, userdata, msg):
    """ 수신된 패킷 처리 """
    received_hex = msg.payload.hex()
    print(f"Received Data: {received_hex}")

    # 층수 추출 및 MQTT 센서 업데이트
    floor_hex = parse_floor(msg.payload)
    if floor_hex is not None:
        print(f"현재 층: {floor_hex}")
        client.publish(SENSOR_TOPIC, floor_hex)  # 16진수 그대로 MQTT 센서에 게시

    # 도착 패킷 수신 시 스위치 OFF
    if received_hex == OFF_PACKET:
        print("도착 패킷 수신! 스위치 OFF")
        client.publish(SWITCH_TOPIC, "off")

def send_packet():
    """ 스위치를 ON할 때 패킷 송신 """
    client.publish(RAW_TOPIC, ON_PACKET)
    print("Packet sent:", ON_PACKET.hex())

# MQTT 브로커 연결 및 초기 설정
client.on_message = on_message
client.connect(MQTT_BROKER, 1883, 60)
client.subscribe(RAW_TOPIC)

# 스위치 ON 패킷 전송
send_packet()

# MQTT 메시지 수신 시작
client.loop_forever()
