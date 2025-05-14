import paho.mqtt.client as mqtt

MQTT_BROKER = "192.168.200.68"
COMMAND_TOPIC = "rs485_2mqtt/dev/command"
RAW_TOPIC = "rs485_2mqtt/dev/raw"

client = mqtt.Client()

def on_message(client, userdata, msg):
    print(f"Received Data: {msg.payload.hex()}")
    # 원하는 값 추출 후 센서 업데이트 로직 추가

client.on_message = on_message
client.connect(MQTT_BROKER, 1883, 60)
client.subscribe(RAW_TOPIC)
client.loop_forever()
