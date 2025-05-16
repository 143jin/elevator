FROM python:3.10

RUN pip install paho-mqtt

COPY run.sh /run.sh
COPY elevator/mqtt_handler.py /mqtt_handler.py

CMD ["sh", "/run.sh"]
