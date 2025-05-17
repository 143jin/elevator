FROM python:3.10

RUN pip install paho-mqtt

COPY elevator/mqtt_handler.py /mqtt_handler.py

CMD ["python", "/mqtt_handler.py"]
