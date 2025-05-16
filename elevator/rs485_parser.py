def parse_rs485_packet(packet):
    hex_data = packet.hex()
    extracted_value = hex_data[4:6]  # 특정 값 추출 예제
    return extracted_value
