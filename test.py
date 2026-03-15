import socket
import struct

CAMERA_IP = "192.168.0.133"
CAMERA_PORT = 32108
UID = "TBBT-108037-JRIJY"
PASSWORD = "888888"  # try also: 123456, blank, 888888

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.settimeout(3)

# PPPP "HELLO" / discovery punch packet (magic bytes)
hello = bytes([0xF1, 0xD0, 0x00, 0x00,  # magic header
               0x00, 0x00, 0x00, 0x00])  # payload length = 0

sock.sendto(hello, (CAMERA_IP, CAMERA_PORT))

try:
    data, addr = sock.recvfrom(1024)
    print(f"Response from {addr}: {data.hex()}")
except socket.timeout:
    print("No response")
