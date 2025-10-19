#!/usr/bin/env python3
import ipaddress
import pathlib
import socket

flag = pathlib.Path('/flag').read_bytes() 

so = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
so.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, True)
so.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, b'bare0')
so.bind((str(ipaddress.IPv4Address(b':3:3')), int.from_bytes(b':3')))

output = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
output.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, True)
output.bind(('0.0.0.0', int.from_bytes(b'^^')))

expected = b'please give me the flag :3' + b':3' * 101

while True:
    payload, client = so.recvfrom(4096)
    if payload == expected:
        output.sendto(flag, client)
