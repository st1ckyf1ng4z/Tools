#!/usr/bin/env python3

from ctypes import *
import struct
import socket
import sys
import os

# host to listen on
host = sys.argv[1]

# our ip header
class IP(Structure):
    _fields_ = [
        ('ihl', c_ubyte, 4),
        ('version', c_ubyte, 4),
        ('tos', c_ubyte),
        ('len', c_ushort),
        ('id', c_ushort),
        ('offset', c_ushort),
        ('ttl', c_ubyte),
        ('protocol_num', c_ubyte),
        ('sum', c_ushort),
        ('src', c_uint32),
        ('dst', c_uint32)
    ]

    def __new__(self, socket_buffer=None):
        return self.from_buffer_copy(socket_buffer)

    def __init__(self, socket_buffer=None):
        # map protocol constants to their names
        self.protocol_map = {1:'ICMP', 6:'TCP', 17:'UDP'}

        # human readable format
        self.src_address = socket.inet_ntoa(struct.pack('<L', self.src))
        self.dst_address = socket.inet_ntoa(struct.pack('<L', self.dst))

        try:
            self.protocol = self.protocol_map[self.protocol_num]
        except:
            self.protocol = str(self.protocol_num)

class ICMP(Structure):
    _fields_ = [
    ('type', c_ubyte),
    ('code', c_ubyte),
    ('checksum', c_ushort),
    ('unused', c_ushort),
    ('next_hop_mtu', c_ushort)
    ]

    def __new__(self, socket_buffer):
        return self.from_buffer_copy(socket_buffer)
    
    def __init__(self, socket_buffer):
        pass

# create a raw socket and bind it to the interface
if os.name == 'nt':
    socket_proto = socket.IPPROTO_IP
else:
    socket_proto = socket.IPPROTO_ICMP

sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket_proto)
sniffer.bind((host, 0))

# we want the ip headers included in the capture
sniffer.getsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
# if we're using Windows, we need to send an IOCTL
# to set up promiscuous mode
if os.name == 'nt':
    sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

# processing packets
try:
    while True:
        # read in a packet
        raw_buffer = sniffer.recvfrom(65535)[0]
        # create an IP header from first 32/20 (depends on CPU arch) bytes of the buffer
        ip_header = IP(raw_buffer[0:20])
        # print out the protocol that was detected and the hosts
        print('[*] Protocol %s : %s -> %s' % (ip_header.protocol, ip_header.src_address, ip_header.dst_address))
        # for ICMP detailise
        #TODO: decoder for TCP and UDP packets
        if ip_header.protocol == 'ICMP':
            # calculate where our ICMP packet starts
            offset = ip_header.ihl * 4
            buf = raw_buffer[offset:offset + sizeof(ICMP)]
            # create our ICMP structure
            icmp_header = ICMP(buf)
            print('    ICMP -> Type: %d Code: %d' % (icmp_header.type, icmp_header.code))

# handle Ctrl-C
except KeyboardInterrupt:
    # if we're using Windows - need to turn off promiscuous mode
    if os.name == 'nt':
        sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)