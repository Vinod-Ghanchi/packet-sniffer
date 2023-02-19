#! /usr/local/bin/python3.5

import socket
import struct
import textwrap
import binascii
import struct
import sys

TAB_1 = '\t - '
TAB_2 = '\t\t - '
TAB_3 = '\t\t\t - '
TAB_4 = '\t\t\t\t - '

DATA_TAB_1 = '\t   '
DATA_TAB_2 = '\t\t   '
DATA_TAB_3 = '\t\t\t   '
DATA_TAB_4 = '\t\t\t\t   '

def main():
    conn = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

    filters = (["ICMP", 1, "ICMPv6"],["UDP", 17, "UDP"], ["TCP", 6, "TCP"])
    filter = []

    if len(sys.argv) == 2:
        print("This is the filter: ", sys.argv[1])
        for f in filters:
            if sys .argv[1] == f[0]:
                filter = f



    while True:
        raw_data, addr = conn.recvfrom(65536)
        dest_mac, src_mac, eth_proto, data = ethernet_frame(raw_data)

        if eth_proto == 'IPV6':
            newPacket, nextProto = ipv6Header(data, filter)
            printPacketsV6(filter, nextProto, newPacket)

        elif eth_proto == 'IPV4':
            printPacketsV4(filter, data, raw_data)



def printPacketsV4(filter, data, raw_data):
    (version, header_length, ttl, proto, src, target, data) = ipv4_Packet(data)

    # ICMP
    if proto == 1 and (len(filter) == 0 or filter[1] == 1):
        icmp_type, code, checksum, data = icmp_packet(data)
        print ("*******************ICMP***********************")
        print ("\tICMP type: %s" % (icmp_type))
        print ("\tICMP code: %s" % (code))
        print ("\tICMP checksum: %s" % (checksum))

    # TCP
    elif proto == 6 and (len(filter) == 0 or filter[1] == 6):
        print("*******************TCPv4***********************")
        print('Version: {}\nHeader Length: {}\nTTL: {}'.format(version, header_length, ttl))
        print('protocol: {}\nSource: {}\nTarget: {}'.format(proto, src, target))
        src_port, dest_port, sequence, acknowledgment, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin = struct.unpack(
            '! H H L L H H H H H H', raw_data[:24])
        print('*****TCP Segment*****')
        print('Source Port: {}\nDestination Port: {}'.format(src_port, dest_port))
        print('Sequence: {}\nAcknowledgment: {}'.format(sequence, acknowledgment))
        print('*****Flags*****')
        print('URG: {}\nACK: {}\nPSH: {}'.format(flag_urg, flag_ack, flag_psh))
        print('RST: {}\nSYN: {}\nFIN:{}'.format(flag_rst, flag_syn, flag_fin))

        if len(data) > 0:
            # HTTP
            if src_port == 80 or dest_port == 80:
                print('*****HTTP Data*****')
                try:
                    http = HTTP(data)
                    http_info = str(http.data).split('\n')
                    for line in http_info:
                        print(str(line))
                except:
                    print(format_output_line("",data))
            else:
                print('*****TCP Data*****')
                print(format_output_line("",data))
    # UDP
    elif proto == 17 and (len(filter) == 0 or filter[1] == 17):
        print("*******************UDPv4***********************")
        print('Version: {}\nHeader Length: {}\nTTL: {}'.format(version, header_length, ttl))
        print('protocol: {}\nSource: {}\nTarget: {}'.format(proto, src, target))
        src_port, dest_port, length, data = udp_seg(data)
        print('*****UDP Segment*****')
        print('Source Port: {}\nDestination Port: {}\nLength: {}'.format(src_port, dest_port, length))

def printPacketsV6(filter, nextProto, newPacket):
    remainingPacket = ""

    if (nextProto == 'ICMPv6' and (len(filter) == 0 or filter[2] == "ICMPv6")):
        remainingPacket = icmpv6Header(newPacket)
    elif (nextProto == 'TCP' and (len(filter) == 0 or filter[2] == "TCP")):
        remainingPacket = tcpHeader(newPacket)
    elif (nextProto == 'UDP' and (len(filter) == 0 or filter[2] == "UDP")):
        remainingPacket = udpHeader(newPacket)

    return remainingPacket


def tcpHeader(newPacket):
    # 2 unsigned short,2unsigned Int,4 unsigned short. 2byt+2byt+4byt+4byt+2byt+2byt+2byt+2byt==20byts
    packet = struct.unpack("!2H2I4H", newPacket[0:20])
    srcPort = packet[0]
    dstPort = packet[1]
    sqncNum = packet[2]
    acknNum = packet[3]
    dataOffset = packet[4] >> 12
    reserved = (packet[4] >> 6) & 0x003F
    tcpFlags = packet[4] & 0x003F 
    urgFlag = tcpFlags & 0x0020 
    ackFlag = tcpFlags & 0x0010 
    pushFlag = tcpFlags & 0x0008  
    resetFlag = tcpFlags & 0x0004 
    synFlag = tcpFlags & 0x0002 
    finFlag = tcpFlags & 0x0001 
    window = packet[5]
    checkSum = packet[6]
    urgPntr = packet[7]

    print ("*******************TCP***********************")
    print ("\tSource Port: "+str(srcPort) )
    print ("\tDestination Port: "+str(dstPort) )
    print ("\tSequence Number: "+str(sqncNum) )
    print ("\tAck. Number: "+str(acknNum) )
    print ("\tData Offset: "+str(dataOffset) )
    print ("\tReserved: "+str(reserved) )
    print ("\tTCP Flags: "+str(tcpFlags) )

    if(urgFlag == 32):
        print ("\tUrgent Flag: Set")
    if(ackFlag == 16):
        print ("\tAck Flag: Set")
    if(pushFlag == 8):
        print ("\tPush Flag: Set")
    if(resetFlag == 4):
        print ("\tReset Flag: Set")
    if(synFlag == 2):
        print ("\tSyn Flag: Set")
    if(finFlag == True):
        print ("\tFin Flag: Set")

    print ("\tWindow: "+str(window))
    print ("\tChecksum: "+str(checkSum))
    print ("\tUrgent Pointer: "+str(urgPntr))
    print (" ")

    packet = packet[20:]
    return packet


def udpHeader(newPacket):
    packet = struct.unpack("!4H", newPacket[0:8])
    srcPort = packet[0]
    dstPort = packet[1]
    lenght = packet[2]
    checkSum = packet[3]

    print ("*******************UDP***********************")
    print ("\tSource Port: "+str(srcPort))
    print ("\tDestination Port: "+str(dstPort))
    print ("\tLenght: "+str(lenght))
    print ("\tChecksum: "+str(checkSum))
    print (" ")

    packet = packet[8:]
    return packet


def icmpv6Header(data):
    ipv6_icmp_type, ipv6_icmp_code, ipv6_icmp_chekcsum = struct.unpack(
        ">BBH", data[:4])

    print ("*******************ICMPv6***********************")
    print ("\tICMPv6 type: %s" % (ipv6_icmp_type))
    print ("\tICMPv6 code: %s" % (ipv6_icmp_code))
    print ("\tICMPv6 checksum: %s" % (ipv6_icmp_chekcsum))

    data = data[4:]
    return data