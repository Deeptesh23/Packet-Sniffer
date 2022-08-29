#Packet Sniffer Project

import struct
import socket
import textwrap

TAB_1 = '\t -'
TAB_2 = '\t \t -'
TAB_3 = '\t \t \t -'
TAB_4 = '\t \t \t \t -'

DATA_TAB_1 = '\t '
DATA_TAB_2 = '\t \t '
DATA_TAB_3 = '\t \t \t '
DATA_TAB_4 = '\t \t \t \t '




# 3. Date recieving
def main():
    connection=socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    
    while True:
        raw_data, add=connection.recvfrom(65536)
        dest_mac, src_mac, eth_proto, data=ethernet_frame(raw_data)
        print('\nEthernet Frame: ')
        print(TAB_1 + 'Destination: {}, Source: {}, Protocol: {}'.format(dest_mac, src_mac, eth_proto))
        
        # 8 IPV4
        if eth_proto == 8:
            (version, header_length, ttl, proto, src, target, data) = ipv4_packet(data)
            print(TAB_1 + 'IPV4 Packets: ')
            print(TAB_2 + 'Version: {}, Header Lenght: {}, TTL: {}'.format(version, header_length, ttl))
            print(TAB_2 + 'Protocol: {}, Source: {}, Target: {}'.format(proto, src, target))
            
            # ICMP
            if proto == 1:
                icmp_type, code, checksum, data = icmp_packet(data)
                print(TAB_1 + 'ICMP PACKET: ' )
                print(TAB_2 + 'Type: {}, Code: {}, Chechsum: {}'.format(icmp_type, code, checksum))
                print(TAB_2 + 'Data:')
                print(format_multi_lines(DATA_TAB_3, data))
            
            # TCP
            elif proto == 6:
                src_port, dest_port, sequence, acknowledgment, flag_urg, flag_ack, flag_rst, flag_psh, flag_syn, flag_fin, data = tcp_segment(data)
                print(TAB_1 + 'TCP Segment: ')
                print(TAB_2 + 'Source: {}, Destination: {}'.format(src_port, dest_port))
                print(TAB_2 + 'Sequence: {}, Acknowledgement: {}'.format(sequence, acknowledgment))
                print(TAB_2 + 'Flags:')
                print(TAB_3 + 'URG: {}, ACK: {}, RST: {}, PSH: {}, SYN: {}, FIN: {}'.format(flag_urg, flag_ack, flag_rst, flag_psh, flag_syn, flag_fin))
                print(TAB_2 + 'Data:')
                print(format_multi_lines(DATA_TAB_3, data))
            
            # UDP
            elif proto == 17:
                src_port, dest_port, size, data = udp_segment(data)
                print(TAB_1 + 'UDP Segment:')
                print(TAB_2 + 'Source: {}, Destination: {}, Size: {}'.format(src_port, dest_port, size))
        
            # Other
        else:
            print(TAB_1 + 'Data:')
            print(format_multi_lines(DATA_TAB_3, data))
                
            
        


# 1. Unpacking of ethernet Frames
def ethernet_frame(data):
    dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', data[:14])
    return get_mac_addr(dest_mac), get_mac_addr(src_mac), socket.htons(proto), data[14:]


# 2. IP address Fromatting (AA:BB:CC:DD:EE:FF)
def get_mac_addr(bytes_addr):
    bytes_str=map('{:02x}'.format, bytes_addr)
    return':'.join(bytes_str).upper() 


# 3. Unpacking of IPv4 data packets
def ipv4_packet(data):
	version_header_length=data[0]
	version=version_header_length >> 4
	header_length=(version_header_length & 15) * 4
	ttl, proto, src, target=struct.unpack('! 8x B B 2x 4s 4s', data[:20])
	return version, header_length, ttl, proto, ipv4(target), ipv4(src), data[header_length:]

# 4. Return formatting of ipv4 eg:127.0.0.1
def ipv4(addr):
    return '.'.join(map(str,addr))
    
# 5. Unapacking of ICMP packets:
def icmp_packet(data):
    icmp_type, code, checksum=struct.unpack('! B B H', data[4:])
    return icmp_type, code, checksum, data[:4]

# 6. Unpacking of TCP segment:
def  tcp_segment(data):
    (src_port, dest_port, sequence, acknowledgment, offset_reverse_flag)=struct.unpack('! H H L L H', data[:14])
    offset = (offset_reverse_flag >> 12) * 4
    flag_urg = (offset_reverse_flag & 32) >> 5
    flag_ack = (offset_reverse_flag & 16) >> 4
    flag_rst = (offset_reverse_flag & 8) >> 3
    flag_psh = (offset_reverse_flag & 4) >> 2
    flag_syn = (offset_reverse_flag & 2) >> 1
    flag_fin = offset_reverse_flag & 1
    return src_port, dest_port, sequence, acknowledgment, flag_urg, flag_ack, flag_rst, flag_psh, flag_syn, flag_fin, data[offset:]

# 7. Unpacking of UDP segment:
def udp_segment(data):
    src_port, dest_port, size = struct.unpack('! H H 2x H', data[:8])
    return src_port, dest_port, size, data[8:]

# 8. Data FOrmatting of multiple data lines:
def format_multi_lines(prefix, string, size=80):
    size -=len(prefix)
    if isinstance(string, bytes):
        string=''.join(r'\x{:02x}'.format(byte) for byte in string)
        if size % 2:
            size -=1
    return '\n'.join([prefix + line for line in textwrap.wrap(string, size)])
    
    
main()

