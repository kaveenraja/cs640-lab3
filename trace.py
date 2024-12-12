import argparse
import socket
import struct
import time


#Args

parser = argparse.ArgumentParser(prog='routetrace', description='forwarding trace in emulator network')

parser.add_argument('-a', '--rt_port')       # the port that the routetrace listens on
parser.add_argument('-b', '--s_host')        # 
parser.add_argument('-c', '--s_port')         # 
parser.add_argument('-d', '--d_host')        # 
parser.add_argument('-e', '--d_port')        # 
parser.add_argument('-f', '--debug')         # application will print info on 1, other nothing on 0

args = parser.parse_args()

socket_addr = (socket.gethostbyname(socket.gethostname()), int(args.rt_port))
source_addr = (args.s_host, int(args.s_port))
dest_addr   = (args.d_host, int(args.d_port))

debug = int(args.debug)


soc = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
soc.bind(socket_addr)

send_ttl = 0

while(1):
    newpacket = struct.pack("!cI4sH4sHII", 'T'.encode(), send_ttl, socket.inet_aton(socket_addr[0]), socket_addr[1], socket.inet_aton(dest_addr[0]), dest_addr[1], 0, 0)
    soc.sendto(newpacket, source_addr)

    if(debug):
        print("SENT: ", send_ttl, source_addr, dest_addr)
        
    incoming_packet, incoming_addr = soc.recvfrom(65565)
    packettype, ttl, sourceip, sourceport, destip, destport, sequence, length = struct.unpack("!cI4sH4sHII", incoming_packet[0:25])
    sourceip = socket.inet_ntoa(sourceip)
    destip = socket.inet_ntoa(destip)

    if(debug):
        print("RECV: ", ttl, sourceip, sourceport, destip, destport)


    print(sourceip, sourceport)

    if( (sourceip, sourceport) == dest_addr):
        exit(0)
    send_ttl += 1


