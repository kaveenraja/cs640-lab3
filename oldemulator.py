import argparse
import socket
import queue
import random
import struct

import time
from datetime import datetime

#Args
parser = argparse.ArgumentParser(prog='sender',description='sets up a file packet sender on specified port')

parser.add_argument('-p', '--port')         #port of emulator
parser.add_argument('-q', '--queue_size')   #size of queue
parser.add_argument('-f', '--filename')     #filename of forwarding table
parser.add_argument('-l', '--log')          #name of log file
args = parser.parse_args()

soc = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
soc.bind((socket.gethostbyname(socket.gethostname()), int(args.port)))

table = []
file = open(args.filename, "r")

for line in file:
    entry = line.strip().split(" ")
    if entry[0] == socket.gethostname() and entry[1] == args.port:
        table.append(entry)


def getmilli():
    return round(time.time() * 1000)

def log(cause, packet):
    outer_header = struct.unpack("!B4sH4sHI", packet[0:17])
    inner_header = struct.unpack("!cII", packet[17:26])


    srcport = str(outer_header[2])
    destport = str(outer_header[4])
    priority = str(outer_header[0])
    payload = str(outer_header[5])



    f = open(args.log, "a+")
    string =  "Cause:      " + cause + "\n" + "Source:     " + socket.gethostbyaddr(socket.inet_ntoa(outer_header[1]))[0].removesuffix(".cs.wisc.edu") + ":" + srcport + "\n" + "Dest:       " + socket.gethostbyaddr(socket.inet_ntoa(outer_header[3]))[0].removesuffix(".cs.wisc.edu") + ":" + destport + "\n" + "PckType:    " + inner_header[0].decode() + "\n" + "Time:       " + datetime.now().isoformat(sep=" ", timespec="milliseconds") + "\n" +"Priority:   " + priority + "\n" +"Payload:    " + payload + "\n\n"
    f.write(string)
    f.close()


cur_packet = -1

hig_q = queue.Queue(maxsize=int(args.queue_size))
med_q = queue.Queue(maxsize=int(args.queue_size))
low_q = queue.Queue(maxsize=int(args.queue_size))

# Main loop
while 1:
    incoming_packet = 0
    try:
        soc.setblocking(False)
        incoming_packet, incoming_addr = soc.recvfrom(65565)
    except:
        #Do nothing
        print(end="")
    else:
        error = 1
        incoming_header = struct.unpack("!B4sH4sHI", incoming_packet[0:17])
        for entry in table:

               if entry[2] == socket.gethostbyaddr(socket.inet_ntoa(incoming_header[3]))[0].removesuffix(".cs.wisc.edu") and int(entry[3]) == int(incoming_header[4]):
                if int(incoming_header[0] == 1):
                    if hig_q.full():
                        log("Priority queue 1 was full", incoming_packet)
                    else: 
                        #Packet, next hop ip, next hop port, send at
                        hig_q.put((incoming_packet, entry[4], entry[5], entry[6], 0, entry[7]), block=False)
                    error = 0
                    break

                elif int(incoming_header[0] == 2):
                    if med_q.full():
                        log("Priority queue 2 was full", incoming_packet)
                    else:
                        med_q.put((incoming_packet, entry[4], entry[5], entry[6], 0, entry[7]), block=False)
                    error = 0
                    break

                else:
                    if low_q.full():
                        log("Priority queue 3 was full", incoming_packet)
                    else: 
                        low_q.put((incoming_packet, entry[4], entry[5], entry[6], 0, entry[7]), block=False)
                    error = 0
                    break
                    
        if error:
            log("No forwarding entry found", incoming_packet)

    finally:
        if cur_packet != -1:
            #Check currently delayed packet and send
            if int(cur_packet[4]) < getmilli():

                inner_header = struct.unpack("!cII", cur_packet[0][17:26])
                if inner_header[0].decode() != "E" and inner_header[0].decode() != "R":
                    r = random.randint(0, 100)
                    if 0 < r < int(cur_packet[5]):
                        log("Loss event occurred", cur_packet[0])
                        cur_packet = -1
                        continue;
                soc.sendto(cur_packet[0], (socket.gethostbyname(cur_packet[1]), int(cur_packet[2])))
                cur_packet = -1

        else:
            # Queue next packet to delay
            if hig_q.empty() != True:
                cur_packet = hig_q.get(block=False)
                cur_packet = (cur_packet[0], cur_packet[1], cur_packet[2], cur_packet[3], getmilli() + int(cur_packet[3]), cur_packet[5])
            elif med_q.empty() != True:
                cur_packet=med_q.get(block=False)
                cur_packet = (cur_packet[0], cur_packet[1], cur_packet[2], cur_packet[3], getmilli() + int(cur_packet[3]), cur_packet[5])
            elif low_q.empty() != True:
                cur_packet=low_q.get(block=False)
                cur_packet = (cur_packet[0], cur_packet[1], cur_packet[2], cur_packet[3], getmilli() + int(cur_packet[3]), cur_packet[5])

        
        

