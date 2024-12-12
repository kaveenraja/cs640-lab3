import argparse
import socket
import struct
import time

#Args

parser = argparse.ArgumentParser(prog='emulator', description='Symbolizes a node in a link state routing system')

parser.add_argument('-p', '--port')         #port of emulator
parser.add_argument('-f', '--filename')     #filename of forwarding table

args = parser.parse_args()

socket_addr = (socket.gethostbyname(socket.gethostname()), int(args.port))
soc = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
soc.bind(socket_addr)

newid = 0
sequence = 1
lasttrans = 0

# [id, (IP, Port), enabled(bool)]
nodes = []

# [(start, end, weight)]
edges = []

# Destination, NextHop
# [(IP, Port), cost, (IP, Port)] 
forwarding_table = []

#[(id, timestamp)]
latest_timestamps = []
largest_seq = []


def getnode(addr):
    for node in nodes:
            if(node[1] == addr):
                return node[0]

def getneighbors(node):
    neighbors = []
    for edge in edges:
        if(edge[0] == node):
            neighbors.append(edge[1])
    return neighbors


def getmilli():
    return round(time.time() * 1000)

def printdebug():
    for node in nodes:
        
        if(node[2]):
            print(node[0]+1, " ", node[1][0], node[1][1], " ", end="")

            for edge in edges:
                edgenode = nodes[edge[1]]
                if(edge[0] == node[0] and edgenode[2]):
                    print(edgenode[1][0], edgenode[1][1], edge[2], " ", end="")

                
            print()

    print()


    for entry in forwarding_table:
        if(entry[2] == -1):
            continue
        print(entry[0][0], entry[0][1], entry[2][0], entry[2][1])

    print()
    print()



# Called on topology change, also prints topology/forwarding table
def buildForwardTable():
    global forwarding_table

    valid_nodes = 0

    for node in nodes:
        if(node[2]):
            valid_nodes += 1

    newtable = [[socket_addr, 0, -1]]
    tentative = []

    nextnode = [socket_addr, 0, -1]

    while(1):
        for edge in edges:
            skip = 0;

            if(edge[0] == getnode(nextnode[0]) and nodes[edge[1]][2]):
                cost = nextnode[1] + edge[2]
                neighbor = nodes[edge[1]][1]
                nexT = nextnode[2] if nextnode[2] != -1 else neighbor

                for confirmed in newtable:
                    if(confirmed[0] == neighbor):
                        skip = 1
                        break

                if(skip):
                    continue

                for tent in tentative:
                    if(tent[0] == neighbor and tent[1] > cost):
                        tentative.remove(tent)
                        break
                    if(tent[0] == neighbor and tent[1] < cost):
                        skip = 1
                        break
                if(skip):
                    continue
                tentative.append([neighbor, cost, nexT])

        
        if(len(tentative) == 0):
            break;

        index = 0
        mindex = 0
        mincost = 0
        for t_node in tentative:
            if(t_node[1] < mincost):
                mincost = t_node[2]
                mindex = index

            index += 1
        newentry = tentative.pop(mindex)
        newtable.append(newentry)
        nextnode = newentry

    forwarding_table = newtable
    printdebug()
    return

def sendLinkState():
    global sequence
    startnode = getnode(socket_addr)

    data = ""
    length = 0
    
    for edge in edges:
        if(edge[0] == startnode and nodes[edge[1]][2] == True):
            data = data + str(edge[1]) + "," + str(edge[2]) + ","
            length += 1

    for edge in edges:
        if(edge[0] == startnode):
            dest_addr = nodes[edge[1]][1]
            newpacket = struct.pack("!cI4sH4sHII", 'L'.encode(), 5, socket.inet_aton(socket_addr[0]), socket_addr[1], socket.inet_aton(dest_addr[0]), dest_addr[1], sequence, length)
            newpacket = newpacket + data[:-1].encode()

            soc.sendto(newpacket, dest_addr)

    sequence += 1
    return


# Initial file read
def readtopology():
    global nodes 
    global edges
    global newid

    file = open(args.filename, "r")

    for line in file:
        entry = line.strip().split(" ")
        # Add node
        addr = (entry[0].split(",")[0], int(entry[0].split(",")[1]))
        nodes.append([newid, addr, True])
        latest_timestamps.append((newid, getmilli()))
        largest_seq.append((newid, 0))
        newid += 1

    file.seek(0)

    for line in file:
        entry = line.strip().split(" ")


        startaddr = (entry[0].split(",")[0], int(entry[0].split(",")[1]))
        startnode = 0

        for node in nodes:
            if(node[1] == startaddr):
                startnode = node[0]

        # Add edges

        index = 1
        while(index < len(entry)):
            endentry = entry[index].split(",")
            endaddr = (endentry[0], int(endentry[1]))
            distance = int(endentry[2])
            endnode = 0
            
            for node in nodes:
                if(node[1] == endaddr):
                    endnode = node[0]

            newedge = (startnode, endnode, distance)

            edges.append(newedge)

            index += 1

    file.close()

# Deal with received packets
def forwardpacket(from_addr, packet):
    global nodes
    global latest_timestamps
    global largest_seq
    packettype, ttl, sourceip, sourceport, destip, destport, sequence, length = struct.unpack("!cI4sH4sHII", packet[0:25])
    packettype = packettype.decode()
    sourceip = socket.inet_ntoa(sourceip)
    destip = socket.inet_ntoa(destip)

    if(packettype == 'H'):
        node = getnode((sourceip, sourceport))
        if(nodes[node][2] == False):
            nodes[node][2] = True;
            buildForwardTable()
            sendLinkState()
            
        latest_timestamps[node] = (latest_timestamps[node][0], getmilli())

    elif(packettype == 'L'):
        node = getnode((sourceip, sourceport))
        

        if(sequence <= largest_seq[node][1]):
            return
        
        largest_seq[node] = (largest_seq[node][0], sequence)
        data = packet[25:].decode()
        data = data.split(",")

        topologychanged = False


        index = 0
        while(index < length*2):
            node = int(data[index])
            neighbors = getneighbors(getnode(socket_addr))
            if(node in neighbors or node == getnode(socket_addr)):
                index += 2
                continue

            if(nodes[node][2] == False):
                nodes[node][2] = True
                buildForwardTable()
            
            
            latest_timestamps[node] = (node, getmilli())
            index += 2

        if(ttl > 0):
            ttl -= 1
            
            startnode = getnode(socket_addr)
            fromnode = getnode(from_addr)

            for edge in edges:
                if(edge[0] == startnode):
                    if(edge[1] != fromnode):
                        dest_addr = nodes[edge[1]][1]

                        newpacket = struct.pack("!cI4sH4sHII", 'L'.encode(), ttl, socket.inet_aton(sourceip), sourceport, socket.inet_aton(dest_addr[0]), dest_addr[1], sequence, length)
                        newpacket = newpacket + packet[25:]

                        soc.sendto(newpacket, dest_addr)
        
        return

    else:
        if(ttl == 0):
            newpacket = struct.pack("!cI4sH4sHII", 'T'.encode(), ttl, socket.inet_aton(socket_addr[0]), socket_addr[1], socket.inet_aton(destip), destport, sequence, length)
            soc.sendto(newpacket, (sourceip, sourceport)) 
        else:

            for entry in forwarding_table:
                if(entry[0] == (destip, destport)):
                    sendaddr = entry[2]

            newpacket = struct.pack("!cI4sH4sHII", 'T'.encode(), ttl - 1, socket.inet_aton(sourceip), sourceport, socket.inet_aton(destip), destport, sequence, length)
            soc.sendto(newpacket, sendaddr)

        
    return


def createroutes():
    global lasttrans
    global nodes
    while(1):
        try:
            soc.setblocking(False)
            incoming_packet, incoming_addr = soc.recvfrom(65565)
        except:
            # Do nothing
            print(end="")
        else:
            forwardpacket(incoming_addr, incoming_packet)
        finally:

            # Send hello
            if(getmilli() - lasttrans > 1000):

                startnode = getnode(socket_addr)


                for edge in edges:
                    if(edge[0] == startnode):
                        dest_addr = nodes[edge[1]][1]
                        newpacket = struct.pack("!cI4sH4sHII", 'H'.encode(), 0, socket.inet_aton(socket_addr[0]), socket_addr[1], socket.inet_aton(dest_addr[0]), dest_addr[1], 0, 0)
                        soc.sendto(newpacket, nodes[edge[1]][1])

                sendLinkState()
                lasttrans = getmilli()


        # Check received hellos
            neighbors = getneighbors(getnode(socket_addr))

            for timestamp in latest_timestamps:
                if(getmilli() - timestamp[1] > 2000 and nodes[timestamp[0]][2] == True and timestamp[0] != getnode(socket_addr)):
                    nodes[timestamp[0]][2] = False
                    buildForwardTable()
                    sendLinkState()
        
                
            
    

readtopology()
buildForwardTable()
createroutes()

soc.close()

# struct.pack("!cI4sH4sHII", 'H'.encode(), 0, socket.inet_aton(), 0, socket.inet_aton(), 0, 0, 0)
# packettype, ttl, sourceip, sourceport, destip, destport, sequence, length= struct.unpack("!cI4sH4sHII", packet) ; socket.inet_ntoa()
