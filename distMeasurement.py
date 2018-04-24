import socket
import struct
import time
import ipaddress
import select

class TraceRoute(object):
    def getfile(dst='targets.txt'):
        f = open(dst)
        list = f.readlines()
        stripped_lline = [s.rstrip() for s in list]
        return stripped_lline

    def __init__(self,destination = 'www.google.com',hops = 30, port = 33434):
        """initializes the object for route tracing
        destination (str) = the destination of the probe
        hops (int) = the number of hops the probe will take before quitting
        ttl = the number of hops that can still be made by the current packet.
        port (int) = the port number of the listening socket
        """
        self.dst = destination
        self.hops = hops
        self.ttl = 100

        self.port = port

    def run(self):
        """Runs the traceroute. This is done by creating a sending socket and a recieving socket.
        After that a udp datagram is sent out and using the Traceroute method we trace the route back to the
        sender through the response ICMP messages. Then, we check to see if this was the one we sent out by
        comparing the port number of the encapsulated UDP datagram against the ne that it was initially sent
        as.
        :return:
        """
        """This is used as dns query to get the ip address of the destination from the host name"""
        try:
            destination_ip = socket.gethostbyname(self.dst)
        except socket.error as e:
            raise IOError('Unable to resolve {}: {}', self.dst, e)
        output_message = 'traceroute to ' + self.dst  + '('+destination_ip+')'

        print(output_message)
        ## eD42~dW$M+2T
        ##THe main body of the run. This loops until either A 30 hops has been achieved
        ##or B when we get to the destination. This is checked by looking at the return ICMP
        ##type and code message
        ##These are some of the values that are known for various parts of the ICMP packet
        portNumberAddress = 50
        sourceIPAddress = 12
        ICMP_type = 20
        ICMP_code = 21
        end_of_icmp = 24
        ttl_of_packet_address = 36


        recv_sock = self.create_listener()
        send_sock = self.create_sender()
        msg = 'measurement for class project. questions to student abc123@case.edu or professor mxr136@case.edu'
        payload = bytes(msg + 'a'*(1472 - len(msg)),'ascii')
        startTimer = time.time()
        recv_sock_list, ready_to_write, in_error = select.select([recv_sock],[send_sock],'',20)
        print(recv_sock_list)
        send_sock.sendto(payload, (destination_ip, self.port))
        while True:
            try:
                icmp_packet = recv_sock_list[recv_sock].recv(65536)
                print(icmp_packet)
                entTimer = time.time()
            except socket.error as e:
                raise IOError('socket error {}'.format((e)))
            finally:
                recv_sock.close()
                send_sock.close()

            ###This is unpacking the ICMP message and getting the needed fields out of it.
            port_from_packet = struct.unpack("!H", icmp_packet[portNumberAddress:portNumberAddress+2])[0]
            ip_from_packet = struct.unpack("!I",icmp_packet[sourceIPAddress:sourceIPAddress+4])[0]
            readable_ip = socket.inet_ntoa(icmp_packet[sourceIPAddress:sourceIPAddress+4])
            ##These are used to determine whether we reached our destination
            icmp_message_type = icmp_packet[ICMP_type]
            icmp_message_code = icmp_packet[ICMP_code]

            ##This is the TTL Left on the original packet
            ttl_of_packet = icmp_packet[ttl_of_packet_address]
            ##We are checking whether the port numbers match up if yes we can confirm it is from our probe
            if port_from_packet == self.port:
                timeCost = round((entTimer - startTimer) * 1000, 2)
                print('Hops:',self.ttl - ttl_of_packet, 'IP address:',readable_ip,'Time:', timeCost,'ms','Bytes of original datagram:',len(icmp_packet)-end_of_icmp)
            else:
                print(self.ttl)
            self.ttl += 1
            if(self.ttl > self.hops ):
                break
            elif(icmp_message_code == 3 and icmp_message_type == 3):
                break

    def create_listener(self):
        """
        create a recieving socket that is bound to the port number self.port
        :return: the recieving socket

        raises IOERROR when socket fails to bind to set port.
        """
        recv_sock  = socket.socket(socket.AF_INET,socket.SOCK_RAW,socket.IPPROTO_ICMP)

        try:
            recv_sock.setblocking(0)
            recv_sock.bind(('',self.port))
        except socket.error as e:
            raise IOError('Failure to bind reciever socket!{}'.format(e))
        return recv_sock

    def create_sender(self):
        """
        create_sending creates a sending socket with the ttl set to the self.ttl
        :return:
            the sending socket
        """
        send_sock = socket.socket(socket.AF_INET,socket.SOCK_DGRAM,socket.IPPROTO_UDP)
        send_sock.setsockopt(socket.SOL_IP,socket.IP_TTL,self.ttl)
        return send_sock

if __name__ == '__main__':
    listOfTargets = TraceRoute.getfile()
    print(listOfTargets)
    for targets in listOfTargets:
        target = TraceRoute(destination=targets)
        target.run()


