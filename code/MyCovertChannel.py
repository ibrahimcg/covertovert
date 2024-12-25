from CovertChannelBase import CovertChannelBase

from scapy.sendrecv import srp, sniff
from scapy.layers.inet import Ether
from scapy.layers.l2 import ARP, LLC, SNAP
from scapy.all import get_if_hwaddr

class MyCovertChannel(CovertChannelBase):
    """
    - You are not allowed to change the file name and class name.
    - You can edit the class in any way you want (e.g. adding helper functions); however, there must be a "send" and a "receive" function, the covert channel will be triggered by calling these functions.
    """
    def __init__(self):
        """
        - You can edit __init__.
        """
        self.message = ""


    def send(self, log_file_name, parameter1, parameter2):
        """
        -
        -
        """
        sender_mac = get_if_hwaddr("eth0")
        ether = Ether(src = sender_mac, dst = "ff:ff:ff:ff:ff:ff")

        self.message = self.generate_random_binary_message_with_logging(log_file_name)

        for i in range(0, len(self.message), 8):
            byte = self.message[i:i + 8]
            byte = int(byte, 2)
            byte ^= 0x69
            byte = str(bin(byte))[2:].zfill(8)

            for j in range(4):
                bits = byte[j:j + 2]
                llc = LLC(dsap=0x69, ssap=(0b11011000 | int(bits, 2)))
                packet = ether / llc
                super().send(packet)
            
                
        
    def receive(self, parameter1, parameter2, parameter3, log_file_name):
        """
        -
        -
        """
        byte = ""
        counter = 0

        def recv_packet(packet):
            nonlocal byte
            nonlocal counter

            if LLC in packet:
                byte = str(bin(byte))[2:] + byte
                counter += 1
                if counter == 4:
                    counter = 0
                    byte = int(byte, 2)
                    byte ^= 0x69
                    received_bits = str(bin(byte))[2:].zfill(8)
                    received_char = chr(int(received_bits, 2))
                    print(received_char)
                    self.message += received_char
                    byte = ""
                
                    if received_char == '.':
                        raise Exception("Dot character received in the message")

        try:
            sniff(prn=recv_packet)
        except Exception as e:
            print(e)

        self.log_message(self.message, log_file_name)
