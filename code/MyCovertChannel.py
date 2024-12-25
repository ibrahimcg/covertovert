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

        for bit in self.message:
            llc = LLC(dsap=0x69, ssap=int(bit))
            packet = ether / llc
            super().send(packet)
        
                
        
    def receive(self, parameter1, parameter2, parameter3, log_file_name):
        """
        -
        -
        """
        def recv_packet(packet):
            if packet.haslayer(LLC):
                if packet[LLC].dsap == 0xff:
                    raise Exception
                
                packet.show()
                self.message = self.message + str(packet[LLC].ssap)

        try:
            sniff(prn=recv_packet)
        except Exception:
            pass

        chars = [self.message[i:i+8] for i in range(0, len(self.message), 8)]
        
        message = ""
        for char in chars:
            message = message + self.convert_eight_bits_to_character(char)

        self.log_message(message, log_file_name)
