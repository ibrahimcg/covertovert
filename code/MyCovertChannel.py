from CovertChannelBase import CovertChannelBase

from scapy.sendrecv import srp, sniff
from scapy.layers.inet import Ether
from scapy.layers.l2 import ARP, LLC, SNAP
from scapy.all import get_if_hwaddr
import random
import time

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


    def send(self, log_file_name, parameter1, parameter2, parameter3):
        """
        - We first get the MAC address of the sender.
        - Then, we create an Ethernet frame with the source MAC address of the sender and the destination MAC address of the broadcast address.
        - We generate a random binary message.
        - For each byte in the message, we XOR it with parameter1.
        - Then for each bit we generate a random number between 0 and (parameter2-1) or between parameter2 and 15 depending on the parameter3.
        - If the first bit of the parameter3 is 0 we generate a random number between 0 and (parameter2-1), otherwise between parameter2 and 15.
        - If the second bit of the parameter3 is 0 we generate a random number between 0 and (parameter2-1), otherwise between parameter2 and 15.
        - We send the message with combining these 2 halfbytes to the SSAP field of the LLC layer.
        """
        sender_mac = get_if_hwaddr("eth0")
        ether = Ether(src = sender_mac, dst = "ff:ff:ff:ff:ff:ff")

        self.message = self.generate_random_binary_message_with_logging(log_file_name, min_length=16, max_length=16)
        
        start_time = time.time()

        for i in range(0, len(self.message), 8):
            byte = self.message[i:i + 8]
            byte = int(byte, 2)
            byte ^= parameter1
            byte = str(bin(byte))[2:].zfill(8)

            for j in range(0, 8, 2):
                bits = byte[j:j + 2]

                if parameter3 % 2 == 0:
                    bits0 = random.randint(parameter2,15) if bits[0] == '1' else random.randint(0,parameter2-1)
                else:
                    bits0 = random.randint(parameter2,15) if bits[0] == '0' else random.randint(0,parameter2-1)
                
                if parameter3 > 1:
                    bits1 = random.randint(parameter2,15) if bits[1] == '1' else random.randint(0,parameter2-1)
                else:
                    bits1 = random.randint(parameter2,15) if bits[1] == '0' else random.randint(0,parameter2-1)

                bits = str(bin(bits0))[2:].zfill(4) + str(bin(bits1))[2:].zfill(4)

                llc = LLC(dsap=0x69, ssap=int(bits, 2))
                packet = ether / llc
                super().send(packet)

        end_time = time.time()
        time_diff = end_time - start_time
        result = 128 / time_diff
        print(f"Sent {len(self.message)} bytes in {time_diff} seconds. The bandwidth is {result} bytes/second.")
        
    def receive(self,log_file_name, parameter1, parameter2, parameter3):
        """
        - We sniff the packets.
        - For each packet, we check if it has LLC layer.
        - If it has, we extract the SSAP field.
        - First we check parameter3 to determine the range of the random number for two bits.
        - If the first bit of the parameter3 is 0 we check if the first 4 bits of the SSAP field is greater than or equal to parameter2.
        - If it is, we set the first bit of the byte to 1, otherwise 0.
        - Likewise, if the second bit of the parameter3 is 0 we check if the last 4 bits of the SSAP field is greater than or equal to parameter2.
        - If it is, we set the second bit of the byte to 1, otherwise 0.
        - We concatenate these 2 bits to form a byte.
        - After 4 packets, we get a byte.
        - Then we XOR the byte with parameter1.
        - We convert the byte to a character.
        - We check if the received character is a dot character. If it is, we stop receiving the message.
        - We log the message to the log file.
        """
        byte = ""
        counter = 0

        def recv_packet(packet):
            nonlocal byte
            nonlocal counter

            if LLC in packet:
                packet.show()
                ssap_byte = bin(packet[LLC].ssap)[2:].zfill(8)
                bits0 = ssap_byte[:4]
                bits1 = ssap_byte[4:]

                if parameter3 % 2 == 0:
                    bit0 = '1' if int(bits0, 2) >= parameter2 else '0'
                else:
                    bit0 = '0' if int(bits0, 2) >= parameter2 else '1'

                if parameter3 > 1:
                    bit1 = '1' if int(bits1, 2) >= parameter2 else '0'
                else:
                    bit1 = '0' if int(bits1, 2) >= parameter2 else '1'
                
                bits = bit0 + bit1
                byte += bits
                counter += 1
                
                if counter == 4:
                    counter = 0
                    byte = int(byte, 2)
                    byte ^= parameter1

                    received_char = chr(byte)
                    
                    self.message += received_char
                    byte = ""

                    if received_char == '.':
                        raise Exception("Dot character received in the message")

        try:
            sniff(prn=recv_packet)
        except Exception as e:
            print(e)

        self.log_message(self.message, log_file_name)
