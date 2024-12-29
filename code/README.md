# covertovert

A covert channel is a method of communication that is used to transmit information in a stealthy way. It utilizes unintended use of protocols. There are two types of covert channels which are covert storage channels and covert timing channels. Covert storage channels involve writing and reading data to and from a shared resources such as some bits in some fields while covert timing channels involve manipulating the timing of events to convey information.

This covert channel implements a storage channel. It utilizes protocol field manipulation by exploiting the SSAP field in the LLC layer. The purpose of the SSAP field is to identify the network layer protocol that generated the frame, but in this covert channel implementation, it is manipulated to encode and transmit hidden messages.

As the purpose of the covert channels is to convey information in a stealth way, the information must be encoded by the sender and decoded by the receiver. This covert channel encodes the message in the following way. 

## Packet Structure
### Ethernet Frame
The covert channel uses standard Ethernet frames with the following structure:

* Source MAC Address: The MAC address of the sender (obtained from eth0 interface)
* Destination MAC Address: Broadcast address (ff:ff:ff:ff:ff:ff)
* LLC Layer:
    * SSAP: Used for covert data transmission (manipulated field)

Each packet carries 2 bits of the encoded message within this field.
 
## Important Notes
* Both sender and receiver must use the same parameters to ensure safe encoding and decoding
* **Covert Channel Capacity**: ~85 bits/second
 
## Parameters

The system uses the 4 parameters in the config.json file:
```
{
  "covert_channel_code": "CSC-PSV-TCP-WS",
  "send": {
    "parameters": {
      "parameter1": 105,
      "parameter2": 8,
      "parameter3": "up",
      "parameter4": "down",
      "log_file_name": "Example_UDPTimingInterarrivalChannelSender.log"
    }
  },
  "receive": {
    "parameters": {
      "parameter1": 105,
      "parameter2": 8,
      "parameter3": "up",
      "parameter4": "down",
      "log_file_name": "Example_UDPTimingInterarrivalChannelReceiver.log"
    }
  }
}
```
* **parameter1**: Takes a value between 0 and 255
* **parameter2**: Takes a value between 1 and 15
* **parameter3**: Takes either "up" or "down"
* **parameter4**: Takes either "up" or "down"

## Encoding Process

### Initial Encoding
The covert channel begins by XORing each byte of the message with parameter1.

### Message Transmission
After XORing, the message is sent in bit pairs. Before embedding these 2 bits into the SSAP field, an additional encoding is performed.

### SSAP Field Structure
Since the SSAP field is one byte long, it is divided into 2 halfbytes, each responsible for one of the sent bits. A halfbyte can take a value between 0 and 15. Using parameter2, this range is divided into two subsets:
* `[0, parameter2 - 1]`
* `[parameter2, 15]`

### Bit Mapping

#### Significant Bit
When parameter3 is "up":
* Range `[parameter2, 15]` corresponds to value 1
* Range `[0, parameter2-1]` corresponds to value 0

When parameter3 is "down":
* The mapping is reversed

#### Insignificant Bit
When parameter4 is "up":
* Range `[parameter2, 15]` corresponds to value 1
* Range `[0, parameter2-1]` corresponds to value 0

When parameter4 is "down":
* The mapping is reversed

### Random Number Generation
For both significant and insignificant bits, a random number is generated from the corresponding range based on the bit's value.

### Final SSAP Field Value
After generating two halfbytes with respect to the algorithm defined above, we combine them into one byte and use it as the SSAP Field Value.

## Decoding
The receiver decodes the message by reversing the above process.

