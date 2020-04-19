import socket
import enum
import struct


class IpPacket(object):
    """
    Represents the *required* data to be extracted from an IP packet.
    """

    def __init__(self, protocol, ihl, source_address, destination_address, payload):
        self.protocol = protocol
        self.ihl = ihl
        self.source_address = source_address
        self.destination_address = destination_address
        self.payload = payload

    def to_str(self):
        string = "IHL: " + str(self.ihl) + "\n" \
                 + "Protocol: " + str(self.protocol) + "\n" \
                 + "Source address: " + self.source_address + "\n" \
                 + "Destination address: " + self.destination_address
        return string


class TcpPacket(object):
    """
    Represents the *required* data to be extracted from a TCP packet.
    """

    def __init__(self, src_port, dst_port, data_offset, payload):
        self.src_port = src_port
        self.dst_port = dst_port
        # As far as I know, this field doesn't appear in Wireshark for some reason.
        self.data_offset = data_offset
        self.payload = payload

    def to_str(self):
        try:
            string = "Source port: " + str(self.src_port) + "\n" \
                     + "Destination port: " + str(self.dst_port) + "\n" \
                     + "Data offset: " + str(self.data_offset) + "\n" \
                     + "Data: " + self.payload.decode("UTF-8")
        except:
            string = "Cannot decode to UTF-8"
        return string


class InternetProtocol(enum.Enum):
    TCP = 6
    UDP = 17


def print_packet_data(ip_packet: IpPacket, tcp_packet: TcpPacket):
    print(ip_packet.to_str())
    print(tcp_packet.to_str())
    return None


def parse_raw_ip_addr(raw_ip_addr: bytes) -> str:
    # the input is on the form b'\xaa\xab'... a byte array
    address = str(raw_ip_addr[0]) + "." + str(raw_ip_addr[1]) \
              + "." + str(raw_ip_addr[2]) + "." + str(raw_ip_addr[3])
    return address


def parse_application_layer_packet(ip_packet_payload: bytes) -> TcpPacket:
    # Parses raw bytes of a TCP packet
    # That's a byte literal (~byte array) check resources section
    source_port = struct.unpack("!H", ip_packet_payload[0:2])[0]
    destination_port = struct.unpack("!H", ip_packet_payload[2:4])[0]
    offset = (ip_packet_payload[12] & 0xF0) >> 4
    payload = ip_packet_payload[offset * 4:]
    return TcpPacket(source_port, destination_port, offset, payload)


def parse_network_layer_packet(ip_packet: bytes) -> IpPacket:
    # Parses raw bytes of an IPv4 packet
    # That's a byte literal (~byte array) check resources section
    ihl = ip_packet[0] & 0x0F
    protocol = ip_packet[9]
    source_address = parse_raw_ip_addr(ip_packet[12:16])
    destination_address = parse_raw_ip_addr(ip_packet[16:20])
    payload = ip_packet[ihl * 4:]
    return IpPacket(protocol, ihl, source_address, destination_address, payload)


def process_packet(packet: bytes, address: list):
    ip_packet = parse_network_layer_packet(packet)
    tcp_packet = parse_application_layer_packet(ip_packet.payload)
    # print_packet_data(ip_packet, tcp_packet)
    try:
        print(tcp_packet.payload.decode("UTF-8"))
    except:
        print("Cannot decode to UTF-8")
    return None


def setup_socket():
    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, InternetProtocol.TCP.value)
    return sock


def main():
    stealer = setup_socket()
    # Un-comment this line if you're getting too much noisy traffic.
    # to bind to an interface on your PC. (or you can simply disconnect from the internet)

    # iface_name = "lo"
    # stealer.setsockopt(socket.SOL_SOCKET,
    #                    socket.SO_BINDTODEVICE, bytes(iface_name, "ASCII"))
    while True:
        # Receive packets and do processing here
        packet, address = stealer.recvfrom(4096)
        process_packet(packet, address)
    pass


if __name__ == "__main__":
    main()
