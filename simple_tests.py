from lab3_skeleton import parse_application_layer_packet, parse_network_layer_packet, parse_raw_ip_addr, IpPacket, TcpPacket
import sys
import binascii

####################################################
####################################################
############# H A C K Y   C O D E S ################
####################################################
####################################################
# https://stackoverflow.com/questions/5762491/how-to-print-color-in-console-using-system-out-println
# https://www.linuxjournal.com/article/8603
# those guys don't work on poor windows (mostly)
ANSI_RESET = "\u001B[0m"
ANSI_RED = "\u001B[31m"
ANSI_GREEN = "\u001B[32m"


def caller_info():
    caller_stackframe = sys._getframe().f_back.f_back
    function_name = caller_stackframe.f_code.co_name
    line_num = caller_stackframe.f_lineno

    return function_name, line_num


def do_assert(correct, actual, case=""):
    fn_name, fn_lineno = caller_info()
    if correct != actual:
        msg_hd = f"{ANSI_RED}Line {fn_lineno} [failed] {fn_name}: {case}"
        msg_tl = f" \nExpected ( %s ) got ( %s ) {ANSI_RESET}\n" % (
            correct, actual)
        print(msg_hd+msg_tl)
    else:
        print(f"{ANSI_GREEN}[success] {fn_name}: {case}{ANSI_RESET}")

####################################################
####################################################


def test_parse_ip_addr():
    # this is NOT a string. It's a byte literal (byte array).
    # treat this as an array in your code and it'll work.
    ip_raw = b'\x7f\x00\x00\x01'

    actual_value = parse_raw_ip_addr(ip_raw)
    correct_value = "127.0.0.1"
    case = "Parse IP address."
    do_assert(correct_value, actual_value, case)


def test_ip_packet_parsing():
    # Returns a byte array, don't use binascii. It's just for aesthetics.
    packet = binascii.unhexlify(
        b'450000280000400040063cce7f0000017f00000201bbc5b000000000c59af2b15014000032160000')

    ip_packet: IpPacket = parse_network_layer_packet(packet)

    actual_value = ip_packet.ihl
    correct_value = 5
    case = "IHL."
    do_assert(correct_value, actual_value, case)

    actual_value = ip_packet.source_address
    correct_value = "127.0.0.1"
    case = "Source address."
    do_assert(correct_value, actual_value, case)

    actual_value = ip_packet.destination_address
    correct_value = "127.0.0.2"
    case = "Destination address."
    do_assert(correct_value, actual_value, case)


def test_tcp_data_packet():
    # Returns a byte array, don't use binascii. It's just for aesthetics.
    packet = binascii.unhexlify(b'45000043a5424000400697707f0000017f000001bb72dd5a05e9a678cbb9a7'
                                b'e180180156fe3700000101080ae94db495e94d9686746869736973616d6573736167650a')
    ip_packet: IpPacket = parse_network_layer_packet(packet)
    tcp_packet: TcpPacket = parse_application_layer_packet(ip_packet.payload)

    actual_value = tcp_packet.src_port
    correct_value = 47986
    case = "TCP source port."
    do_assert(correct_value, actual_value, case)

    actual_value = tcp_packet.dst_port
    correct_value = 56666
    case = "TCP destination port."
    do_assert(correct_value, actual_value, case)

    actual_value = tcp_packet.data_offset
    correct_value = 8
    case = "TCP data offset."
    do_assert(correct_value, actual_value, case)

    actual_value = tcp_packet.payload
    correct_value = bytes("thisisamessage\n", encoding="UTF-8")
    case = "TCP payload."
    do_assert(correct_value, actual_value, case)


def main():
    # Returns a byte array, don't use binascii. It's just for aesthetics.
    # This call just converts a hex stream into a byte array (just so code looks acceptable)
    pbr = binascii.unhexlify(b'4500003c5cfd40004006dfbc7f0000017f000001bad0dd5a3b012bb'
                             b'67e80e7b280180156fe3000000101080ae945da61e945ca')

    # This is a byte array.
    pbl = b'E\x00\x00<\\\xfd@\x00@\x06\xdf\xbc\x7f\x00\x00\x01\x7f\x00\x00\x01\xba\xd0\xddZ;\x01+\xb6~\x80\xe7\xb2\x80\x18\x01V\xfe0\x00\x00\x01\x01\x08\n\xe9E\xdaa\xe9E\xca'

    # Just to prove that they're equivalent.
    assert pbl == pbr
    test_parse_ip_addr()
    test_ip_packet_parsing()
    test_tcp_data_packet()


if __name__ == "__main__":
    main()
