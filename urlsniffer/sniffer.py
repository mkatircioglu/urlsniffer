#!/usr/bin/python
import re
import sys
import signal
import logging
import socket
import pcapy
from impacket import ImpactDecoder
from urlparse import urlparse

ETHERNET_MAX_FRAME_SIZE = 1518
PROMISC_MODE = 0
REGEX_LINKS = re.compile("((https?|ftp|gopher|telnet|file|notes|ms-help|rtmp|rtmpe):((//)|(\\\\))[\w\d:#%/;$()~_?\-=\\\.&!]*)")

class Packet(object):
    def __init__(self, link, timestamp, proto_id, src_ip, tgt_ip, src_port, tgt_port):
        super(Packet, self).__init__()
        self.link = link
        self.src_ip = src_ip
        self.tgt_ip = tgt_ip
        self.src_port = src_port
        self.tgt_port = tgt_port
        self.timestamp = timestamp
        self.protocol = "unknown"
        try:
            if proto_id:
                if proto_id == socket.IPPROTO_TCP:
                    self.protocol = "TCP"
                elif proto_id == socket.IPPROTO_UDP:
                    self.protocol = "UDP"
        except Exception, msg:
            logging.error("Sniffer:start_sniffing : failed setting protocol. Error: %s" % str(msg))

class Sniffer(object):
    """ @brief Class for sniffing and detecting packets.
    """

    def __init__(self, options):
        """ @brief Initialize data.

            @param List containing dest ports to sniff for.
        """
        super(Sniffer, self).__init__()
        self.decoder = None
        self.captured_device = None
        self.options = options

    def do_sniffing(self):
        """ @brief Do sniffing and return results.

            @param device String that represents the device on which to capture packets.
        """
        try:
            self.captured_device = pcapy.open_live(self.options.interface, ETHERNET_MAX_FRAME_SIZE,
                                                   PROMISC_MODE, self.options.timeout)
        except Exception, msg:
            logging.error("Sniffer:start_sniffing : open_live() failed for device='%s'. Error: %s" % (self.options.interface,
                                                                                                      str(msg)))
        else:
            logging.debug("Sniffer:start_sniffing : Listening on %s: net=%s, mask=%s" % (self.options.interface,
                                                                                         self.captured_device.getnet(),
                                                                                         self.captured_device.getmask()))
            if self.captured_device:
                datalink = self.captured_device.datalink()
                if datalink == pcapy.DLT_EN10MB:
                    self.decoder = ImpactDecoder.EthDecoder()
                elif datalink == pcapy.DLT_LINUX_SLL:
                    self.decoder = ImpactDecoder.LinuxSLLDecoder()
                else:
                    logging.critical("Datalink type not supported:%s" % datalink)
                    sys.exit(1)

                try:
                    # maxcant is set to -1, so all packets are captured until the timeout
                    self.captured_device.loop(0, self.receive_packets)
                except Exception, msg:
                    logging.error("Sniffer:start_sniffing : dispatch() failed for device='%s'. Error: %s" %
                                                                            (self.options.interface, str(msg)))

    def receive_packets(self, hdr, data):
        """ @brief Callback function for pcapy sniffer. """
        link = ""
        timestamp = None
        proto_id = None
        src_ip = None
        tgt_ip = None
        src_port = None
        tgt_port = None

        # try to decode the packet data using impacket
        try:
            decoded_data = self.decoder.decode(data)
        except Exception, msg:
            logging.error("Sniffer:receive_packets : impacket decoder raised exception: %s" % str(msg))
        else:
            # get the details from the decoded packet data
            if decoded_data:
                # get details from IP packet
                try:
                    src_ip = decoded_data.child().get_ip_src()
                    tgt_ip = decoded_data.child().get_ip_dst()
                    proto_id = decoded_data.child().child().protocol
                    data = decoded_data.child().child().get_packet()
                except Exception, msg:
                    logging.error("Sniffer:receive_packets : exception while parsing ip packet: %s" % str(msg))
                # get details from TCP/UDP packet
                else:
                    if data:
                        for item in REGEX_LINKS.finditer(str(data)):
                            if not item:
                                continue
                            else:
                                link = item.groups()[0]

                    if proto_id:
                        try:
                            if proto_id == socket.IPPROTO_TCP:
                                tgt_port = decoded_data.child().child().get_th_dport()
                                src_port = decoded_data.child().child().get_th_sport()
                            elif proto_id == socket.IPPROTO_UDP:
                                tgt_port = decoded_data.child().child().get_uh_dport()
                                src_port = decoded_data.child().child().get_uh_sport()
                        except Exception, msg:
                            logging.error("Sniffer:receive_packets : exception while parsing tcp/udp packet: %s" % str(msg))

        try:
            timestamp = hdr.getts()[0]
        except Exception, msg:
            logging.error("Sniffer:receive_packets : failed getting timestamp from header. Exception: %s" % str(msg))

        try:
            packet = Packet(link, timestamp, proto_id,
                            src_ip, tgt_ip, src_port, tgt_port)
        except Exception, msg:
            logging.error("Sniffer:receive_packets : failed constructing Packet object. Exception: %s" % str(msg))
        else:
            log_package_information(self.options, packet)

def log_package_information(options, packet):
    if packet.link and packet.tgt_port == options.port and packet.protocol == options.protocol:
        packet_information = "%s\t%s\t%s\t%s\n" % (packet.timestamp, packet.src_ip, packet.tgt_ip, urlparse(packet.link).netloc)
        if options.daemon:
            log_file = open(options.dumpfile, mode='a')
            log_file.write(packet_information)
            log_file.close()
        else:
            print packet_information

def capture_process(options):
    logging.debug("Network Device is capturing.")
    sniffer = Sniffer(options)
    sniffer.do_sniffing()
