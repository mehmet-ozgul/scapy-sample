from scapy.all import *
from scapy.layers.inet import UDP
from scapy.layers.rtp import RTP
from scapy.utils import PcapWriter
import logging

logger = logging.getLogger("juicy-rtp")
logger.setLevel(logging.DEBUG)

INPUT_FILE = 'the-call.pcap'
OUTPUT_FILE = 'modified-call.pcap'
SPORT = 35322
DPORT = 16662

TARGET_SEQS = [17261, 17285, 17362]
TS_OFFSET = 1558200000
MAX_PACKETS_TO_MODIFY = 2


def main():
    bind_layers(UDP, RTP, sport=SPORT, dport=DPORT)
    packets = rdpcap(INPUT_FILE)
    modified_pcap = PcapWriter(OUTPUT_FILE)
    modified_packets = 0
    mark_next = False
    for p in packets:
        r = p["RTP"]
        if mark_next:
            r.marker = 1
            mark_next = False
        if modified_packets > 0:
            logger.info("Modifying conseq packets, seq=%d c=%d", r.sequence, modified_packets)
            r.timestamp = r.timestamp - TS_OFFSET
            modified_packets = modified_packets + 1
            if modified_packets >= MAX_PACKETS_TO_MODIFY:
                logging.info("Resetting, seq=%d", r.sequence)
                mark_next = True
                modified_packets = 0
        elif r.sequence in TARGET_SEQS:
            logger.info("Starting to modify, seq=%d c=%d", r.sequence, modified_packets)
            r.marker = 1
            r.timestamp = r.timestamp - TS_OFFSET
            modified_packets = 1

        logger.info("Writing packet, seq=%d m=%d ts=%d", r.sequence, r.marker, r.timestamp)
        p["UDP"].payload = r
        modified_pcap.write(p)


if __name__ == '__main__':
    main()
