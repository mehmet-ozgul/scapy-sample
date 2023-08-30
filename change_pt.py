from scapy.all import *
from scapy.layers.inet import UDP
from scapy.layers.rtp import RTP
from scapy.utils import PcapWriter
import logging

logger = logging.getLogger("juicy-rtp")
logger.setLevel(logging.DEBUG)

INPUT_FILE = '/Users/mehmetozgul/projects/genius/sdp/sdp-sip-traffic-generator/scenarios/interleaved.g711.pcap'
OUTPUT_FILE = '/Users/mehmetozgul/projects/genius/sdp/sdp-sip-traffic-generator/scenarios/interleaved.g711.alaw.pcap'
SPORT = 44598
DPORT = 20096


def main():
    bind_layers(UDP, RTP, sport=SPORT, dport=DPORT)
    packets = rdpcap(INPUT_FILE)
    modified_pcap = PcapWriter(OUTPUT_FILE)
    for p in packets:
        r = p["RTP"]
        if r.payload_type == 0:
            r.payload_type = 8

        logger.info("Writing packet, seq=%d m=%d ts=%d", r.sequence, r.marker, r.timestamp)
        p["UDP"].payload = r
        modified_pcap.write(p)


if __name__ == '__main__':
    main()
