from scapy.all import *
from scapy.layers.inet import IP, UDP
from scapy.layers.rtp import RTP
from scapy.utils import PcapWriter
import logging

logger = logging.getLogger("juicy-rtp")
logger.setLevel(logging.DEBUG)

INPUT_FILE = '/Users/mehmetozgul/projects/genius/sdp/sdp-sip-traffic-generator/scenarios/interleaved.g711.pcap'
OUTPUT_FILE = '/Users/mehmetozgul/projects/genius/sdp/sdp-sip-traffic-generator/scenarios/interleaved.g711.scrubbed.pcap'
SPORT = 44598
DPORT = 20096

# a silent A-law encoded PCM channel has the 8 bit samples coded 0xD5 instead of 0x80 in the octets.
# ulaw Note that 0 is transmitted as 0xFF, and −1 is transmitted as 0x7F, but when received the result is 0 in both cases.
ULAW_SILENCE = b'\x7F'
ALAW_SILENCE = b'\xD5'


def main():
    bind_layers(UDP, RTP, sport=SPORT, dport=DPORT)
    packets = rdpcap(INPUT_FILE)
    modified_pcap = PcapWriter(OUTPUT_FILE)
    fill_value = 42
    for p in packets:
        ipv4 = p["IP"]
        ipv4.src = "10.0.0.1"
        ipv4.dst = "10.0.0.2"

        r = p["RTP"]
        # TODO: Find out how to write audio payload of RTP using scapy

        fv = (fill_value % 256).to_bytes(1, byteorder='big', signed=False)

        if r.payload_type == 0:
            fill_value = fill_value + 1
            r.payload = Raw(r.payload.__len__() * fv)
        elif r.payload_type == 8:
            fill_value = fill_value + 1
            r.payload = Raw(r.payload.__len__() * fv)

        logger.info("Writing packet, seq=%d m=%d ts=%d", r.sequence, r.marker, r.timestamp)
        # p["UDP"].payload = r
        modified_pcap.write(p)


if __name__ == '__main__':
    main()
