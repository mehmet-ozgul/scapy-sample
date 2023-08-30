from scapy.all import *
from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import Ether
from scapy.layers.rtp import RTP
from scapy.utils import PcapWriter
import logging

logger = logging.getLogger("juicy-rtp")
logger.setLevel(logging.DEBUG)

ALAW_AUDIO = 'sine.10m.alaw.raw'
# ULAW_AUDIO = 'sine.10m.ulaw.raw'
ULAW_AUDIO = 'snl.ulaw.raw'
USE_ULAW = True
AUDIO_FILE = ULAW_AUDIO if USE_ULAW else ALAW_AUDIO
OUTPUT_FILE = f"snl.{'ulaw' if USE_ULAW else 'alaw'}.pcap"
PTIME = 20
SAMPLE_RATE = 8000
SPP = int((PTIME * SAMPLE_RATE) / 1000)
DURATION_MS = 30000
N_PACKETS = int(DURATION_MS / PTIME)

DTX_POINTS = {
    100: 1,
    200: 2,
    300: 5,
    320: 1,
    322: 1,
    325: 1,
    500: 10,
    600: 20,
    700: 50,
    800: 100
}

SRC_IP = '10.0.0.1'
DST_IP = '10.0.0.2'
SRC_PORT = 16000
DST_PORT = 24400


def get_audio_samples(file_object, n_packets, spp=SPP) -> bytes:
    for i in range(0, N_PACKETS):
        data = file_object.read(spp)
        if not data:
            file_object.seek(0)
            data = file_object.read(spp)
        yield data


def main():
    pcap_out = PcapWriter(OUTPUT_FILE)

    seq = random.randrange(0xFFFF)
    ts = random.randrange(0xFFFF) * SPP
    ssrc = random.randrange(0xFFFFFFFF)
    with open(AUDIO_FILE, mode='rb') as f:
        count = 0
        sec = 0
        usec = 0
        in_dtx = False
        set_marker = False
        dtx_packets_left = 0
        for payload in get_audio_samples(file_object=f, n_packets=N_PACKETS, spp=SPP):
            if not in_dtx:
                l1 = Ether()
                l2 = IP(src=SRC_IP, dst=DST_IP)
                l3 = UDP(sport=SRC_PORT, dport=DST_PORT)
                l4 = RTP(version=2, payload_type=0 if USE_ULAW else 8, sequence=seq, timestamp=ts, sourcesync=ssrc, marker=set_marker)
                if set_marker:
                    set_marker = False
                l4.payload = Raw(payload)
                p = l1 / l2 / l3 / l4
                print(f"Writing packet {sec}.{usec:03}")
                if not pcap_out.header_present:
                    pcap_out.write_header(p)
                pcap_out.write_packet(p, sec=sec, usec=usec)
                seq = seq + 1
            count = count + 1
            ts = ts + SPP
            usec = usec + PTIME * 1000
            if usec >= 1000000:
                usec = usec - 1000000
                sec = sec + 1
            if in_dtx:
                dtx_packets_left = dtx_packets_left - 1
                if dtx_packets_left == 0:
                    set_marker = True
                    in_dtx = False
            else:
                if count in DTX_POINTS.keys():
                    in_dtx = True
                    dtx_packets_left = DTX_POINTS[count]
    pcap_out.close()


if __name__ == '__main__':
    main()
