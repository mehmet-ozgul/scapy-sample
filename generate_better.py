import structlog

import yaml
import argparse
from random import randint

from scapy.all import *
from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import Ether
from scapy.layers.rtp import RTP
from scapy.utils import PcapWriter

logging.getLogger('scapy').setLevel(logging.CRITICAL)
logger = structlog.getLogger(__name__)


class DefaultAction:
    SRC_IP = '10.0.0.1'
    DST_IP = '10.0.0.2'
    SRC_PORT = 16000
    DST_PORT = 24400

    def __init__(self, properties):
        self.properties = properties

    @staticmethod
    def factory(properties):
        if properties['function'] == 'dtx':
            return Dtx(properties)
        elif properties['function'] == 'dtmf':
            return Dtmf(properties)
        elif properties['function'] == 'byop':
            return Byop(properties)
        elif properties['function'] == 'dtmf_manual':
            return DtmfManual(properties)
        else:
            raise Exception("Unknown action %s", properties)

    @staticmethod
    def default_packet(payload: bytes, ssrc: int, pt: int, seq: int, ts: int, marker: bool) -> Packet:
        l1 = Ether()
        l2 = IP(src=DefaultAction.SRC_IP, dst=DefaultAction.DST_IP)
        l3 = UDP(sport=DefaultAction.SRC_PORT, dport=DefaultAction.DST_PORT)
        l4 = RTP(version=2, payload_type=pt, sequence=seq, timestamp=ts, sourcesync=ssrc, marker=marker)
        l4.payload = Raw(payload)
        p = l1 / l2 / l3 / l4
        return p

    @staticmethod
    def finalize(scenario: 'Scenario'):
        logger.debug("Finalizing action %s", scenario.action)
        scenario.action = None

    def generate_packet(self, payload: bytes, scenario: 'Scenario') -> [Packet]:
        p = self.default_packet(payload=payload, ssrc=scenario.ssrc, pt=scenario.payload_type,
                                seq=scenario.seq, ts=scenario.ts, marker=scenario.set_marker)
        scenario.increment_seq()
        scenario.increment_ts()
        return [p]

    def __str__(self) -> str:
        return str(self.properties)


class Dtx(DefaultAction):
    def __init__(self, properties):
        super().__init__(properties=properties)
        self.duration_packets = properties['duration_packets']
        self.in_dtx = True
        self.dtx_packets_left = self.duration_packets

    def generate_packet(self, payload: bytes, scenario: 'Scenario') -> [Packet]:
        p = self.default_packet(payload=payload, ssrc=scenario.ssrc, pt=scenario.payload_type,
                                seq=scenario.seq, ts=scenario.ts, marker=scenario.set_marker)
        scenario.increment_ts()
        # Don't increment the sequence number for DTX packets
        if self.in_dtx:
            self.dtx_packets_left = self.dtx_packets_left - 1
            if self.dtx_packets_left == 0:
                scenario.set_marker = True
                self.in_dtx = False
                scenario.set_marker = True
                DefaultAction.finalize(scenario=scenario)
        else:
            return [p]
        return [None]


class Dtmf(DefaultAction):
    DIGIT_MAP = {'0': 0, '1': 1, '2': 2, '3': 3, '4': 4, '5': 5, '6': 6, '7': 7, '8': 9, '9': 9, '*': 10, '#': 11,
                 'A': 12, 'B': 13, 'C': 14, 'D': 15, 'Flash': 16}

    def __init__(self, properties):
        super().__init__(properties=properties)
        self.event_packets = properties['event_packets']
        self.end_packets = properties['end_packets']
        self.digit = properties['digit']
        self.volume = properties['volume']
        self.payload_type = properties['payload_type']
        self.interleave = properties['interleave'] if 'interleave' in properties.keys() else False
        self.event_packets_to_send = self.event_packets
        self.end_packets_to_send = self.end_packets
        self.event_ts = -1
        self.duration = 0
        self.ending = False

    @staticmethod
    def create_event_payload(digit: int, volume: int, duration: int, end: bool) -> bytes:
        # 0                   1                   2                   3
        # 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
        # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        # |     event     |E|R| volume    |          duration             |
        # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        payload = bytearray([0, 0, 0, 0])
        payload[0] = Dtmf.DIGIT_MAP[digit]
        payload[1] = (0x80 if end else 0x00) | (volume & 0x3F)
        payload[2] = (duration & 0xFF00) >> 8
        payload[3] = duration & 0x00FF
        return bytes(payload)

    def generate_packet(self, payload: bytes, scenario: 'Scenario') -> [Packet]:
        audio_packet = self.default_packet(payload=payload, ssrc=scenario.ssrc, pt=scenario.payload_type,
                                           seq=scenario.seq, ts=scenario.ts, marker=scenario.set_marker)
        if self.interleave:
            scenario.increment_seq()

        if self.event_ts == -1:
            self.event_ts = scenario.ts
            self.duration = scenario.spp

        if self.event_packets_to_send > 0:
            self.event_packets_to_send = self.event_packets_to_send - 1
        elif self.end_packets_to_send > 0:
            self.end_packets_to_send = self.end_packets_to_send - 1
            self.ending = True
        if self.event_packets_to_send == 0 and self.end_packets_to_send == 0:
            DefaultAction.finalize(scenario=scenario)

        event_packet = self.default_packet(
            payload=Dtmf.create_event_payload(digit=self.digit, volume=self.volume, duration=self.duration,
                                              end=self.ending),
            ssrc=scenario.ssrc, pt=self.payload_type,
            seq=scenario.seq, ts=self.event_ts, marker=scenario.set_marker)
        scenario.increment_seq()
        if not self.ending:
            self.duration = self.duration + scenario.spp
            scenario.increment_ts()

        logger.debug("Dtmf: %s@%d:%d %d:%d interleaved:%s", self.digit, self.event_ts, scenario.ts,
                     self.event_packets_to_send, self.end_packets_to_send,
                     self.interleave)

        return [event_packet, audio_packet] if self.interleave else [event_packet]


class DtmfManual(DefaultAction):
    def __init__(self, properties):
        super().__init__(properties=properties)
        self.digit = properties['digit']
        self.volume = properties['volume']
        self.payload_type = properties['payload_type']
        self.interleave = properties['interleave'] if 'interleave' in properties.keys() else False
        self.timestamp_delta = properties['timestamp_delta']
        self.seq_delta = properties['seq_delta']
        self.duration = properties['duration']
        self.end = properties['end']
        self.marker = properties['marker']

    def generate_packet(self, payload: bytes, scenario: 'Scenario') -> [Packet]:
        audio_packet = self.default_packet(payload=payload, ssrc=scenario.ssrc, pt=scenario.payload_type,
                                           seq=scenario.seq, ts=scenario.ts, marker=scenario.set_marker)
        if self.interleave:
            scenario.increment_seq()

        DefaultAction.finalize(scenario=scenario)
        event_seq = scenario.seq + self.seq_delta
        event_ts = scenario.ts + self.timestamp_delta

        event_packet = self.default_packet(payload=Dtmf.create_event_payload(digit=self.digit,
                                                                             volume=self.volume, duration=self.duration,
                                                                             end=self.end),
                                           ssrc=scenario.ssrc, pt=self.payload_type,
                                           seq=event_seq, ts=event_ts, marker=scenario.set_marker)
        scenario.increment_seq()
        scenario.increment_ts()

        logger.debug("DtmfManual: %s@%d:%d %d:%d interleaved:%s", self.digit, event_ts, scenario.ts,
                     self.duration, self.end, self.interleave)

        return [event_packet, audio_packet] if self.interleave else [event_packet]


class Byop(DefaultAction):
    def __init__(self, properties):
        super().__init__(properties=properties)
        self.timestamp_delta = properties['timestamp_delta']
        self.seq_delta = properties['seq_delta']
        self.payload_type = properties['payload_type']
        self.payload_length = properties['payload_length']
        self.include_default_audio = properties['include_default_audio']
        self.marker = properties['marker']

    def generate_packet(self, payload: bytes, scenario: 'Scenario') -> [Packet]:
        rslt = []
        if self.include_default_audio:
            p = self.default_packet(payload=payload, ssrc=scenario.ssrc, pt=scenario.payload_type,
                                    seq=scenario.seq, ts=scenario.ts, marker=scenario.set_marker)
            scenario.ts = scenario.ts + scenario.spp
            scenario.seq = scenario.seq + 1
            rslt.append(p)
        random_payload = [randint(0, 255) for _ in range(self.payload_length)]
        p = self.default_packet(payload=bytes(random_payload), ssrc=scenario.ssrc, pt=self.payload_type,
                                seq=scenario.seq + self.seq_delta,
                                ts=scenario.ts + self.timestamp_delta, marker=self.marker)
        rslt.append(p)
        DefaultAction.finalize(scenario=scenario)
        return rslt


class Scenario:
    SRC_IP = '10.0.0.1'
    DST_IP = '10.0.0.2'
    SRC_PORT = 16000
    DST_PORT = 24400

    def __init__(self, filename):
        self.filename = filename
        self.scenario = {}
        self.set_marker = False
        self.load()
        self.name = self.scenario['name']
        self.description = self.scenario['description']
        self.audio_file = self.scenario['audio_file']
        self.codec = self.scenario['codec']
        self.payload_type = 0 if self.codec == 'ulaw' else 8 if self.codec == 'alaw' else 66
        self.ptime = self.scenario['ptime']
        self.duration_ms = self.scenario['duration_ms']
        self.sample_rate = self.scenario['sample_rate']
        self.actions = self.scenario['actions']
        self.spp = int((self.ptime * self.sample_rate) / 1000)
        self.n_packets = int(self.duration_ms / self.ptime)
        self.input_file = open(self.audio_file, mode='rb')
        self.pcap_out = PcapWriter(self.name + '.pcap')
        self.seq = random.randrange(0xFFFF)
        self.ts = random.randrange(0xFFFF) * self.spp
        self.ssrc = random.randrange(0xFFFFFFFF)
        self.action = None
        logger.info("Initialized scenario %s %d:%d:%08x", self.scenario,
                    self.seq, self.ts, self.ssrc)

    def load(self):
        with open(self.filename, 'r') as fh:
            self.scenario = yaml.safe_load(fh)
        logger.debug("Loaded scenario %s", self.scenario)

    def get_audio_samples(self) -> bytes:
        for i in range(0, self.n_packets):
            data = self.input_file.read(self.spp)
            if not data:
                self.input_file.seek(0)
                data = self.input_file.read(self.spp)
            yield data

    def increment_seq(self):
        self.seq = self.seq + 1

    def increment_ts(self):
        self.ts = self.ts + self.spp

    def execute(self):
        count = 0
        sec = 0
        usec = 0
        default_action = DefaultAction(properties={'function': 'default'})
        for payload in self.get_audio_samples():
            if count in self.actions.keys():
                if self.action is not None:
                    logger.warning("Action %s is already running, ignoring %s", self.action, self.actions[count])
                else:
                    self.action = DefaultAction.factory(self.actions[count])
                    logger.debug("[%d] Starting action %s", count, self.action)
            loop_action = self.action if self.action is not None else default_action
            packets = loop_action.generate_packet(payload=payload, scenario=self)
            for p in packets:
                if p:
                    if not self.pcap_out.header_present:
                        self.pcap_out.write_header(p)
                    self.pcap_out.write_packet(p, sec=sec, usec=usec)
                    if self.set_marker:
                        self.set_marker = False
                usec = usec + self.ptime * 1000
                if usec >= 1000000:
                    usec = usec - 1000000
                    sec = sec + 1
            count = count + 1
            if count >= self.n_packets:
                break


def main():
    parser = argparse.ArgumentParser(prog='juicy.rtp', description='Generate RTP traffic')
    parser.add_argument('--scenario', '-s', help='Scenario file', required=True)
    arguments = parser.parse_args()
    scenario = Scenario(arguments.scenario)
    scenario.execute()


if __name__ == '__main__':
    main()
