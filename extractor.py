#!/usr/bin/env python3
import argparse
import binascii
import struct
import pyshark
import hmac
import hashlib
import xiaomi_pb2
import json

from Crypto.Cipher import AES
from Crypto.Util import Counter
from enum import Enum
from google.protobuf import json_format
from loguru import logger

class ParseError(Exception):
    pass


class XiaomiPacket:
    ACK = 1
    SESSION_CONFIG = 2
    DATA = 3

    CHANNEL_UNKNOWN = -1
    CHANNEL_PROTOBUF = 1
    CHANNEL_DATA = 2
    CHANNEL_ACTIVITY = 5
    
    PLAINTEXT = 1
    ENCRYPTED = 2
    
    def __init__(self, type, remote, seq_num, payload=None):
        self.type = type
        self.remote = remote
        self.sequence_number = seq_num
        self.payload = payload
        self.decode()
    

    def decode(self):
        match self.type:
            case XiaomiPacket.SESSION_CONFIG:
                self.decode_session_config()
            case XiaomiPacket.DATA:
                self.decode_data()
    

    def decode_session_config(self):
        # TODO
        payload = memoryview(self.payload)

        if len(payload) < 1:
            raise ParseError("SessionConfig payload too short")

        self.op_code = payload[0]
    

    def decode_data(self):
        payload = memoryview(self.payload)
        if len(payload) < 2:
            raise ParseError("DataPacket payload too short")
        
        self.channel = payload[0]
        self.op_code = payload[1]
        self.payload = payload[2:].tobytes()

        match self.channel:
            case XiaomiPacket.CHANNEL_PROTOBUF:
                self.channel = XiaomiPacket.CHANNEL_PROTOBUF
            case XiaomiPacket.CHANNEL_DATA:
                self.channel = XiaomiPacket.CHANNEL_DATA
            case XiaomiPacket.CHANNEL_ACTIVITY:
                self.channel = XiaomiPacket.CHANNEL_ACTIVITY
            case _:
                self.channel = XiaomiPacket.CHANNEL_UNKNOWN
    
    
    def __str__(self):
        source = 'Phone'
        if self.remote: source = 'Watch'

        result = {
            'source': source,
            'sequence_number': self.sequence_number
        }

        match self.type:
            case XiaomiPacket.ACK:
                result['type'] = 'ACK'
            case XiaomiPacket.SESSION_CONFIG:
                result['type'] = 'SESSION_CONFIG'
                result['op_code'] = self.op_code
            case XiaomiPacket.DATA:
                result['type'] = 'DATA'
                match self.channel:
                    case XiaomiPacket.CHANNEL_PROTOBUF:
                        result['channel'] = 'PROTOBUF'
                    case XiaomiPacket.CHANNEL_DATA:
                        result['channel'] = 'DATA'
                    case XiaomiPacket.CHANNEL_ACTIVITY:
                        result['channel'] = 'ACTIVITY'
                    case _:
                        result['channel'] = 'UNKNOWN'
        
        return json.dumps(result)


class XiaomiProtobufExtractor:
    def __init__(self, auth_key):
        self.auth_key = binascii.unhexlify(auth_key)
        self.auth_done = False
    
    def find_watch_addr(self, cap):
        for packet in cap:
            if 'BTHCI_ACL' not in packet: continue
            name = packet.bthci_acl.src_name
            bd_addr = packet.bthci_acl.src_bd_addr
            if 'Band' in name and 'Xiaomi' in name:
                logger.debug("Found watch bd_addr: " + bd_addr)
                self.bd_addr = bd_addr
                break
    

    def process_payloads(self, payload, remote):
        """
            Payload can be nested if payload_length
            is less than bytes left in payload
        """
        results = []

        def parse_packet(packet_bytes):
            if len(packet_bytes) < 8:
                raise ParseError("Packet is too short")

            # Check header (a5 a5)
            magic = packet_bytes[0:2]
            if magic != b'\xa5\xa5':
                raise ParseError("Invalid magic")

            if len(packet_bytes) < 8:
                raise ParseError("Packet too short after finding magic!")

            packet_type = packet_bytes[2] & 0xF
            sequence_number = packet_bytes[3]
            payload_length = struct.unpack('<H', packet_bytes[4:6])[0]
            checksum = struct.unpack('<H', packet_bytes[6:8])[0]

            if len(packet_bytes) < 8 + payload_length:
                raise ParseError("Incomplete packet")

            payload = packet_bytes[8:8 + payload_length]
            remaining_bytes = packet_bytes[8 + payload_length:]

            match packet_type:
                case XiaomiPacket.ACK:
                    results.append(XiaomiPacket(XiaomiPacket.ACK, remote, sequence_number))
                case XiaomiPacket.SESSION_CONFIG:
                    results.append(XiaomiPacket(XiaomiPacket.SESSION_CONFIG, remote, sequence_number, payload))
                case XiaomiPacket.DATA:
                    results.append(XiaomiPacket(XiaomiPacket.DATA, remote, sequence_number, payload))
                case _:
                    raise ParseError(f"Unknown packet type: {packet_type}")

            if remaining_bytes:
                parse_packet(remaining_bytes)
        
        parse_packet(payload)
        return results
    
    
    def decrypt_payload(self, remote, payload):
        key = self.decryption_key
        if not remote:
            key = self.encryption_key

        ctr = Counter.new(128, initial_value=int.from_bytes(key, 'big'))
        cipher = AES.new(key, AES.MODE_CTR, counter=ctr)

        return cipher.decrypt(payload)


    def compute_auth_step3_hmac(self):
        miwear_auth_bytes = b"miwear-auth"

        try:
            # Initialize HMAC with the concatenated nonces
            initial_key = self.phone_nonce + self.watch_nonce
            mac = hmac.new(initial_key, self.auth_key, digestmod=hashlib.sha256)

            # Compute the actual key
            hmac_key_bytes = mac.digest()
            key = hmac.new(hmac_key_bytes, digestmod=hashlib.sha256)
        except Exception as e:
            raise RuntimeError("Failed to initialize HMAC for auth step 3") from e

        output = bytearray(64)
        tmp = b""
        b = 1
        i = 0

        while i < len(output):
            key.update(tmp)
            key.update(miwear_auth_bytes)
            key.update(bytes([b]))
            tmp = key.digest()

            for j in range(len(tmp)):
                if i < len(output):
                    output[i] = tmp[j]
                    i += 1

            b += 1

        return bytes(output)


    @staticmethod    
    def hmac_sha256(key: bytes, input_data: bytes) -> bytes:
        try:
            mac = hmac.new(key, input_data, digestmod=hashlib.sha256)
            return mac.digest()
        except Exception as e:
            raise RuntimeError("Failed to compute HMAC") from e

    """
        TODO
    """
    def process_packets(self):
        processed_commands = []

        for packet in self.packets:
            if (packet.type == XiaomiPacket.DATA and
                packet.op_code == XiaomiPacket.PLAINTEXT):
                # Unencrypted packets (auth)
                cmd = xiaomi_pb2.Command()
                cmd.ParseFromString(packet.payload)

                if cmd.HasField('auth'):
                    auth = cmd.auth
                    if auth.HasField('phoneNonce'):
                        self.phone_nonce = auth.phoneNonce.nonce
                    elif auth.HasField('watchNonce'):
                        self.watch_nonce = auth.watchNonce.nonce
                        self.watch_hmac = auth.watchNonce.hmac

                        step2hmac = self.compute_auth_step3_hmac()

                        self.decryption_key = step2hmac[:16]
                        self.encryption_key = step2hmac[16:32]
                        self.decryption_nonce = step2hmac[32:36]
                        self.encryption_nonce = step2hmac[36:40]

                        hmac_confirm = self.hmac_sha256(self.decryption_key, self.watch_nonce + self.phone_nonce)

                        if hmac_confirm != self.watch_hmac:
                            raise ParseError('Failed to get decryption key!')
                        
                        logger.debug("decryption_key=" + binascii.hexlify(self.decryption_key).decode('utf-8'))
                        logger.debug("encryption_key=" + binascii.hexlify(self.encryption_key).decode('utf-8'))

                        self.auth_done = True
            elif (packet.type == XiaomiPacket.DATA and
                packet.op_code == XiaomiPacket.ENCRYPTED and
                packet.channel == XiaomiPacket.CHANNEL_PROTOBUF):
                if not self.auth_done:
                    raise ParseError("Received an encrypted packet without parsed auth")
                
                payload = self.decrypt_payload(packet.remote, packet.payload)

                cmd = xiaomi_pb2.Command()
                cmd.ParseFromString(payload)
                cmd = json_format.MessageToDict(cmd)
                
                source = 'Phone'
                if packet.remote: source = 'Watch'
                
                cmd['packet_type'] = 'DATA'
                cmd['packet_channel'] = 'PROTOBUF'
                cmd['packet_source'] = source
                cmd['packet_sequence_number'] = packet.sequence_number

                processed_commands.append(json.dumps(cmd))
            else:
                processed_commands.append(packet)
        
        self.processed_commands = processed_commands


    def export_data(self, filename):
        file = open(filename, "w")

        for cmd in self.processed_commands:
            file.write(cmd.__str__() + "\n")
        
        file.close()

        logger.info("Packet data written to {}".format(filename))

    
    def proccess_capture(self, filename):
        cap = pyshark.FileCapture('btsnoop_hci.log')
        self.find_watch_addr(cap)

        results = []

        for packet in cap:
            # Filter junk packets
            if 'BLUETOOTH' not in packet: continue
            if 'BTHCI_ACL' not in packet: continue

            # Filter packets that are not from watch
            src_bd_addr = packet.bthci_acl.src_bd_addr
            dst_bd_addr = packet.bthci_acl.dst_bd_addr
            if (src_bd_addr != self.bd_addr and
                dst_bd_addr != self.bd_addr):
                continue

            if src_bd_addr == self.bd_addr:
                remote = True
            else:
                remote = False

            # Support only SPP(v2) proto for now
            if 'BTSPP' not in packet: continue

            payload = packet.btspp.data.binary_value
            try: payloads = self.process_payloads(payload, remote)
            except ParseError as e:
                continue

            for p in payloads: results.append(p)

        self.packets = results
        self.process_packets()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        prog='XiaomiProtobufExtractor',
        description='Extracts and decrypts xiaomi protobuf capture')
    parser.add_argument('input_file')
    parser.add_argument('output_file')
    parser.add_argument('-k', '--auth_key', required=True)
    args = parser.parse_args()

    extractor = XiaomiProtobufExtractor(args.auth_key)
    extractor.proccess_capture(args.input_file)
    extractor.export_data(args.output_file)