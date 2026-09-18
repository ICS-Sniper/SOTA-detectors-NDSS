import struct
import subprocess
import transcriber.settings as settings
from transcriber.messages import Activity, IpalMessage
from transcribers.transcriber import Transcriber


class CIPTranscriber(Transcriber):
    _name = "cip"

    def __init__(self, id_counter):
        super().__init__(id_counter)
        self._tshark_parsed_packets = None
        self._packet_iterator = None

    @classmethod
    def state_identifier(cls, msg, key):
        if msg.activity in [Activity.INTERROGATE, Activity.COMMAND]:
            return f"{msg.dest}:{key}"
        elif msg.activity in [Activity.INFORM, Activity.ACTION]:
            return f"{msg.src}:{key}"
        else:
            settings.logger.critical(f"Unknown activity {msg.activity}")
            return f"{msg.src}:{key}"

    def matches_protocol(self, pkt):
        return "CIP" in pkt

    @staticmethod
    def parse_cip_symbol(symbol_str):
        """
        Parse CIP symbol from 'HMI,LIT101,Pv:2' to 'HMI. Lit101.Pv'
        """
        if not symbol_str:
            return None
        
        # Remove ':2' suffix if present
        if ':' in symbol_str:
            symbol_str = symbol_str.rsplit(':', 1)[0]
        
        # Replace commas with dots
        return symbol_str.replace(',', '.')

    @staticmethod
    def parse_cip_data(data_str, is_request=False):
        if not data_str or data_str.strip() == '':
            return None
        data_str = data_str.replace(':', '').replace(' ', '').strip()
        if len(data_str) < 2:
            return None
        try:
            if is_request:
                if data_str.startswith('c3000100') and len(data_str) == 12:
                    value_hex = data_str[8:]
                    return struct.unpack('<H', bytes.fromhex(value_hex))[0]
                elif data_str.startswith('ca000100') and len(data_str) == 16:
                    value_hex = data_str[8:]
                    return struct.unpack('<f', bytes.fromhex(value_hex))[0]
                else:
                    return data_str
            else: # is_response
                if data_str.startswith('c300') and len(data_str) == 8:
                    value_hex = data_str[4:]
                    return struct.unpack('<H', bytes.fromhex(value_hex))[0]
                elif data_str.startswith('ca') and len(data_str) >= 16:
                    value_hex = data_str[-8:]
                    return struct.unpack('<f', bytes.fromhex(value_hex))[0]
                else:
                    if len(data_str) == 4:
                        return struct.unpack('<H', bytes.fromhex(data_str))[0]
                    if len(data_str) == 8:
                        try:
                            return struct.unpack('<f', bytes.fromhex(data_str))[0]
                        except struct.error:
                            return struct.unpack('<I', bytes.fromhex(data_str))[0]
                    return data_str
        except (struct.error, ValueError, TypeError):
            return None

    def _run_tshark_and_parse(self):
        settings.logger.info("CIP Transcriber: Using tshark CLI for parsing (pyshark bypass).")
        pcap_file = settings.source
        if not pcap_file:
            settings.logger.error("CIP Transcriber: pcap file path (settings.source) is not set.")
            self._tshark_parsed_packets = []
            return
        
        import shutil
        tshark_paths = [
            "tshark",                    
            "/opt/homebrew/bin/tshark",  
            "/usr/local/bin/tshark",    
            "/usr/bin/tshark"
        ]
        
        tshark_binary = None
        for path in tshark_paths:
            if shutil.which(path):
                tshark_binary = path
                break
        
        if not tshark_binary:
            settings.logger.error("Could not find tshark executable")
            self._tshark_parsed_packets = []
            return
        

        tshark_cmd = [
            tshark_binary, "-r", pcap_file, "-Y", "cip", "-T", "fields",
            "-e", "frame.number", "-e", "frame.time_epoch",
            "-e", "ip.src", "-e", "tcp.srcport",
            "-e", "ip.dst", "-e", "tcp.dstport",
            "-e", "cip.service", "-e", "cip.symbol", "-e", "cip.data",
        ]

        try:
            result = subprocess.run(tshark_cmd, capture_output=True, text=True, check=True)
        except (subprocess.CalledProcessError, FileNotFoundError) as e:
            settings.logger.error(f"Failed to run tshark for CIP parsing: {e}")
            self._tshark_parsed_packets = []
            return

        lines = [line.strip() for line in result.stdout.splitlines() if line.strip()]
        
        parsed_messages = []
        for line in lines:
            parts = line.split('\t')
            
            frame_num = parts[0] if len(parts) > 0 else ""
            timestamp = float(parts[1]) if len(parts) > 1 else 0.0
            src_ip = parts[2] if len(parts) > 2 else ""
            src_port = parts[3] if len(parts) > 3 else ""
            dst_ip = parts[4] if len(parts) > 4 else ""
            dst_port = parts[5] if len(parts) > 5 else ""
            service_raw = parts[6] if len(parts) > 6 else ""
            symbol_raw = parts[7] if len(parts) > 7 else ""
            data_raw = parts[8] if len(parts) > 8 else ""

            if not dst_port: continue

            is_request = (dst_port == str(settings.ENIP_PORT))
            
            service_code_str = service_raw.split(',')[-1].strip() if ',' in service_raw else service_raw
            try:
                code = int(service_code_str, 16)
            except (ValueError, TypeError):
                continue

            m = IpalMessage(
                id=self._id_counter.get_next_id(),
                src=f"{src_ip}:{src_port}",
                dest=f"{dst_ip}:{dst_port}",
                timestamp=timestamp,
                protocol=self._name,
                type=code,
                data={}
            )

            symbol = self.parse_cip_symbol(symbol_raw)
            data_value = self.parse_cip_data(data_raw, is_request=is_request)

            if symbol:
                m.data[symbol] = data_value if data_value is not None else ""

            if is_request:
                if code == 0x4C: # Read
                    m.activity = Activity.INTERROGATE
                    m._add_to_request_queue = True
                elif code == 0x4D: # Write
                    m.activity = Activity.COMMAND
                    m._add_to_request_queue = True
            else: # Response
                if code == 0xCC: # Read Response
                    m.activity = Activity.INFORM
                    m._match_to_requests = True
                elif code == 0xCD: # Write Response
                    m.activity = Activity.ACTION
                    m._match_to_requests = True

            parsed_messages.append(m)

        self._tshark_parsed_packets = parsed_messages
        self._packet_iterator = iter(self._tshark_parsed_packets)

    def parse_packet(self, pkt):
        """
        Rewriten to use cached tshark parsed packets.
        """
        if self._tshark_parsed_packets is None:
            self._run_tshark_and_parse()

        try:
            return [next(self._packet_iterator)]
        except StopIteration:
            return []

    def match_response(self, requests, response):
        remove_from_queue = []
        expected_request_type = None
        if response.type == 0xCC:
            expected_request_type = 0x4C
        elif response.type == 0xCD:
            expected_request_type = 0x4D

        if response.activity in [Activity.INFORM, Activity.ACTION]:
            res_keys = list(response.data.keys())
            for request in requests:
                if expected_request_type and request.type != expected_request_type:
                    continue
                req_keys = list(request.data.keys())
                if not req_keys or req_keys[0] is None:
                    continue
                if res_keys == req_keys:
                    response.responds_to.append(request.id)
                    remove_from_queue.append(request)
                elif set(res_keys).issubset(req_keys):
                    response.responds_to.append(request.id)
                    for key in res_keys:
                        if key in request.data:
                            request.data.pop(key)
                    if not request.data:
                        remove_from_queue.append(request)
        else:
            settings.logger.warning(f"Unhandled CIP response activity: {response.activity}")
        return remove_from_queue

    # transcribe_* methods are no longer used due to tshark parsing
    def transcribe_read_request(self, m, cip): pass
    def transcribe_read_response(self, m, cip): pass
    def transcribe_write_request(self, m, cip): pass
    def transcribe_write_response(self, m, cip): pass