import transcriber.settings as settings
from transcriber.messages import IpalMessage
from transcribers.transcriber import Transcriber


class OpenVPNTranscriber(Transcriber):
    _name = "openvpn"

    def matches_protocol(self, pkt):
        """Check if packet contains OpenVPN data."""
        # Check for TCP OpenVPN
        if hasattr(pkt, 'tcp'):
            tcp_layer = pkt.tcp
            if (int(tcp_layer.srcport) == settings.OPENVPN_PORT or 
                int(tcp_layer.dstport) == settings.OPENVPN_PORT):
                return hasattr(pkt, 'openvpn')
        
        return False
    
    def _is_request(self, pkt):
        """Check if the application layer message is a request or response.
        We classify srcport == 1194 as response (server) and dstport == 1194 as request (client). It is degined in a way Modbus packets are classified.
        """
        if int(pkt.tcp.dstport) == settings.OPENVPN_PORT:
            return "REQUEST"
        elif int(pkt.tcp.srcport) == settings.OPENVPN_PORT:
            return "RESPONSE"
        else:
            return "UNKNOWN"
    
    def parse_packet(self, pkt):
        """Parse OpenVPN packet and return IPAL messages."""
        res = []
        
        if not self.matches_protocol(pkt):
            return res
        
        try:
            # Extract basic packet information
            timestamp = float(pkt.sniff_time.timestamp())
            src_ip = pkt.ip.src if hasattr(pkt, 'ip') else None
            dst_ip = pkt.ip.dst if hasattr(pkt, 'ip') else None
            src_port = int(pkt.tcp.srcport)
            dst_port = int(pkt.tcp.dstport)
            vpn_activity = self._is_request(pkt)

            # Get raw payload data from OpenVPN layer
            raw_data = ""
            data_length = 0
            openvpn_layer = pkt.openvpn

            if hasattr(openvpn_layer, 'data'):
                raw_data = str(openvpn_layer.data)
                hex_data = raw_data.replace(':', '')
                
                try:
                    if hex_data:
                        data_bytes = bytes.fromhex(hex_data)
                        data_length = len(data_bytes)
                    else:
                        data_length = 0
                except ValueError as e:
                    print(f"ValueError: {e}")
                    data_length = 0

            # Extract OpenVPN protocol fields
            openvpn_fields = self._parse_openvpn_layer(openvpn_layer, raw_data)          
            
            # Create data dictionary
            data = {
                "transport_protocol": "TCP",
                "data_length": data_length,
                # **openvpn_fields
            }
            
            # Add TCP-specific fields
            # if hasattr(pkt, 'tcp'):
            #     tcp_fields = self._extract_tcp_fields(pkt.tcp)
            #     data.update(tcp_fields)
            
            # # Add IP-specific fields
            # if hasattr(pkt, 'ip'):
                # ip_fields = self._extract_ip_fields(pkt.ip)
                # data.update(ip_fields)
            
            # Create IPAL message
            res.append(
                IpalMessage(
                    id=self._id_counter.get_next_id(),
                    src=f"{src_ip}:{src_port}" if src_ip else None,
                    dest=f"{dst_ip}:{dst_port}" if dst_ip else None,
                    timestamp=timestamp,
                    protocol=self._name,
                    length=openvpn_fields.get("packet_length", data_length),
                    type=openvpn_fields.get("opcode", 0),
                    data=data,
                    activity=vpn_activity
                )
            )
            
        except Exception as e:
            settings.logger.error(f"Error parsing OpenVPN packet: {e}")
        
        return res
    
    def _parse_openvpn_layer(self, openvpn_layer, raw_data=""):
        """Parse OpenVPN protocol layer fields."""
        fields = {}
        
        try:
            # Extract packet length (OPENVPN.plen)
            if hasattr(openvpn_layer, 'plen'):
                fields["packet_length"] = int(openvpn_layer.plen)
            
            # Extract Type field (opcode + key_id)
            if hasattr(openvpn_layer, 'type'):
                type_value = int(openvpn_layer.type, 16) if isinstance(openvpn_layer.type, str) else int(openvpn_layer.type)
                # fields["type_value"] = type_value
                
                opcode = (type_value >> 3) & 0x1F
                key_id = type_value & 0x07
                
                fields["opcode"] = opcode
                fields["key_id"] = key_id
                
                # Determine packet type based on opcode
                opcode_names = {
                    0x01: "P_CONTROL_HARD_RESET_CLIENT_V1",
                    0x02: "P_CONTROL_HARD_RESET_SERVER_V1", 
                    0x03: "P_CONTROL_SOFT_RESET_V1",
                    0x04: "P_CONTROL_V1",
                    0x05: "P_ACK_V1", 
                    0x06: "P_DATA_V1",
                    0x07: "P_CONTROL_HARD_RESET_CLIENT_V2",
                    0x08: "P_CONTROL_HARD_RESET_SERVER_V2",
                    0x09: "P_DATA_V2",
                    0x0A: "P_CONTROL_WKC_V1"
                }
                
                fields["packet_type"] = opcode_names.get(opcode, f"UNKNOWN_{opcode}")
            
            # Extract Peer ID
            if hasattr(openvpn_layer, 'peer_id'):
                fields["peer_id"] = int(openvpn_layer.peer_id)
            
            # For control packets only
            control_opcodes = [0x01, 0x02, 0x03, 0x04, 0x05, 0x07, 0x08, 0x0A]
            if hasattr(openvpn_layer, 'session_id') and opcode in control_opcodes:
                fields["session_id"] = int(openvpn_layer.session_id)
            
            # For data packets (0x06 and 0x09)
            if opcode in [0x06, 0x09]:
                fields["is_data_packet"] = True
                    
        except Exception as e:
            fields["parse_error"] = str(e)
        
        return fields
    
    def _extract_tcp_fields(self, tcp_layer):
        fields = {}
        try:
            # TCP.stream
            if hasattr(tcp_layer, 'stream'):
                fields["tcp_stream"] = int(tcp_layer.stream)
            
            # TCP.stream_pnum  
            if hasattr(tcp_layer, 'stream_pnum'):
                fields["tcp_stream_pnum"] = int(tcp_layer.stream_pnum)
            
            # TCP.completeness
            if hasattr(tcp_layer, 'completeness'):
                fields["tcp_completeness"] = str(tcp_layer.completeness)
            
            # TCP.len (TCP payload length, not OpenVPN packet length)
            if hasattr(tcp_layer, 'len'):
                fields["tcp_len"] = int(tcp_layer.len)
            
            # TCP.seq
            if hasattr(tcp_layer, 'seq'):
                fields["tcp_seq"] = int(tcp_layer.seq)
            
            # TCP.nxtseq
            if hasattr(tcp_layer, 'nxtseq'):
                fields["tcp_nxtseq"] = int(tcp_layer.nxtseq)
            
            # TCP.ack
            if hasattr(tcp_layer, 'ack'):
                fields["tcp_ack"] = int(tcp_layer.ack)
            
            # TCP.time_delta
            if hasattr(tcp_layer, 'time_delta'):
                fields["tcp_time_delta"] = float(tcp_layer.time_delta)
            
            # TCP.pdu_size
            if hasattr(tcp_layer, 'pdu_size'):
                fields["tcp_pdu_size"] = int(tcp_layer.pdu_size)
            
            # TCP.analysis_ack_rtt
            if hasattr(tcp_layer, 'analysis_ack_rtt'):
                fields["tcp_analysis_ack_rtt"] = float(tcp_layer.analysis_ack_rtt)
                
        except Exception as e:
            settings.logger.debug(f"Error extracting TCP fields: {e}")
        return fields
    
    def _extract_ip_fields(self, ip_layer):
        """Extract IP-specific fields matching CSV columns."""
        fields = {}
        try:
            # IP.len
            if hasattr(ip_layer, 'len'):
                fields["ip_len"] = int(ip_layer.len)                
        except Exception as e:
            settings.logger.debug(f"Error extracting IP fields: {e}")
        return fields