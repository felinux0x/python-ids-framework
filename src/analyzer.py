# src/analyzer.py
from scapy.all import IP, TCP, UDP, ICMP, Raw

class PacketAnalyzer:
    def __init__(self, rules, alert_manager):
        self.rules = rules
        self.alert_manager = alert_manager

    def analyze(self, packet):
        for rule in self.rules:
            if self._matches(packet, rule):
                self._trigger_alert(packet, rule)
                break 

    def _matches(self, packet, rule):
        if not packet.haslayer(IP):
            return False

        proto_map = {'tcp': TCP, 'udp': UDP, 'icmp': ICMP}
        packet_proto_layer = proto_map.get(rule['proto'].lower())
        
        if not packet_proto_layer or not packet.haslayer(packet_proto_layer):
            return False

        if rule['src_ip'] != 'any' and packet[IP].src != rule['src_ip']:
            return False
        if rule['dst_ip'] != 'any' and packet[IP].dst != rule['dst_ip']:
            return False

        if packet.haslayer(TCP) or packet.haslayer(UDP):
            if rule['src_port'] != 'any' and str(packet[packet_proto_layer].sport) != rule['src_port']:
                return False
            if rule['dst_port'] != 'any' and str(packet[packet_proto_layer].dport) != rule['dst_port']:
                return False

        # --- INÍCIO DA CORREÇÃO ---
        options = rule.get('options', {})
        if 'flags' in options and packet.haslayer(TCP):
            flags_str = str(packet[TCP].flags)
            rule_flags = options['flags']
            if not all(flag in flags_str for flag in rule_flags):
                return False
        # --- FIM DA CORREÇÃO ---

        if 'content' in options:
            if not packet.haslayer(Raw):
                return False
            try:
                payload = packet[Raw].load.decode('utf-8', errors='ignore')
                if options['content'] not in payload:
                    return False
            except Exception:
                return False
        
        return True

    def _trigger_alert(self, packet, rule):
        msg = rule['options'].get('msg', 'N/A')
        sid = rule['options'].get('sid', 'N/A')
        
        sport = packet[IP].sport if packet.haslayer(TCP) or packet.haslayer(UDP) else ''
        dport = packet[IP].dport if packet.haslayer(TCP) or packet.haslayer(UDP) else ''
        
        alert_message = (
            f"Intrusão Detectada (SID: {sid})! Regra: '{msg}'. "
            f"Proto: {rule['proto'].upper()} | "
            f"Origem: {packet[IP].src}:{sport} -> "
            f"Destino: {packet[IP].dst}:{dport}"
        )
        self.alert_manager.alert(alert_message)