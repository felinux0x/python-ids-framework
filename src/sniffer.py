# src/sniffer.py
from scapy.all import sniff

class Sniffer:
    def __init__(self, interface, analyzer):
        self.interface = interface
        self.analyzer = analyzer

    def start(self):
        sniff_args = {"prn": self.analyzer.analyze, "store": 0}
        if self.interface:
            sniff_args["iface"] = self.interface
        
        try:
            sniff(**sniff_args)
        except Exception as e:
            print(f"[ERRO] Falha ao iniciar o sniffer. Verifique as permissões ou o nome da interface. Erro: {e}")